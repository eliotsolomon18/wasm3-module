#define _GNU_SOURCE
#define _POSIX_C_SOURCE 199309L
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <fcntl.h>


#define RING_SIZE (1 << 20)  // 1MB ring
#define BLOCK_SIZE (1 << 12)  // 4KB blocks
#define FRAME_SIZE (1 << 11)  // 2KB frames
#define BATCH_SIZE 1024
#define BUF_SIZE (1024 * 1024)  // 1MB buffer

static volatile int running = 1;
static int map_fd;
static struct timespec start_time;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

struct stats {
    __u64 filtered_packets;
    __u64 allowed_packets;
    __u64 drops;
};

static void signal_handler(int signo) {
    running = 0;
}

static int setup_socket(const char *ifname) {
    // Create socket with non-blocking mode
    int sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Enable packet fanout for better CPU distribution
    int fanout_id = 1;
    int fanout_type = PACKET_FANOUT_CPU;
    int fanout_arg = (fanout_id | (fanout_type << 16));
    if (setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) < 0) {
        perror("setsockopt PACKET_FANOUT");
    }

    // Enable busy polling
    int busy_poll = 50;  // microseconds
    if (setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll)) < 0) {
        perror("setsockopt SO_BUSY_POLL");
    }

    // Set very large socket buffer (1GB)
    int sockbuf_size = 1024 * 1024 * 1024;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sockbuf_size, sizeof(sockbuf_size)) < 0) {
        perror("setsockopt SO_RCVBUF");
        // Try smaller buffer if 1GB fails
        sockbuf_size = 128 * 1024 * 1024;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sockbuf_size, sizeof(sockbuf_size)) < 0) {
            perror("setsockopt SO_RCVBUF fallback");
        }
    }

    // Verify actual buffer size
    int actual_size;
    socklen_t size_len = sizeof(actual_size);
    if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &actual_size, &size_len) == 0) {
        printf("DEBUG: Socket buffer size set to %d bytes\n", actual_size);
    }

    // Increase max packet size and backlog
    int backlog = 1000000;
    if (setsockopt(sock, SOL_SOCKET, SO_MAX_PKTSIZE, &backlog, sizeof(backlog)) < 0) {
        perror("setsockopt SO_MAX_PKTSIZE");
    }

    // Setup packet RX ring
    struct tpacket_req3 req = {
        .tp_block_size = 1 << 20,     // 1MB blocks
        .tp_block_nr = 1024,          // 1024 blocks = 1GB total
        .tp_frame_size = 1 << 12,     // 4KB frames
        .tp_frame_nr = (1 << 20) * 1024 / (1 << 12), // Calculate frames based on block size
        .tp_retire_blk_tov = 10,      // 10ms timeout
        .tp_feature_req_word = TP_FT_REQ_FILL_RXHASH,
        .tp_sizeof_priv = 0,
    };

    // Try TPACKET_V3 first
    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        // Fall back to TPACKET_V1 if V3 fails
        struct tpacket_req req_v1 = {
            .tp_block_size = req.tp_block_size,
            .tp_block_nr = req.tp_block_nr,
            .tp_frame_size = req.tp_frame_size,
            .tp_frame_nr = req.tp_frame_nr,
        };
        if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req_v1, sizeof(req_v1)) < 0) {
            perror("setsockopt PACKET_RX_RING");
            close(sock);
            return -1;
        }
    }

    // Bind to interface with promiscuous mode
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(ifname);
    if (!sll.sll_ifindex) {
        perror("if_nametoindex");
        close(sock);
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    // Enable promiscuous mode
    struct packet_mreq mreq = {
        .mr_ifindex = sll.sll_ifindex,
        .mr_type = PACKET_MR_PROMISC,
        .mr_alen = 0,
    };
    
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt PACKET_ADD_MEMBERSHIP");
    }

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    return sock;
}

static void print_stats(__u64 total_pkts) {
    __u32 key = 0;
    struct stats total = {0};

    pthread_mutex_lock(&stats_mutex);
    if (bpf_map_lookup_elem(map_fd, &key, &total) == 0) {
        __u64 all = total.filtered_packets + total.allowed_packets;
        printf("=================================\n");
        printf("=== eBPF Filter Statistics ===\n");
        printf("Filtered packets: %llu\n", (unsigned long long)total.filtered_packets);
        printf("Allowed packets: %llu\n", (unsigned long long)total.allowed_packets);
        printf("Total BPF packets: %llu\n", (unsigned long long)all);
        printf("Socket packets: %llu\n", total_pkts);
        printf("=================================\n\n");
        fflush(stdout);
    }
    pthread_mutex_unlock(&stats_mutex);
}

static void process_packets(int sock) {
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    char *buffers[BATCH_SIZE];
    __u64 total_pkts = 0;

    // Initialize batch processing structures
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH_SIZE; i++) {
        buffers[i] = malloc(BUF_SIZE);
        if (!buffers[i]) {
            perror("malloc");
            return;
        }
        iovecs[i].iov_base = buffers[i];
        iovecs[i].iov_len = BUF_SIZE;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    struct pollfd pfd = {
        .fd = sock,
        .events = POLLIN,
    };

    while (running) {
        // Batch receive packets
        int ret = poll(&pfd, 1, 100);
        if (ret < 0) {
            if (errno != EINTR) {
                perror("poll");
            }
            continue;
        }

        if (ret > 0 && (pfd.revents & POLLIN)) {
            int received = recvmmsg(sock, msgs, BATCH_SIZE, MSG_WAITFORONE, NULL);
            if (received > 0) {
                total_pkts += received;
                // Memory barrier to ensure counter updates are ordered
                __sync_synchronize();
            }
        }

        // Print periodic stats
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start_time.tv_sec >= 7) {
            break;
        }
    }

    // Final stats
    print_stats(total_pkts);

    // Cleanup
    for (int i = 0; i < BATCH_SIZE; i++) {
        free(buffers[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Set high RLIMIT_MEMLOCK
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }

    // Load BPF program
    struct bpf_object *obj = bpf_object__open("filter.o");
    if (!obj) {
        fprintf(stderr, "Error opening filter.o\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "nf_filter");
    if (!prog) {
        fprintf(stderr, "Error finding nf_filter program\n");
        return 1;
    }

    bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER);

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_stats");

    // Setup socket
    int sock = setup_socket(argv[1]);
    if (sock < 0) {
        fprintf(stderr, "Failed to setup socket\n");
        return 1;
    }

    // Attach BPF program
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("setsockopt SO_ATTACH_BPF");
        return 1;
    }

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize timing
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Process packets
    process_packets(sock);

    // Cleanup
    close(sock);
    bpf_object__close(obj);

    return 0;
}