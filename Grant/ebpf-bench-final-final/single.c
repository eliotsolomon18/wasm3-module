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
#include <sys/wait.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <poll.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define TOTAL_DURATION 15
#define PRINT_INTERVAL 5

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif

// Default NS: veth0 with 10.0.1.1/24
// ns1: veth1 with 10.0.1.2/24
// Servers on 10.0.1.1, clients in ns1 from 10.0.1.2
// Ports:
#define FILTERED_PORT "23557"
#define ALLOWED_PORT  "23558"
#define TEST_DURATION "10"
#define BLOCK_SIZE "1200"

static volatile int running = 1;
static int map_fd;
static struct timespec start_time;

struct stats {
    __u64 filtered_packets;
    __u64 allowed_packets;
};

static int libbpf_print_callback(enum libbpf_print_level level,
                                 const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void signal_handler(int signo) {
    running = 0;
}

static void print_stats() {
    struct timespec current_time_ts;
    clock_gettime(CLOCK_MONOTONIC, &current_time_ts);
    double duration = (current_time_ts.tv_sec - start_time.tv_sec) +
                      (current_time_ts.tv_nsec - start_time.tv_nsec) / 1e9;

    __u32 key = 0;
    struct stats total = {0};

    if (bpf_map_lookup_elem(map_fd, &key, &total) != 0) {
        fprintf(stderr, "Failed to lookup stats\n");
        return;
    }

    __u64 all = total.filtered_packets + total.allowed_packets;
    double pps = 0.0;
    if (duration > 0)
        pps = all / duration;

    printf("\n=================================\n");
    printf("=== eBPF Filter Statistics ===\n");
    printf("Filtered packets (port %s): %llu\n", FILTERED_PORT, (unsigned long long)total.filtered_packets);
    printf("Allowed packets (other ports): %llu\n", (unsigned long long)total.allowed_packets);
    printf("Total packets seen: %llu\n", (unsigned long long)all);
    printf("Packets/second: %.2f\n", pps);
    printf("Test duration: %.2f seconds\n", duration);
    printf("=================================\n\n");
    fflush(stdout);
}

static pid_t start_iperf3_server(const char *port, const char *bind_ip) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("iperf3", "iperf3", "-s", "-p", port, "-B", bind_ip, (char*)NULL);
        perror("execlp(iperf3 server)");
        exit(1);
    }
    return pid;
}

static pid_t start_iperf3_client_ns(const char *netns, const char *port, int udp, const char *server_ip, const char *bind_ip) {
    pid_t pid = fork();
    if (pid == 0) {
        // Run iperf3 client inside ns1 namespace
        if (udp) {
            execlp("sudo", "sudo", "ip", "netns", "exec", netns,
                   "iperf3",
                   "-c", server_ip,
                   "-p", port,
                   "-u", "-b", "0",
                   "-t", TEST_DURATION,
                   "-l", BLOCK_SIZE,
                   "-B", bind_ip,
                   (char*)NULL);
        } else {
            execlp("sudo", "sudo", "ip", "netns", "exec", netns,
                   "iperf3",
                   "-c", server_ip,
                   "-p", port,
                   "-t", TEST_DURATION,
                   "-l", BLOCK_SIZE,
                   "-B", bind_ip,
                   (char*)NULL);
        }
        perror("execlp(iperf3 client ns)");
        exit(1);
    }
    return pid;
}

static void setup_network() {
    // Remove old devices and ns
    system("sudo ip link del veth0 2>/dev/null");
    system("sudo ip link del veth1 2>/dev/null");
    system("sudo ip netns del ns1 2>/dev/null");

    // Create veth pair
    if (system("sudo ip link add veth0 type veth peer name veth1") != 0) {
        fprintf(stderr, "Failed to create veth pair\n");
        exit(1);
    }

    // Assign IP to veth0 and bring it up
    if (system("sudo ip addr add 10.0.1.1/24 dev veth0") != 0) {
        fprintf(stderr, "Failed to assign IP to veth0\n");
        exit(1);
    }
    system("sudo ip link set veth0 up");

    // Create ns1 and move veth1 into it
    if (system("sudo ip netns add ns1") != 0) {
        fprintf(stderr, "Failed to create ns1\n");
        exit(1);
    }
    if (system("sudo ip link set veth1 netns ns1") != 0) {
        fprintf(stderr, "Failed to move veth1 into ns1\n");
        exit(1);
    }
    if (system("sudo ip netns exec ns1 ip link set veth1 up") != 0) {
        fprintf(stderr, "Failed to set veth1 up in ns1\n");
        exit(1);
    }
    if (system("sudo ip netns exec ns1 ip addr add 10.0.1.2/24 dev veth1") != 0) {
        fprintf(stderr, "Failed to assign IP to veth1 in ns1\n");
        exit(1);
    }

    // Just show route inside ns1 (no need to add route)
    system("sudo ip netns exec ns1 ip route show");

    // Enable IP forwarding
    if (system("sudo sysctl -w net.ipv4.ip_forward=1") != 0) {
        fprintf(stderr, "Failed to enable ip_forward\n");
        exit(1);
    }
}

int main(void) {
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }

    libbpf_set_print(libbpf_print_callback);

    // Setup network
    setup_network();

    // Kill any leftover iperf3 processes
    system("sudo pkill iperf3 2>/dev/null");

    clock_gettime(CLOCK_MONOTONIC, &start_time);

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
    bpf_program__set_log_level(prog, 7);

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error getting program FD\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_stats");
    if (map_fd < 0) {
        fprintf(stderr, "Error getting map FD\n");
        return 1;
    }

    __u32 key = 0;
    struct stats zero_stats = {0};
    if (bpf_map_update_elem(map_fd, &key, &zero_stats, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to init stats map\n");
        return 1;
    }

    int raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("veth0");
    if (bind(raw_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind raw socket");
        return 1;
    }

    if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("setsockopt(SO_ATTACH_BPF)");
        return 1;
    }

    printf("eBPF program loaded and attached to veth0 raw socket\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Start servers on 10.0.1.1 in default namespace
    pid_t s1 = start_iperf3_server(FILTERED_PORT, "10.0.1.1");
    pid_t s2 = start_iperf3_server(ALLOWED_PORT, "10.0.1.1");

    sleep(1); // let servers start

    // Start clients in ns1 from 10.0.1.2 to 10.0.1.1
    pid_t c1 = start_iperf3_client_ns("ns1", FILTERED_PORT, 0, "10.0.1.1", "10.0.1.2"); // TCP to filtered
    pid_t c2 = start_iperf3_client_ns("ns1", FILTERED_PORT, 1, "10.0.1.1", "10.0.1.2"); // UDP to filtered
    pid_t c3 = start_iperf3_client_ns("ns1", ALLOWED_PORT, 0, "10.0.1.1", "10.0.1.2");   // TCP to allowed

    struct pollfd pfd = {
        .fd = raw_fd,
        .events = POLLIN,
    };

    time_t start_t = time(NULL);
    time_t last_print_t = start_t;

    while (running) {
        time_t current_t = time(NULL);

        // Stop after TOTAL_DURATION seconds
        if (current_t - start_t >= TOTAL_DURATION) {
            break;
        }

        int ret = poll(&pfd, 1, 500); // wait 0.5s
        if (ret > 0 && (pfd.revents & POLLIN)) {
            char buf[2048];
            ssize_t n = recv(raw_fd, buf, sizeof(buf), 0);
            (void)n; // even if no usage, just reading triggers BPF
        }

        // Print stats every PRINT_INTERVAL seconds
        if (current_t - last_print_t >= PRINT_INTERVAL) {
            print_stats();
            last_print_t = current_t;
        }

        // Check if clients are done
        int status;
        int done_count = 0;
        if (waitpid(c1, &status, WNOHANG) == c1) done_count++;
        if (waitpid(c2, &status, WNOHANG) == c2) done_count++;
        if (waitpid(c3, &status, WNOHANG) == c3) done_count++;
        if (done_count == 3) {
            // All clients done
            break;
        }
    }

    // Clients done, kill servers
    kill(s1, SIGINT);
    kill(s2, SIGINT);
    int status;
    waitpid(s1, &status, 0);
    waitpid(s2, &status, 0);

    // Final print
    print_stats();

    close(raw_fd);
    bpf_object__close(obj);

    // Optional cleanup if desired:
    // system("sudo ip link del veth0");
    // system("sudo ip netns del ns1");

    printf("Test complete. Exiting.\n");
    return 0;
}
