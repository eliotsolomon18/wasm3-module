#define SEC(NAME) __attribute__((section(NAME), used))
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h> // For ETH_HLEN = 14
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct stats {
    __u64 filtered_packets; // TCP packets to port 23557
    __u64 allowed_packets;  // all other packets
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} packet_stats SEC(".maps");

SEC("socket")
int nf_filter(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct stats *stats = bpf_map_lookup_elem(&packet_stats, &key);
    if (!stats)
        return skb->len;

    // We'll read up to Ethernet + IP + TCP
    // Max IP header: 60 bytes, TCP header: 20 bytes, Eth: 14 bytes = 94 bytes max
    // Use a larger buffer just in case:
    __u8 buf[128];

    // First load just IP header to find ip_header_len
    // IP header starts at ETH_HLEN (14)
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0) {
        // Not enough data to read IP header
        return skb->len;
    }

    int ip_header_len = iph.ihl * 4;
    if (ip_header_len < (int)sizeof(struct iphdr) || ip_header_len > 60) {
        // Invalid IP header length
        return skb->len;
    }

    int total_needed = ETH_HLEN + ip_header_len + (int)sizeof(struct tcphdr);
    if (total_needed > (int)sizeof(buf)) {
        // Should not happen since total_needed <= 94 and buf = 128
        return skb->len;
    }

    // Load Ethernet + IP + TCP into buf starting at offset 0
    if (bpf_skb_load_bytes(skb, 0, buf, total_needed) < 0) {
        // Not enough data for IP+TCP
        return skb->len;
    }

    // IP header is at buf[14 ... 14 + ip_header_len-1]
    struct iphdr *iphdr_ptr = (struct iphdr *)(buf + ETH_HLEN);

    // Check if it's TCP
    if (iphdr_ptr->protocol == IPPROTO_TCP) {
        // TCP header starts after IP header
        struct tcphdr *tcph = (struct tcphdr *)(buf + ETH_HLEN + ip_header_len);

        __u16 dst_port_host = __builtin_bswap16(tcph->dest);
        if (dst_port_host == 23557) {
            __sync_fetch_and_add(&stats->filtered_packets, 1);
            return 0; // drop
        }
    }

    __sync_fetch_and_add(&stats->allowed_packets, 1);
    return skb->len; // pass all others
}

char LICENSE[] SEC("license") = "GPL";
