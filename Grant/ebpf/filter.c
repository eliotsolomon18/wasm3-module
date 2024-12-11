#define SEC(NAME) __attribute__((section(NAME), used))
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define TCP_HEADER_SIZE 20
#define IP_HEADER_MIN_SIZE 20
#define FILTERED_PORT 23557

struct bpf_spin_lock {
    __u32 val;
};

struct stats {
    struct bpf_spin_lock lock;
    __u64 filtered_packets;
    __u64 allowed_packets;
    __u64 drops;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} packet_stats SEC(".maps");

SEC("socket")
int nf_filter(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct stats *stats;
    
    stats = bpf_map_lookup_elem(&packet_stats, &key);
    if (unlikely(!stats))
        return skb->len;

    // Quick size check
    if (unlikely(skb->len < ETH_HLEN + IP_HEADER_MIN_SIZE))
        return skb->len;

    // Read IP header efficiently
    struct iphdr iph;
    if (unlikely(bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0))
        return skb->len;

    // Quick protocol check
    if (likely(iph.protocol != IPPROTO_TCP)) {
        __sync_fetch_and_add(&stats->allowed_packets, 1);
        return skb->len;
    }

    // Verify IP header
    __u32 ip_header_len = iph.ihl << 2;
    if (unlikely(ip_header_len < IP_HEADER_MIN_SIZE))
        return skb->len;

    // Read TCP header with lock
    struct tcphdr tcph;
    __u32 tcp_offset = ETH_HLEN + ip_header_len;
    
    bpf_spin_lock(&stats->lock);
    if (unlikely(bpf_skb_load_bytes(skb, tcp_offset, &tcph, sizeof(tcph)) < 0)) {
        bpf_spin_unlock(&stats->lock);
        return skb->len;
    }

    // Update atomic counters
    __u16 dport = __builtin_bswap16(tcph.dest);
    if (unlikely(dport == FILTERED_PORT)) {
        __sync_fetch_and_add(&stats->filtered_packets, 1);
        __sync_fetch_and_add(&stats->total_bytes, skb->len);
        bpf_spin_unlock(&stats->lock);
        return 0;
    }

    __sync_fetch_and_add(&stats->allowed_packets, 1);
    __sync_fetch_and_add(&stats->total_bytes, skb->len);
    bpf_spin_unlock(&stats->lock);
    return skb->len;
}

char LICENSE[] SEC("license") = "GPL";