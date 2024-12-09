#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Inlining all functions
// Custom htons function
static __inline __u16 htons(__u16 hostshort) {
    return __builtin_bswap16(hostshort);
}

// Checksum algo I picked up from the internet
static __inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static __inline void ip_csum_replace(__u16 *csum, __u32 old, __u32 new) {
    __u32 sum = ~*csum & 0xffff;
    sum += ~old & 0xffff;
    sum += new & 0xffff;
    *csum = csum_fold_helper(sum);
}

SEC("tc")
int ttl_modify(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));

    if ((void *)ip + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    __u32 old_ttl = ip->ttl;

    // Hardcode ttl to 1 for experiment
    if (ip->ttl > 1) {
        ip->ttl = 1;
    }

    // Update the IP checksum (important)
    ip_csum_replace(&ip->check, old_ttl, ip->ttl);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";