// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"

#define NF_DROP         0
#define NF_ACCEPT       1
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define IP_MF           0x2000
#define IP_OFFSET       0x1FFF
#define NEXTHDR_FRAGMENT    44

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
                  struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
                  void *buffer, uint32_t buffer__sz) __ksym;

volatile int shootdowns = 0;

static bool is_frag_v4(struct iphdr *iph)
{
    int offset;
    int flags;

    offset = bpf_ntohs(iph->frag_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;
    offset <<= 3;

    return (flags & IP_MF) || offset;
}

static int handle_v4(struct __sk_buff *skb)
{
    struct bpf_dynptr ptr;
    struct iphdr *iph;
    u8 iph_buf[20] = {};

    if (bpf_dynptr_from_skb(skb, 0, &ptr))
        return NF_DROP;

    iph = bpf_dynptr_slice(&ptr, 0, iph_buf, sizeof(iph_buf));
    if (!iph)
        return NF_DROP;

    /* Decrement TTL */
    if (iph->ttl > 1) {
        iph->ttl--;

        /* Recalculate checksum */
        __u16 *iph16 = (__u16 *)iph;
        __u32 csum = 0;
        iph->check = 0;
        for (int i = 0; i < sizeof(*iph) / 2; i++) {
            csum += *iph16++;
        }
        while (csum >> 16) {
            csum = (csum & 0xFFFF) + (csum >> 16);
        }
        iph->check = ~csum;
    } else {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

SEC("netfilter")
int defrag(struct bpf_nf_ctx *ctx)
{
    struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;

    switch (bpf_ntohs(ctx->skb->protocol)) {
    case ETH_P_IP:
        return handle_v4(skb);
    case ETH_P_IPV6:
        return NF_ACCEPT;
    default:
        return NF_ACCEPT;
    }
}

char _license[] SEC("license") = "GPL";