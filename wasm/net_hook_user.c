#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>

#define DROP_PORT 20080

static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;

  if (!skb)
    return NF_ACCEPT;

  iph = ip_hdr(skb);
  if (!iph)
    return NF_ACCEPT;

  if (iph->protocol == IPPROTO_TCP) {
    tcph = tcp_hdr(skb);
    if (!tcph)
      return NF_ACCEPT;

    if (ntohs(tcph->dest) == DROP_PORT) {
      return NF_DROP; // Drop the packet
    }
  }

  return NF_ACCEPT;
}