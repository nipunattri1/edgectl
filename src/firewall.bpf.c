#include "../include/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  int pkt_sz = data_end - data;

  struct ethhdr *eth = data;

  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

  if (iph->protocol == IPPROTO_ICMP) {
    bpf_printk("ICMP packet of size %d dropped", pkt_sz);
    return XDP_DROP;
  }
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";