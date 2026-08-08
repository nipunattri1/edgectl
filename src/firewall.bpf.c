#include "../include/vmlinux.h"
#include "../include/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// #include <linux/bpf.h>

#include "maps.bpf.h"

int contains_proto(uint8_t mask, int proto) {
  if (proto == 0)
    return 0;

  if (mask & (1 << proto))
    return 1;

  return 0;
}

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

  __u32 config_key = 0;
  FirewallConfig *config = bpf_map_lookup_elem(&config_map, &config_key);
  if (config) {
    if (contains_proto(config->block_mask, iph->protocol)) {
      bpf_printk("ICMP packet of size %d dropped", pkt_sz);
      return XDP_DROP;
    }
  }

  __u32 *blocked = bpf_map_lookup_elem(&manual_blacklist_map, &iph->saddr);

  if (blocked) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";