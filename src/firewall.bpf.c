#include "../include/vmlinux.h"
#include "../include/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "maps.bpf.h"

int contains_proto(uint8_t mask, int proto) {
  if (proto == 0)
    return 0;

  if (mask & (1 << proto))
    return 1;

  return 0;
}

static __always_inline int syn_attack_check(struct iphdr *iph,
                                            FirewallConfig *config) {
  if (iph->protocol != IPPROTO_TCP)
    return 0;

  __u8 ip_hl = iph->ihl * 4;
  if (ip_hl < sizeof(struct iphdr))
    return 0;

  struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_hl);

  if (!(tcph->syn && !tcph->ack))
    return 0;

  __u32 src_ip = iph->saddr;
  __u64 now = bpf_ktime_get_ns();

  struct syn_tracker *tracker = bpf_map_lookup_elem(&syn_flood_map, &src_ip);

  if (tracker) {
    __u64 elapsed = now - tracker->timestamp;

    if (elapsed > 1000000000ULL) {
      tracker->timestamp = now;
      tracker->count = 1;
      return 0;
    }

    if (tracker->count >= config->syn_rate_limit) {
      return 1;
    }

    tracker->count++;
  } else {
    // New source IP
    struct syn_tracker new_tracker = {.timestamp = now, .count = 1};
    bpf_map_update_elem(&syn_flood_map, &src_ip, &new_tracker, BPF_ANY);
  }
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
      bpf_printk("packet of size %d dropped", pkt_sz);
      return XDP_DROP;
    }
  } else {
    // no config exists or some error with config
    bpf_printk("no config found allowing all packets");
    return XDP_PASS;
  }

  struct ipv4_lpm_key key = {
      .prefixlen = 32,
      .ip = iph->saddr,
  };

  __u32 *is_blocked = bpf_map_lookup_elem(&manual_blacklist_map, &key);

  if (is_blocked && *is_blocked == 1) {
    bpf_printk("Dropping packet from %pI4 (LPM match: block)", &iph->saddr);
    return XDP_DROP;
  }

  if (syn_attack_check(iph, config)) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";