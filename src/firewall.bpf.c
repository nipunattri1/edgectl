#include "../include/vmlinux.h"
#include "../include/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

struct packet_headers {
  struct iphdr *iph;
  union {
    struct tcphdr *tcph;
    struct udphdr *udph;
    void *l4_hdr;
  };
};

int contains_proto(uint8_t mask, int proto) {
  if (proto == 0)
    return 0;

  if (mask & (1 << proto))
    return 1;

  return 0;
}

static __always_inline int parse_headers(struct xdp_md *ctx, 
                                        struct packet_headers *hdr) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return -1;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return -1;

  hdr->iph = iph;

  __u8 ip_hl = iph->ihl * 4;
  if (ip_hl < sizeof(struct iphdr))
    return -1;

  void *l4_ptr = (void *)iph + ip_hl;

  if (iph->protocol == IPPROTO_TCP) {
    if (l4_ptr + sizeof(struct tcphdr) > data_end)
      return -1;
    hdr->tcph = (struct tcphdr *)l4_ptr;
  } else if (iph->protocol == IPPROTO_UDP) {
    if (l4_ptr + sizeof(struct udphdr) > data_end)
      return -1;
    hdr->udph = (struct udphdr *)l4_ptr;
  } else {
    hdr->l4_hdr = NULL;
  }

  return 0;
}

static __always_inline int syn_attack_check(struct packet_headers *hdr,
                                            FirewallConfig *config) {
  if (hdr->iph->protocol != IPPROTO_TCP || !hdr->tcph)
    return 0;

  if (!(hdr->tcph->syn && !hdr->tcph->ack))
    return 0;

  __u32 src_ip = hdr->iph->saddr;
  __u64 now = bpf_ktime_get_ns();

  struct flood_tracker *tracker = bpf_map_lookup_elem(&syn_flood_map, &src_ip);

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
    struct flood_tracker new_tracker = {.timestamp = now, .count = 1};
    bpf_map_update_elem(&syn_flood_map, &src_ip, &new_tracker, BPF_ANY);
  }

  return 0;
}

static __always_inline int udp_attack_check(struct packet_headers *hdr,
                                            FirewallConfig *config) {
  if (hdr->iph->protocol != IPPROTO_UDP || !hdr->udph)
    return 0;

  __u32 src_ip = hdr->iph->saddr;
  __u64 now = bpf_ktime_get_ns();

  struct flood_tracker *tracker = bpf_map_lookup_elem(&udp_flood_map, &src_ip);

  if (tracker) {
    __u64 elapsed = now - tracker->timestamp;

    if (elapsed > 1000000000ULL) {
      tracker->timestamp = now;
      tracker->count = 1;
      return 0;
    }

    if (tracker->count >= config->udp_rate_limit) {
      return 1;
    }

    tracker->count++;
  } else {
    struct flood_tracker new_tracker = {.timestamp = now, .count = 1};
    bpf_map_update_elem(&udp_flood_map, &src_ip, &new_tracker, BPF_ANY);
  }

  return 0;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
  struct packet_headers hdr = {0};

  if (parse_headers(ctx, &hdr) < 0)
    return XDP_PASS;

  int pkt_sz = (void *)(long)ctx->data_end - (void *)(long)ctx->data;

  __u32 config_key = 0;
  FirewallConfig *config = bpf_map_lookup_elem(&config_map, &config_key);
  if (config) {
    if (contains_proto(config->block_mask, hdr.iph->protocol)) {
      bpf_printk("packet of size %d dropped", pkt_sz);
      return XDP_DROP;
    }
  } else {
    bpf_printk("no config found allowing all packets");
    return XDP_PASS;
  }

  struct ipv4_lpm_key key = {
      .prefixlen = 32,
      .ip = hdr.iph->saddr,
  };

  __u32 *is_blocked = bpf_map_lookup_elem(&manual_blacklist_map, &key);
  if (is_blocked && *is_blocked == 1) {
    bpf_printk("Dropping packet from %pI4 (LPM match: block)", &hdr.iph->saddr);
    return XDP_DROP;
  }

  if (syn_attack_check(&hdr, config))
    return XDP_DROP;

  if (udp_attack_check(&hdr, config))
    return XDP_DROP;

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";