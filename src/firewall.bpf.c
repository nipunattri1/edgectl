#include "../include/vmlinux.h"
#include "../include/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct packet_headers {
  struct iphdr *iph;
  union {
    struct tcphdr *tcph;
    struct udphdr *udph;
    void *l4_hdr;
  };
};

static __always_inline int contains_proto(__u64 mask, __u8 proto) {
  if (proto == 0 || proto >= 64)
    return 0;
  return (mask & (1ULL << proto)) ? 1 : 0;
}

static __always_inline int parse_headers(void *data, void *data_end,
                                         struct packet_headers *hdr) {
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
                                            FirewallConfig *config,
                                            void *data_end) {
  if (hdr->iph->protocol != IPPROTO_TCP || !hdr->tcph)
    return 0;

  if ((void *)(hdr->tcph + 1) > data_end)
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
    __sync_fetch_and_add(&(tracker->count), 1);
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

    __sync_fetch_and_add(&(tracker->count), 1);
  } else {
    struct flood_tracker new_tracker = {.timestamp = now, .count = 1};
    bpf_map_update_elem(&udp_flood_map, &src_ip, &new_tracker, BPF_ANY);
  }

  return 0;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct packet_headers hdr = {0};

  if (parse_headers(data, data_end, &hdr) < 0)
    return XDP_PASS;

  int pkt_sz = data_end - data;

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

  if (syn_attack_check(&hdr, config, data_end))
    return XDP_DROP;

  if (udp_attack_check(&hdr, config))
    return XDP_DROP;

  return XDP_PASS;
}

SEC("tc/egress")
int handle_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct packet_headers hdr = {0};

  if (parse_headers(data, data_end, &hdr) < 0)
    return TC_ACT_OK;

  struct connection_key key = {0};
  key.src_ip = hdr.iph->saddr;
  key.dst_ip = hdr.iph->daddr;
  key.proto = hdr.iph->protocol;

  if (hdr.iph->protocol == IPPROTO_TCP && hdr.tcph) {
    key.src_port = hdr.tcph->source;
    key.dst_port = hdr.tcph->dest;
  } else if (hdr.iph->protocol == IPPROTO_UDP && hdr.udph) {
    key.src_port = hdr.udph->source;
    key.dst_port = hdr.udph->dest;
  } else {
    return TC_ACT_OK;
  }

  struct connection_state state = {.last_seen_ns = bpf_ktime_get_ns(),
                                   .state = 1};

  bpf_map_update_elem(&ct_map, &key, &state, BPF_ANY);

  return TC_ACT_OK;
}

SEC("tc/ingress")
int handle_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct packet_headers hdr = {0};

  if (parse_headers(data, data_end, &hdr) < 0)
    return TC_ACT_OK;

  struct connection_key reverse_key = {0};
  reverse_key.src_ip = hdr.iph->daddr;
  reverse_key.dst_ip = hdr.iph->saddr;
  reverse_key.proto = hdr.iph->protocol;

  if (hdr.iph->protocol == IPPROTO_TCP && hdr.tcph) {
    reverse_key.src_port = hdr.tcph->dest;
    reverse_key.dst_port = hdr.tcph->source;
  } else if (hdr.iph->protocol == IPPROTO_UDP && hdr.udph) {
    reverse_key.src_port = hdr.udph->dest;
    reverse_key.dst_port = hdr.udph->source;
  } else {
    return TC_ACT_OK;
  }

  __u32 config_key = 0;
  FirewallConfig *config = bpf_map_lookup_elem(&config_map, &config_key);
  if (!config) {
    bpf_printk("no config found allowing all packets");
    return TC_ACT_OK;
  }

  struct connection_state *existing =
      bpf_map_lookup_elem(&ct_map, &reverse_key);
  if (existing) {
    __u64 now = bpf_ktime_get_ns();

    if (hdr.iph->protocol == IPPROTO_UDP) {
      if (now - existing->last_seen_ns > config->udp_timeout_ns) {
        bpf_map_delete_elem(&ct_map, &reverse_key);
        return TC_ACT_SHOT;
      }
    }

    existing->last_seen_ns = now;
    return TC_ACT_OK;
  }

  return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";