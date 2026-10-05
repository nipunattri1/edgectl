#include "../include/vmlinux.h"
#include "../include/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"
#include "utils.bpf.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2


static __always_inline int ct_refresh(struct connection_state *existing,
                                      __u8 proto, FirewallConfig *config) {
  __u64 now = bpf_ktime_get_ns();

  if (proto == IPPROTO_UDP &&
      now - existing->last_seen_ns > config->udp_timeout_ns)
    return 0;

  existing->last_seen_ns = now;
  return 1;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
  __u32 config_key = 0;
  FirewallConfig *config = bpf_map_lookup_elem(&config_map, &config_key);
  if (!config) {
    bpf_printk("no config found allowing all packets");
    return XDP_PASS;
  }

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct packet_headers hdr = {0};

  if (parse_headers(data, data_end, &hdr) < 0)
    return config->default_allow ? XDP_PASS : XDP_DROP;

  int pkt_sz = data_end - data;

  if (contains_proto(config->block_mask, hdr.l4_proto)) {
    bpf_printk("packet of size %d dropped", pkt_sz);
    return XDP_DROP;
  }

  if (is_blacklisted(&hdr)) {
    if (hdr.iph)
      bpf_printk("Dropping packet from %pI4 (LPM match: block)",
                 &hdr.iph->saddr);
    else
      bpf_printk("Dropping packet from %pI6 (LPM match: block)",
                 &hdr.ip6h->saddr);
    return XDP_DROP;
  }

  if (syn_attack_check(&hdr, config, data_end)) {
    bpf_printk("[FLOOD]: tcp flood detected, blocking");
    return XDP_DROP;
  }

  if (udp_attack_check(&hdr, config, data_end)) {
    bpf_printk("[FLOOD]: udp flood detected, blocking");
    return XDP_DROP;
  }

  return XDP_PASS;
}

SEC("tc/egress")
int handle_egress(struct __sk_buff *skb) {
  __u32 config_key = 0;
  FirewallConfig *config = bpf_map_lookup_elem(&config_map, &config_key);
  if (!config) {
    bpf_printk("no config found allowing all packets");
    return TC_ACT_OK;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct packet_headers hdr = {0};

  if (parse_headers(data, data_end, &hdr) < 0)
    return config->default_allow ? TC_ACT_OK : TC_ACT_SHOT;

  // Only TCP/UDP are tracked; everything else (eg. ICMPv6) passes. 
  __be16 sport, dport;
  if (get_ports(&hdr, data_end, &sport, &dport) < 0)
    return TC_ACT_OK;

  struct connection_state state = {
      .last_seen_ns = bpf_ktime_get_ns(),
      .state = 1,
  };

  if (hdr.iph) {
    struct connection_key key = {0};
    key.src_ip = hdr.iph->saddr;
    key.dst_ip = hdr.iph->daddr;
    key.src_port = sport;
    key.dst_port = dport;
    key.proto = hdr.l4_proto;
    bpf_map_update_elem(&ct_map, &key, &state, BPF_ANY);
  } else if (hdr.ip6h) {
    struct connection_key6 key = {0};
    __builtin_memcpy(key.src_ip, &hdr.ip6h->saddr, 16);
    __builtin_memcpy(key.dst_ip, &hdr.ip6h->daddr, 16);
    key.src_port = sport;
    key.dst_port = dport;
    key.proto = hdr.l4_proto;
    bpf_map_update_elem(&ct6_map, &key, &state, BPF_ANY);
  }

  return TC_ACT_OK;
}

SEC("tc/ingress")
int handle_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct packet_headers hdr = {0};

  if (parse_headers(data, data_end, &hdr) < 0)
    return TC_ACT_OK;

  __be16 sport, dport;
  if (get_ports(&hdr, data_end, &sport, &dport) < 0)
    return TC_ACT_OK;

  __u32 config_key = 0;
  FirewallConfig *config = bpf_map_lookup_elem(&config_map, &config_key);
  if (!config) {
    bpf_printk("no config found allowing all packets");
    return TC_ACT_OK;
  }

  if (hdr.iph) {
    struct connection_key reverse_key = {0};
    reverse_key.src_ip = hdr.iph->daddr;
    reverse_key.dst_ip = hdr.iph->saddr;
    reverse_key.src_port = dport;
    reverse_key.dst_port = sport;
    reverse_key.proto = hdr.l4_proto;

    struct connection_state *existing =
        bpf_map_lookup_elem(&ct_map, &reverse_key);
    if (existing) {
      if (!ct_refresh(existing, hdr.l4_proto, config)) {
        bpf_map_delete_elem(&ct_map, &reverse_key);
        return TC_ACT_SHOT;
      }
      return TC_ACT_OK;
    }
  } else if (hdr.ip6h) {
    struct connection_key6 reverse_key = {0};
    __builtin_memcpy(reverse_key.src_ip, &hdr.ip6h->daddr, 16);
    __builtin_memcpy(reverse_key.dst_ip, &hdr.ip6h->saddr, 16);
    reverse_key.src_port = dport;
    reverse_key.dst_port = sport;
    reverse_key.proto = hdr.l4_proto;

    struct connection_state *existing =
        bpf_map_lookup_elem(&ct6_map, &reverse_key);
    if (existing) {
      if (!ct_refresh(existing, hdr.l4_proto, config)) {
        bpf_map_delete_elem(&ct6_map, &reverse_key);
        return TC_ACT_SHOT;
      }
      return TC_ACT_OK;
    }
  }

  bpf_printk("[TC]: blocking connection");
  return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";