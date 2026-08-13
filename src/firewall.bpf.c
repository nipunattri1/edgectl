#include "../include/vmlinux.h"
#include "../include/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

// TC Action codes
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define PARSE_HEADERS(ctx_ptr, hdr_ptr)                                        \
  ({                                                                           \
    void *_data = (void *)(long)(ctx_ptr)->data;                               \
    void *_data_end = (void *)(long)(ctx_ptr)->data_end;                       \
    int _res = 0;                                                              \
    struct ethhdr *_eth = _data;                                               \
    if ((void *)(_eth + 1) > _data_end ||                                      \
        _eth->h_proto != bpf_htons(ETH_P_IP))                                  \
      _res = -1;                                                               \
    else {                                                                     \
      struct iphdr *_iph = (void *)(_eth + 1);                                 \
      if ((void *)(_iph + 1) > _data_end)                                      \
        _res = -1;                                                             \
      else {                                                                   \
        (hdr_ptr)->iph = _iph;                                                 \
        __u8 _ip_hl = _iph->ihl * 4;                                           \
        if (_ip_hl < sizeof(struct iphdr))                                     \
          _res = -1;                                                           \
        else {                                                                 \
          void *_l4_ptr = (void *)_iph + _ip_hl;                               \
          if (_iph->protocol == IPPROTO_TCP) {                                 \
            if (_l4_ptr + sizeof(struct tcphdr) > _data_end)                   \
              _res = -1;                                                       \
            else                                                               \
              (hdr_ptr)->tcph = (struct tcphdr *)_l4_ptr;                      \
          } else if (_iph->protocol == IPPROTO_UDP) {                          \
            if (_l4_ptr + sizeof(struct udphdr) > _data_end)                   \
              _res = -1;                                                       \
            else                                                               \
              (hdr_ptr)->udph = (struct udphdr *)_l4_ptr;                      \
          } else {                                                             \
            (hdr_ptr)->l4_hdr = NULL;                                          \
          }                                                                    \
        }                                                                      \
      }                                                                        \
    }                                                                          \
    _res;                                                                      \
  })

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
  return PARSE_HEADERS(ctx, hdr);
}

static __always_inline int parse_headers_skb(struct __sk_buff *skb,
                                             struct packet_headers *hdr) {
  return PARSE_HEADERS(skb, hdr);
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

  void *data_end = (void *)(long)ctx->data_end;
  int pkt_sz = data_end - (void *)(long)ctx->data;

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
  struct packet_headers hdr = {0};
  if (parse_headers_skb(skb, &hdr) < 0)
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
  struct packet_headers hdr = {0};
  if (parse_headers_skb(skb, &hdr) < 0)
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