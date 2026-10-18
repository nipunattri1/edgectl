#ifndef __HELPERS_BPF_H_
#define __HELPERS_BPF_H_

#include "../include/vmlinux.h"
#include "../include/common.h"
#include "maps.bpf.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_IPV6_EXT_HEADERS 8
#define ONE_SEC_NS 1000000000ULL

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

struct packet_headers {
  __be16 h_proto;
  __u8 l4_proto;
  struct iphdr *iph;
  struct ipv6hdr *ip6h;
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

static __always_inline int skip_ipv6_ext_headers(void *data_end,
                                                 struct ipv6hdr *ip6h,
                                                 __u8 *out_proto,
                                                 void **out_hdr_ptr) {
  __u8 next_proto = ip6h->nexthdr;
  void *cursor = (void *)(ip6h + 1);

#pragma unroll
  for (int i = 0; i < MAX_IPV6_EXT_HEADERS; i++) {
    switch (next_proto) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS: {
      struct ipv6_opt_hdr *opt = cursor;
      if ((void *)(opt + 1) > data_end)
        return -1;
      next_proto = opt->nexthdr;
      cursor += (opt->hdrlen + 1) * 8;
      break;
    }
    case IPPROTO_FRAGMENT: {
      struct frag_hdr *frag = cursor;
      if ((void *)(frag + 1) > data_end)
        return -1;
      if (frag->frag_off & bpf_htons(0xFFF8)) {
        *out_proto = IPPROTO_FRAGMENT;
        *out_hdr_ptr = NULL;
        return 0;
      }
      next_proto = frag->nexthdr;
      cursor += sizeof(struct frag_hdr);
      break;
    }
    case IPPROTO_AH: {
      struct ip_auth_hdr *ah = cursor;
      if ((void *)(ah + 1) > data_end)
        return -1;
      next_proto = ah->nexthdr;
      cursor += (ah->hdrlen + 2) * 4;
      break;
    }
    default:
      *out_proto = next_proto;
      *out_hdr_ptr = cursor;
      return 0;
    }

    if (cursor > data_end)
      return -1;
  }

  return -1;
}

static __always_inline int parse_headers(void *data, void *data_end,
                                         struct packet_headers *hdr) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  void *l4_ptr = NULL;
  __u8 l4_proto = 0;

  hdr->h_proto = eth->h_proto;

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
      return -1;

    if (iph->ihl < 5)
      return -1;

    __u32 ip_hlen = iph->ihl * 4;
    if ((void *)iph + ip_hlen > data_end)
      return -1;

    hdr->iph = iph;
    l4_proto = iph->protocol;

    /* Non-first IPv4 fragments carry no L4 header. */
    if (!(iph->frag_off & bpf_htons(0x1FFF)))
      l4_ptr = (void *)iph + ip_hlen;

  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
      return -1;

    hdr->ip6h = ip6h;

    if (skip_ipv6_ext_headers(data_end, ip6h, &l4_proto, &l4_ptr) < 0)
      return -1;

  } else {
    return -1;
  }

  hdr->l4_proto = l4_proto;

  if (!l4_ptr)
    return 0;

  if (l4_proto == IPPROTO_TCP) {
    if (l4_ptr + sizeof(struct tcphdr) > data_end)
      return -1;
    hdr->tcph = (struct tcphdr *)l4_ptr;
  } else if (l4_proto == IPPROTO_UDP) {
    if (l4_ptr + sizeof(struct udphdr) > data_end)
      return -1;
    hdr->udph = (struct udphdr *)l4_ptr;
  }

  return 0;
}

static __always_inline int get_ports(struct packet_headers *hdr, void *data_end,
                                     __be16 *sport, __be16 *dport) {
  if (!hdr->l4_hdr)
    return -1;

  if (hdr->l4_proto == IPPROTO_TCP) {
    if ((void *)(hdr->tcph + 1) > data_end)
      return -1;
    *sport = hdr->tcph->source;
    *dport = hdr->tcph->dest;
    return 0;
  }
  if (hdr->l4_proto == IPPROTO_UDP) {
    if ((void *)(hdr->udph + 1) > data_end)
      return -1;
    *sport = hdr->udph->source;
    *dport = hdr->udph->dest;
    return 0;
  }
  return -1;
}

static __always_inline int is_blacklisted(struct packet_headers *hdr) {
  if (hdr->iph) {
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .ip = hdr->iph->saddr,
    };
    __u32 *blocked = bpf_map_lookup_elem(&manual_blacklist_map, &key);
    return blocked && *blocked == 1;
  }

  if (hdr->ip6h) {
    struct ipv6_lpm_key key = {.prefixlen = 128};
    __builtin_memcpy(key.addr, &hdr->ip6h->saddr, 16);
    __u32 *blocked = bpf_map_lookup_elem(&manual_blacklist6_map, &key);
    return blocked && *blocked == 1;
  }

  return 0;
}

static __always_inline int rate_limit_exceeded(void *map, const void *key,
                                               __u32 limit) {
  __u64 now = bpf_ktime_get_ns();
  struct flood_tracker *tracker = bpf_map_lookup_elem(map, key);

  if (tracker) {
    __u64 elapsed = now - tracker->timestamp;

    if (elapsed > ONE_SEC_NS) {
      tracker->timestamp = now;
      tracker->count = 1;
      return 0;
    }

    if (tracker->count >= limit)
      return 1;

    __sync_fetch_and_add(&(tracker->count), 1);
  } else {
    struct flood_tracker new_tracker = {.timestamp = now, .count = 1};
    bpf_map_update_elem(map, key, &new_tracker, BPF_ANY);
  }

  return 0;
}

static __always_inline __u64 ipv6_src_prefix64(struct ipv6hdr *ip6h) {
  __u64 prefix;
  __builtin_memcpy(&prefix, &ip6h->saddr, sizeof(prefix));
  return prefix;
}

static __always_inline int syn_attack_check(struct packet_headers *hdr,
                                            FirewallConfig *config,
                                            void *data_end) {
  if (hdr->l4_proto != IPPROTO_TCP || !hdr->tcph)
    return 0;

  if ((void *)(hdr->tcph + 1) > data_end)
    return 0;

  if (!(hdr->tcph->syn && !hdr->tcph->ack))
    return 0;

  if (hdr->iph) {
    __u32 src_ip = hdr->iph->saddr;
    return rate_limit_exceeded(&syn_flood_map, &src_ip, config->syn_rate_limit);
  }

  if (hdr->ip6h) {
    __u64 prefix = ipv6_src_prefix64(hdr->ip6h);
    return rate_limit_exceeded(&syn6_flood_map, &prefix,
                               config->syn_rate_limit);
  }

  return 0;
}

static __always_inline int udp_attack_check(struct packet_headers *hdr,
                                            FirewallConfig *config,
                                            void *data_end) {
  if (hdr->l4_proto != IPPROTO_UDP || !hdr->udph)
    return 0;

  if ((void *)(hdr->udph + 1) > data_end)
    return 0;

  if (hdr->iph) {
    __u32 src_ip = hdr->iph->saddr;
    return rate_limit_exceeded(&udp_flood_map, &src_ip, config->udp_rate_limit);
  }

  if (hdr->ip6h) {
    __u64 prefix = ipv6_src_prefix64(hdr->ip6h);
    return rate_limit_exceeded(&udp6_flood_map, &prefix,
                               config->udp_rate_limit);
  }

  return 0;
}

#endif