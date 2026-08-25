#ifndef __HELPERS_BPF_H_
#define __HELPERS_BPF_H_

#include "../include/vmlinux.h"
#include "../include/common.h"
#include "maps.bpf.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_IPV6_EXT_HEADERS 8

enum {
  IPPROTO_HOPOPTS = 0,
#define IPPROTO_HOPOPTS IPPROTO_HOPOPTS
  IPPROTO_ROUTING = 43,
#define IPPROTO_ROUTING IPPROTO_ROUTING
  IPPROTO_FRAGMENT = 44,
#define IPPROTO_FRAGMENT IPPROTO_FRAGMENT
  IPPROTO_ICMPV6 = 58,
#define IPPROTO_ICMPV6 IPPROTO_ICMPV6
  IPPROTO_NONE = 59,
#define IPPROTO_NONE IPPROTO_NONE
  IPPROTO_DSTOPTS = 60,
#define IPPROTO_DSTOPTS IPPROTO_DSTOPTS
  IPPROTO_MH = 135
#define IPPROTO_MH IPPROTO_MH
};

struct packet_headers {
  __be16 h_proto;
  struct iphdr *iph;
  struct ipv6hdr *iph_v6;
  struct tcphdr *tcph;
  struct udphdr *udph;
};

static __always_inline int parse_headers(void *data, void *data_end,
                                         struct packet_headers *hdr) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  switch (eth->h_proto) {
  case bpf_htons(ETH_P_IP): {
    hdr->h_proto = bpf_htons(ETH_P_IP);
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
      return -1;

    if (iph->ihl < 5)
      return -1;

    __u32 ip_hlen = iph->ihl * 4;
    if ((void *)iph + ip_hlen > data_end)
      return -1;

    hdr->iph = iph; // Fixed: assigned iph pointer

    void *l4_ptr = (void *)iph + ip_hlen;

    if (iph->protocol == IPPROTO_TCP) {
      if (l4_ptr + sizeof(struct tcphdr) > data_end)
        return -1;
      hdr->tcph = (struct tcphdr *)l4_ptr;
    } else if (iph->protocol == IPPROTO_UDP) {
      if (l4_ptr + sizeof(struct udphdr) > data_end)
        return -1;
      hdr->udph = (struct udphdr *)l4_ptr;
    }
    break;
  }
  case bpf_htons(ETH_P_IPV6): {
    hdr->h_proto = bpf_htons(ETH_P_IPV6);
    struct ipv6hdr *iph_v6 = (void *)(eth + 1);
    if ((void *)(iph_v6 + 1) > data_end)
      return -1;

    hdr->iph_v6 = iph_v6;
    void *l4_ptr = (void *)(iph_v6 + 1);

    if (iph_v6->nexthdr == IPPROTO_TCP) {
      if (l4_ptr + sizeof(struct tcphdr) > data_end)
        return -1;
      hdr->tcph = (struct tcphdr *)l4_ptr;
    } else if (iph_v6->nexthdr == IPPROTO_UDP) {
      if (l4_ptr + sizeof(struct udphdr) > data_end)
        return -1;
      hdr->udph = (struct udphdr *)l4_ptr;
    }
    break;
  }
  default:
    return -1;
  }
  return 0;
}

static __always_inline int contains_proto(__u64 mask, __u8 proto) {
  if (proto == 0 || proto >= 64)
    return 0;
  return (mask & (1ULL << proto)) ? 1 : 0;
}

static __always_inline int skip_ipv6_ext_headers(void *data, void *data_end,
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

static __always_inline int syn_attack_check(struct packet_headers *hdr,
                                            FirewallConfig *config,
                                            void *data_end) {
  struct iphdr *iph = hdr->iph;
  if (!iph || (void *)(iph + 1) > data_end)
    return 0;

  if (iph->protocol != IPPROTO_TCP || !hdr->tcph)
    return 0;

  if (!(hdr->tcph->syn && !hdr->tcph->ack))
    return 0;

  __u32 src_ip = iph->saddr;
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
  // Fixed: Safety check on hdr->iph to prevent NULL dereference
  if (!hdr->iph || hdr->iph->protocol != IPPROTO_UDP || !hdr->udph)
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

#endif /* __HELPERS_BPF_H_ */