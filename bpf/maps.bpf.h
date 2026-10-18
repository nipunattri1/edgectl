#ifndef MAPS_BPF_H_
#define MAPS_BPF_H_

#include "../include/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../include/common.h"

struct ipv6_lpm_key {
  __u32 prefixlen;
  __u8 addr[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, FirewallConfig);
  __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} manual_blacklist_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv6_lpm_key); // IPv6
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} manual_blacklist6_map SEC(".maps");


struct flood_tracker {
  __u64 timestamp;
  __u32 count;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10000);
  __type(key, __u32); 
  __type(value, struct flood_tracker);
} syn_flood_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10000);
  __type(key, __u32); 
  __type(value, struct flood_tracker);
} udp_flood_map SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10000);
  __type(key, __u64); 
  __type(value, struct flood_tracker);
} syn6_flood_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10000);
  __type(key, __u64); // IPv6 source /64
  __type(value, struct flood_tracker);
} udp6_flood_map SEC(".maps");


struct connection_key {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
  __u8 pad[3];
};

struct connection_key6 {
  __u8 src_ip[16];
  __u8 dst_ip[16];
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
  __u8 pad[3];
};

struct connection_state {
  __u64 last_seen_ns;
  __u8 state;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct connection_key);
  __type(value, struct connection_state);
} ct_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct connection_key6);
  __type(value, struct connection_state);
} ct6_map SEC(".maps");

#endif