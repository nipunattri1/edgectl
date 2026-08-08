#ifndef MAPS_BPF_H_
#define MAPS_BPF_H_

#include "../include/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../include/common.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, FirewallConfig);
  __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv4_lpm_key); // IP
  __type(value, __u32);             // hit counter
  __uint(map_flags, BPF_F_NO_PREALLOC);
} manual_blacklist_map SEC(".maps");

#endif