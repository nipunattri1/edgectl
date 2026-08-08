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
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, __u32);   // IP
  __type(value, __u32); // hit counter
} manual_blacklist_map SEC(".maps");

#endif