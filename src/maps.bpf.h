#ifndef MAPS_BPF_H_
#define MAPS_BPF_H_

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, FirewallConfig);
  __uint(max_entries, 1);
} config_map SEC(".maps");

#endif