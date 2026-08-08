#ifndef COMMON_H_
#define COMMON_H_

#define PROTO_NONE 0x00

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// #if defined(IPPROTO_ICMP)
// #define IPPROTO_ICMP 1
// #define IPPROTO_TCP 6
// #define IPPROTO_UDP 17
// #endif

#define PIN_DIR "/sys/fs/bpf/xdp_firewall"
#define CONFIG_MAP_PATH "/sys/fs/bpf/xdp_firewall/config_map"
#define MANUAL_BLOCK_MAP_PATH "/sys/fs/bpf/xdp_firewall/manual_block_map"
#define LINK_PATH "/sys/fs/bpf/xdp_firewall/prog_link"

#if defined(__bpf__) || defined(__BPF__)
#include "vmlinux.h"
#else
#include <linux/types.h>
#include <stdint.h>
#endif

typedef struct {
  char device[16];
  __u8 block_mask;
} FirewallConfig;

#endif