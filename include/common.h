#ifndef COMMON_H_
#define COMMON_H_

#define PROTO_NONE 0x00
#define PROTO_TCP 0x01
#define PROTO_UDP 0x02
#define PROTO_ICMP 0x04

#define PIN_DIR "/sys/fs/bpf/xdp_firewall"
#define MAP_PATH "/sys/fs/bpf/xdp_firewall/config_map"
#define LINK_PATH "/sys/fs/bpf/xdp_firewall/prog_link"

typedef struct {
  char device[16];
  __u8 allow_mask;
  __u8 block_mask;
} FirewallConfig;

#endif