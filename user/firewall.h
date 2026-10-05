#ifndef LOADER_H_
#define LOADER_H_

#include "../include/common.h"
#include <linux/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

struct ipv6_lpm_key {
  __u32 prefixlen;
  __u8 addr[16];
};

struct ip_net {
  int family; /* AF_INET or AF_INET6 */
  __u32 prefixlen;
  union {
    __u32 v4;
    struct in6_addr v6;
  } addr;
};

void load_and_attach_firewall(FirewallConfig config);
void unload_firewall(const char *device_name);
void reload_config(FirewallConfig config);

void block_ip(const struct ip_net *net);
void unblock_ip(const struct ip_net *net);

void print_blocked_ips(void);

#endif