#ifndef LOADER_H_
#define LOADER_H_

#include <linux/types.h>
#include "../include/common.h"

void load_and_attach_firewall(FirewallConfig config);
void unload_firewall(const char *device_name);
void reload_config(FirewallConfig config);

void block_ip(__u32 ip, __u32 prefixlen);
void unblock_ip(__u32 ip, __u32 prefixlen);

void print_blocked_ips();

#endif