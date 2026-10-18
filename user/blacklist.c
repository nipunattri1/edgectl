/*
 * blacklist.c - manage LPM blacklist entries and list them.
 */
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "firewall.h"

#include "../include/common.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Insert/update one LPM entry with value val. */
static int set_rule(const struct ip_net *net, __u32 val, const char *verb) {
  const char *path =
      net->family == AF_INET6 ? MANUAL_BLOCK_MAP6_PATH : MANUAL_BLOCK_MAP_PATH;

  int map_fd = bpf_obj_get(path);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n", path,
            strerror(errno));
    return -1;
  }

  int ret;
  if (net->family == AF_INET6) {
    struct ipv6_lpm_key key = {.prefixlen = net->prefixlen};
    memcpy(key.addr, &net->addr.v6, sizeof(key.addr));
    ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
  } else {
    struct ipv4_lpm_key key = {.prefixlen = net->prefixlen, .ip = net->addr.v4};
    ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
  }

  if (ret < 0)
    fprintf(stderr, "Failed to %s IP/subnet: %s\n", verb, strerror(errno));
  else
    printf("Successfully %sed rule (val: %u).\n", verb, val);

  close(map_fd);
  return ret;
}

/* Add a subnet/IP to the blacklist. */
void block_ip(const struct ip_net *net) { set_rule(net, 1, "block"); }

/* Remove (mark allowed) a subnet/IP. */
void unblock_ip(const struct ip_net *net) { set_rule(net, 0, "unblock"); }

static size_t print_family(const char *path, int family) {
  int map_fd = bpf_obj_get(path);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n", path,
            strerror(errno));
    return 0;
  }

  size_t count = 0;
  union {
    struct ipv4_lpm_key v4;
    struct ipv6_lpm_key v6;
  } key, next;

  int res = bpf_map_get_next_key(map_fd, NULL, &next);
  while (res == 0) {
    __u32 val = 0;
    char ip_str[INET6_ADDRSTRLEN];
    bpf_map_lookup_elem(map_fd, &next, &val);

    const char *s = NULL;
    __u32 prefixlen;
    if (family == AF_INET6) {
      s = inet_ntop(AF_INET6, next.v6.addr, ip_str, sizeof(ip_str));
      prefixlen = next.v6.prefixlen;
    } else {
      struct in_addr addr = {.s_addr = next.v4.ip};
      s = inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
      prefixlen = next.v4.prefixlen;
    }

    if (s) {
      printf(" - %s/%u [%s]\n", ip_str, prefixlen,
             val == 1 ? "BLOCKED" : "ALLOWED");
      count++;
    }

    key = next;
    res = bpf_map_get_next_key(map_fd, &key, &next);
  }

  close(map_fd);
  return count;
}

/* Print all configured blacklist entries. */
void print_blocked_ips(void) {
  printf("Configured IP Rules:\n");
  size_t n = print_family(MANUAL_BLOCK_MAP_PATH, AF_INET);
  n += print_family(MANUAL_BLOCK_MAP6_PATH, AF_INET6);
  if (n == 0)
    printf("No rules found or failed to read maps.\n");
}
