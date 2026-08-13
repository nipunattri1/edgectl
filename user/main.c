#include <linux/types.h>
#include "../include/common.h"
#include "../include/ini.h"
#include "config.h"
#include "firewall.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int parse_cidr(const char *arg, uint32_t *ip_out, uint32_t *prefixlen_out);

int main(int argc, char **argv) {

  if (argc < 2) {
    fprintf(stderr, "Usage:\n  %s attach\n  %s reload\n", argv[0], argv[0]);
    return 1;
  }

  FirewallConfig config = {
      .device = "lo",
      .block_mask = PROTO_NONE,
      .syn_rate_limit = 100,
      .udp_rate_limit = 1000,
  };

  if (ini_parse("config/config.ini", firewall_ini_handler, &config) < 0) {
    fprintf(stderr,
            "Error loading 'config.ini', applying default fallbacks.\n");
  }

  if (strcmp(argv[1], "attach") == 0) {
    load_and_attach_firewall(config);

  } else if (strcmp(argv[1], "reload") == 0) {
    reload_config(config);

  } else if (strcmp(argv[1], "block") == 0) {
    uint32_t ip_network;
    uint32_t prefixlen;

    if (parse_cidr(argv[2], &ip_network, &prefixlen) != 0) {
      return 1;
    }

    block_ip(ip_network, prefixlen);

    printf("Successfully blocked %s (Prefix length: /%u)\n", argv[2],
           prefixlen);

  } else if (strcmp(argv[1], "unblock") == 0) {
    uint32_t ip_network;
    uint32_t prefixlen;

    if (parse_cidr(argv[2], &ip_network, &prefixlen) != 0) {
      return 1;
    }

    unblock_ip(ip_network, prefixlen);
    printf("Successfully unblocked %s (Prefix length: /%u)\n", argv[2],
           prefixlen);

  } else if (strcmp(argv[1], "list") == 0) {
    print_blocked_ips();

  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
  }

  return 0;
}

int parse_cidr(const char *arg, uint32_t *ip_out, uint32_t *prefixlen_out) {
  char ip_str[64];
  strncpy(ip_str, arg, sizeof(ip_str) - 1);
  ip_str[sizeof(ip_str) - 1] = '\0';

  char *slash = strchr(ip_str, '/');
  uint32_t prefixlen = 32;

  if (slash != NULL) {
    *slash = '\0';
    prefixlen = atoi(slash + 1);

    if (prefixlen > 32) {
      fprintf(stderr, "Invalid prefix length /%u. Must be between 0 and 32.\n",
              prefixlen);
      return -1;
    }
  }

  struct in_addr dst;
  if (inet_pton(AF_INET, ip_str, &dst) != 1) {
    fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
    return -1;
  }

  *ip_out = dst.s_addr;
  *prefixlen_out = prefixlen;
  return 0;
}