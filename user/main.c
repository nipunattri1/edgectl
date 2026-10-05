#include <linux/types.h>
#include "../include/common.h"
#include "../include/ini.h"
#include "config.h"
#include "firewall.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int parse_cidr(const char *arg, struct ip_net *net);

int main(int argc, char **argv) {

  if (argc < 2) {
    fprintf(stderr,
            "Usage:\n  %s attach|detach|reload|list\n  %s block|unblock "
            "<ipv4|ipv6>[/prefix]\n",
            argv[0], argv[0]);
    return 1;
  }

  FirewallConfig config = {
      .device = "lo",
      .block_mask = PROTO_NONE,
      .syn_rate_limit = 100,
      .udp_rate_limit = 1000,
      .udp_timeout_ns = 30000000000,
      .default_allow = 1,
  };

  if (ini_parse("config/config.ini", firewall_ini_handler, &config) < 0) {
    fprintf(stderr,
            "Error loading 'config.ini', applying default fallbacks.\n");
  }

  if (strcmp(argv[1], "attach") == 0) {
    load_and_attach_firewall(config);

  } else if (strcmp(argv[1], "detach") == 0) {
    unload_firewall(config.device);

  } else if (strcmp(argv[1], "reload") == 0) {
    reload_config(config);

  } else if (strcmp(argv[1], "block") == 0 || strcmp(argv[1], "unblock") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage: %s %s <ipv4|ipv6>[/prefix]\n", argv[0], argv[1]);
      return 1;
    }

    struct ip_net net;
    if (parse_cidr(argv[2], &net) != 0)
      return 1;

    if (strcmp(argv[1], "block") == 0)
      block_ip(&net);
    else
      unblock_ip(&net);

  } else if (strcmp(argv[1], "list") == 0) {
    print_blocked_ips();

  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
  }

  return 0;
}

static int parse_cidr(const char *arg, struct ip_net *net) {
  char ip_str[INET6_ADDRSTRLEN + 8];
  if (strlen(arg) >= sizeof(ip_str)) {
    fprintf(stderr, "Address too long: %s\n", arg);
    return -1;
  }
  strcpy(ip_str, arg);

  char *slash = strchr(ip_str, '/');
  long prefixlen = -1;

  if (slash != NULL) {
    *slash = '\0';
    char *end = NULL;
    errno = 0;
    prefixlen = strtol(slash + 1, &end, 10);
    if (errno || end == slash + 1 || *end != '\0' || prefixlen < 0) {
      fprintf(stderr, "Invalid prefix length '%s'.\n", slash + 1);
      return -1;
    }
  }

  memset(net, 0, sizeof(*net));

  if (inet_pton(AF_INET, ip_str, &net->addr.v4) == 1) {
    net->family = AF_INET;
    if (prefixlen < 0)
      prefixlen = 32;
    if (prefixlen > 32) {
      fprintf(stderr, "Invalid prefix length /%ld. Must be 0-32 for IPv4.\n",
              prefixlen);
      return -1;
    }
  } else if (inet_pton(AF_INET6, ip_str, &net->addr.v6) == 1) {
    net->family = AF_INET6;
    if (prefixlen < 0)
      prefixlen = 128;
    if (prefixlen > 128) {
      fprintf(stderr, "Invalid prefix length /%ld. Must be 0-128 for IPv6.\n",
              prefixlen);
      return -1;
    }
  } else {
    fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
    return -1;
  }

  net->prefixlen = (__u32)prefixlen;
  return 0;
}