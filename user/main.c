#include <linux/types.h>
#include "../include/common.h"
#include "../include/ini.h"
#include "config.h"
#include "firewall.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {

  if (argc < 2) {
    fprintf(stderr, "Usage:\n  %s attach\n  %s reload\n", argv[0], argv[0]);
    return 1;
  }

  FirewallConfig config = {
      .device = "lo",
      .block_mask = PROTO_NONE,
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
    struct in_addr dst;
    if (inet_pton(AF_INET, argv[2], &dst) != 1) {
      fprintf(stderr, "Invalid IP address format.\n");
      return 1;
    }

    uint32_t ip_network = dst.s_addr;
    // uint32_t ip_host = ntohl(ip_network);
    block_ip(ip_network);
  } else if (strcmp(argv[1], "unblock") == 0) {
    struct in_addr dst;
    if (inet_pton(AF_INET, argv[2], &dst) != 1) {
      fprintf(stderr, "Invalid IP address format.\n");
      return 1;
    }

    uint32_t ip_network = dst.s_addr;
    // uint32_t ip_host = ntohl(ip_network);
    unblock_ip(ip_network);
  } else if (strcmp(argv[1], "list") == 0) {
    print_blocked_ips();
  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
  }

  return 0;
}
