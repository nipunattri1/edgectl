#ifndef CONFIG_H_
#define CONFIG_H_

#include "../include/common.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static inline void to_lowercase(char *str) {
  for (int i = 0; str[i] != '\0'; i++) {
    str[i] = tolower((unsigned char)str[i]);
  }
}

static uint64_t parse_protocols(const char *str) {
  uint64_t mask = PROTO_NONE;
  char buffer[128];
  strncpy(buffer, str, sizeof(buffer) - 1);
  buffer[sizeof(buffer) - 1] = '\0';

  char *token = strtok(buffer, ", ");
  while (token != NULL) {
    if (strcasecmp(token, "tcp") == 0)
      mask |= (1ULL << IPPROTO_TCP);
    else if (strcasecmp(token, "udp") == 0)
      mask |= (1ULL << IPPROTO_UDP);
    else if (strcasecmp(token, "icmp") == 0)
      mask |= (1ULL << IPPROTO_ICMP);
    else if (strcasecmp(token, "icmpv6") == 0 ||
             strcasecmp(token, "icmp6") == 0)
      mask |= (1ULL << IPPROTO_ICMPV6);

    token = strtok(NULL, ", ");
  }
  return mask;
}

static int firewall_ini_handler(void *user, const char *section,
                                const char *name, const char *value) {
  FirewallConfig *config = (FirewallConfig *)user;

  if (strcmp(section, "interface") == 0) {
    if (strcmp(name, "device") == 0) {
      strncpy(config->device, value, sizeof(config->device) - 1);
    }
  } else if (strcmp(section, "rules") == 0) {
    if (strcmp(name, "block_proto") == 0) {
      config->block_mask = parse_protocols(value);
    } else if (strcmp(name, "default") == 0) {
      char copy[32];
      strncpy(copy, value, sizeof(copy) - 1);
      copy[sizeof(copy) - 1] = '\0';
      to_lowercase(copy);
      config->default_allow = strcmp(copy, "allow") == 0 ? 1 : 0;
    }
  } else if (strcmp(section, "ddos") == 0) {
    if (strcmp(name, "syn_rate_limit") == 0) {
      config->syn_rate_limit = atoi(value);
    } else if (strcmp(name, "udp_rate_limit") == 0) {
      config->udp_rate_limit = atoi(value);
    }
  } else if (strcmp(section, "conn_track") == 0) {
    if (strcmp(name, "enable") == 0) {
      config->enable_tc = strcmp(value, "true") == 0 ? 1 : 0;
    } else if (strcmp(name, "udp_timeout_ns") == 0) {
      config->udp_timeout_ns = strtoull(value, NULL, 10);
    }
  }

  return 1;
}

#endif