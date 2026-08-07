#ifndef CONFIG_H_
#define CONFIG_H_
#include "../include/common.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t parse_protocols(const char *str) {
  uint8_t mask = PROTO_NONE;
  char buffer[128];
  strncpy(buffer, str, sizeof(buffer) - 1);
  buffer[sizeof(buffer) - 1] = '\0';

  char *token = strtok(buffer, ", ");
  while (token != NULL) {
    if (strcasecmp(token, "tcp") == 0)
      mask |= PROTO_TCP;
    else if (strcasecmp(token, "udp") == 0)
      mask |= PROTO_UDP;
    else if (strcasecmp(token, "icmp") == 0)
      mask |= PROTO_ICMP;

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
    if (strcmp(name, "allow_proto") == 0) {
      config->allow_mask = parse_protocols(value);
    } else if (strcmp(name, "block_proto") == 0) {
      config->block_mask = parse_protocols(value);
    }
  }
  return 1;
}

static void print_protocols(uint8_t mask) {
  if (mask & PROTO_TCP)
    printf("TCP ");
  if (mask & PROTO_UDP)
    printf("UDP ");
  if (mask & PROTO_ICMP)
    printf("ICMP ");
  if (mask == PROTO_NONE)
    printf("None");
  printf("\n");
}

#endif