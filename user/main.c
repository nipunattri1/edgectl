#include <linux/types.h>
#include "../include/common.h"
#include "../include/ini.h"
#include "config.h"
#include "loader.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

  if (argc < 2) {
    fprintf(stderr, "Usage:\n  %s attach\n  %s reload\n", argv[0], argv[0]);
    return 1;
  }

  FirewallConfig config = {
      .device = "lo",
      .allow_mask = PROTO_NONE,
      .block_mask = PROTO_NONE,
  };

  if (ini_parse("config/config.ini", firewall_ini_handler, &config) < 0) {
    fprintf(stderr,
            "Error loading 'config.ini', applying default fallbacks.\n");
  }

  if (strcmp(argv[1], "attach") == 0) {
    load_and_attach_firewall(config);
    return 0;
  } else if (strcmp(argv[1], "reload") == 0) {
    // return do_config(argc - 1, argv + 1);
    return 1;
  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
  }

  return 0;
}
