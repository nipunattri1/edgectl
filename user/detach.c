/*
 * detach.c - tear down XDP/TC and remove all pins for an interface.
 */
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "firewall.h"
#include "internal.h"
#include <bpf/libbpf.h>

#include "../include/common.h"
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Detach XDP/TC, destroy hooks and unpin everything. */
void unload_firewall(const char *device_name) {
  int ifindex = if_nametoindex(device_name);
  if (ifindex == 0) {
    fprintf(stderr, "Error: Invalid interface %s\n", device_name);
    return;
  }

  printf("Unloading firewall from interface %s (ifindex: %d)...\n", device_name,
         ifindex);

  if (bpf_xdp_detach(ifindex, 0, NULL) < 0) {
    fprintf(stderr, "XDP detach skipped or not attached\n");
  } else {
    printf("Detached XDP\n");
  }

  struct bpf_tc_hook hook = {
      .sz = sizeof(struct bpf_tc_hook),
      .ifindex = ifindex,
      .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS,
  };

  bpf_tc_hook_destroy(&hook);
  printf("Cleaned up TC hooks\n");

  printf("Unpinning BPF objects from %s...\n", PIN_DIR);
  unlink_all_pins();

  if (rmdir(PIN_DIR) < 0 && errno != ENOENT) {
    fprintf(stderr, "Warning: Failed to remove directory %s: %s\n", PIN_DIR,
            strerror(errno));
  }

  printf("Firewall unloaded.\n");
}
