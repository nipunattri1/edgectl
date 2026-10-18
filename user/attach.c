/*
 * attach.c
 *
 * Loads the eBPF firewall skeleton, attaches the XDP program (and the TC
 * ingress/egress programs when connection tracking is enabled), and pins
 * every map plus the XDP link under PIN_DIR so that later processes and
 * `reload` can reach them.
 *
 * All failures are fatal: on any error we tear down whatever was attached,
 * remove all pins, destroy the skeleton and exit(1). This keeps the system
 * from being left in a half-attached state.
 */

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "firewall.h"
#include "internal.h"

#include "../include/common.h"
#include "../bpf/firewall.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Create the bpffs pin directory if it does not already exist. */
static void ensure_pin_dir_exists(const char *dir) {
  struct stat st = {0};
  if (stat(dir, &st) == -1) {
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
      fprintf(stderr, "Failed to create pin directory %s: %s\n", dir,
              strerror(errno));
    }
  }
}

/* Remove every pinned object so a fresh attach starts from a clean state. */
void unlink_all_pins(void) {
  unlink(LINK_PATH);
  unlink(CONFIG_MAP_PATH);
  unlink(MANUAL_BLOCK_MAP_PATH);
  unlink(MANUAL_BLOCK_MAP6_PATH);
  unlink(CT_MAP_PATH);
  unlink(CT6_MAP_PATH);
}

/* Pin one map to bpffs. Returns 0 on success, negative errno on failure. */
static int pin_map(struct bpf_map *map, const char *path) {
  int err = bpf_map__pin(map, path);
  if (err)
    fprintf(stderr, "Failed to pin map %s: %s\n", path, strerror(-err));
  return err;
}

/*
 * Open, configure, attach and pin the whole firewall.
 *
 * Steps:
 *   1. Prepare the pin directory and clear stale pins.
 *   2. Resolve the interface index.
 *   3. Open + load the BPF skeleton.
 *   4. Push the initial FirewallConfig into config_map.
 *   5. Attach XDP at the driver level.
 *   6. (Optional) Create the clsact qdisc and attach TC ingress + egress.
 *   7. Pin the XDP link and all maps.
 *
 * On any failure the cleanup: labels detach what was attached, destroy the
 * skeleton and exit(1).
 */
void load_and_attach_firewall(FirewallConfig config) {
  struct firewall_bpf *skel;
  int err = 0, ifindex;
  bool ingress_attached = false;
  bool egress_attached = false;

  ensure_pin_dir_exists(PIN_DIR);
  unlink_all_pins();

  ifindex = if_nametoindex(config.device);
  if (ifindex == 0) {
    fprintf(stderr, "Error getting ifindex\n");
    exit(1);
  }

  skel = firewall_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Unable to load ebpf skeleton\n");
    goto cleanup;
  }

  /* Seed the runtime config map before any program runs. */
  __u32 key = 0;
  bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key), &config,
                       sizeof(config), BPF_ANY);

  skel->links.xdp_firewall =
      bpf_program__attach_xdp(skel->progs.xdp_firewall, ifindex);
  if (!skel->links.xdp_firewall) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  struct bpf_tc_hook ingress_hook = {0};
  struct bpf_tc_opts ingress_opts = {0};
  struct bpf_tc_hook egress_hook = {0};
  struct bpf_tc_opts egress_opts = {0};

  if (config.enable_tc != 0) {
    ingress_hook.sz = sizeof(ingress_hook);
    ingress_hook.ifindex = ifindex;
    ingress_hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&ingress_hook);
    if (err && err != -EEXIST) {
      fprintf(stderr, "Failed to create TC clsact hook: %s\n", strerror(-err));
      goto cleanup;
    }

    ingress_opts.sz = sizeof(ingress_opts);
    ingress_opts.prog_fd = bpf_program__fd(skel->progs.handle_ingress);
    err = bpf_tc_attach(&ingress_hook, &ingress_opts);
    if (err) {
      fprintf(stderr, "Failed to attach TC ingress filter: %s\n",
              strerror(-err));
      goto cleanup;
    }
    ingress_attached = true;

    egress_hook.sz = sizeof(egress_hook);
    egress_hook.ifindex = ifindex;
    egress_hook.attach_point = BPF_TC_EGRESS;

    egress_opts.sz = sizeof(egress_opts);
    egress_opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    err = bpf_tc_attach(&egress_hook, &egress_opts);
    if (err) {
      fprintf(stderr, "Failed to attach TC egress filter: %s\n",
              strerror(-err));
      goto cleanup;
    }
    egress_attached = true;
  }

  err = bpf_link__pin(skel->links.xdp_firewall, LINK_PATH);
  if (err) {
    fprintf(stderr, "Failed to pin link: %s\n", strerror(-err));
    goto cleanup;
  }

  /* Pinning all maps together; on failure unlink_all_pins() cleans up. */
  if (pin_map(skel->maps.config_map, CONFIG_MAP_PATH) ||
      pin_map(skel->maps.manual_blacklist_map, MANUAL_BLOCK_MAP_PATH) ||
      pin_map(skel->maps.manual_blacklist6_map, MANUAL_BLOCK_MAP6_PATH) ||
      pin_map(skel->maps.ct_map, CT_MAP_PATH) ||
      pin_map(skel->maps.ct6_map, CT6_MAP_PATH))
    goto cleanup_pins;

  fprintf(stdout, "Successfully attach the program\n");
  return;

cleanup_pins:
  unlink_all_pins();

cleanup:
  if (ingress_attached) {
    ingress_opts.prog_fd = 0;
    ingress_opts.prog_id = 0;
    bpf_tc_detach(&ingress_hook, &ingress_opts);
  }
  if (egress_attached) {
    egress_opts.prog_fd = 0;
    egress_opts.prog_id = 0;
    bpf_tc_detach(&egress_hook, &egress_opts);
  }
  bpf_tc_hook_destroy(&ingress_hook);

  firewall_bpf__destroy(skel);
  exit(1);
}
