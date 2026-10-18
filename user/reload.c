/*
 * reload.c - hot-reload runtime config and toggle TC tracking.
 */
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "firewall.h"

#include "../include/common.h"
#include "../bpf/firewall.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Read old config, toggle TC if requested, then write new config. */
void reload_config(FirewallConfig config) {
  struct firewall_bpf *skel = NULL;
  struct bpf_tc_hook ingress_hook = {0};
  struct bpf_tc_hook egress_hook = {0};
  struct bpf_tc_opts ingress_opts = {0};
  struct bpf_tc_opts egress_opts = {0};
  int map_fd = -1, ifindex = 0, err = 0;
  __u32 key = 0;
  FirewallConfig old_config = {0};

  map_fd = bpf_obj_get(CONFIG_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            CONFIG_MAP_PATH, strerror(errno));
    exit(1);
  }

  if (bpf_map_lookup_elem(map_fd, &key, &old_config) < 0) {
    fprintf(stderr, "Error: Failed to read current config: %s\n",
            strerror(errno));
    close(map_fd);
    exit(1);
  }

  ifindex = if_nametoindex(config.device);
  if (ifindex == 0) {
    fprintf(stderr, "Error getting ifindex for %s\n", config.device);
    close(map_fd);
    exit(1);
  }

  bool was_tc_enabled = old_config.enable_tc != 0;
  bool want_tc_enabled = config.enable_tc != 0;

  if (was_tc_enabled && !want_tc_enabled) {
    ingress_hook.sz = sizeof(ingress_hook);
    ingress_hook.ifindex = ifindex;
    ingress_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
    bpf_tc_hook_destroy(&ingress_hook);
    printf("Disabled TC hooks\n");

  } else if (!was_tc_enabled && want_tc_enabled) {
    skel = firewall_bpf__open_and_load();
    if (!skel) {
      fprintf(stderr, "Unable to load ebpf skeleton for TC attach\n");
      close(map_fd);
      exit(1);
    }

    ingress_hook.sz = sizeof(ingress_hook);
    ingress_hook.ifindex = ifindex;
    ingress_hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_hook_create(&ingress_hook);
    if (err && err != -EEXIST) {
      fprintf(stderr, "Failed to create TC clsact hook: %s\n", strerror(-err));
      firewall_bpf__destroy(skel);
      close(map_fd);
      exit(1);
    }

    ingress_opts.sz = sizeof(ingress_opts);
    ingress_opts.prog_fd = bpf_program__fd(skel->progs.handle_ingress);
    err = bpf_tc_attach(&ingress_hook, &ingress_opts);
    if (err) {
      fprintf(stderr, "Failed to attach TC ingress filter: %s\n",
              strerror(-err));
      firewall_bpf__destroy(skel);
      close(map_fd);
      exit(1);
    }

    egress_hook.sz = sizeof(egress_hook);
    egress_hook.ifindex = ifindex;
    egress_hook.attach_point = BPF_TC_EGRESS;

    egress_opts.sz = sizeof(egress_opts);
    egress_opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    err = bpf_tc_attach(&egress_hook, &egress_opts);
    if (err) {
      fprintf(stderr, "Failed to attach TC egress filter: %s\n",
              strerror(-err));
      ingress_opts.prog_fd = 0;
      ingress_opts.prog_id = 0;
      bpf_tc_detach(&ingress_hook, &ingress_opts);
      firewall_bpf__destroy(skel);
      close(map_fd);
      exit(1);
    }

    printf("Enabled TC hooks\n");
    firewall_bpf__destroy(skel);
  }
  if (bpf_map_update_elem(map_fd, &key, &config, BPF_ANY) < 0) {
    fprintf(stderr, "Error: Failed to update map element: %s\n",
            strerror(errno));
    close(map_fd);
    exit(1);
  }

  close(map_fd);
  printf("Updated Config!\n");
}
