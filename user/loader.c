#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "loader.h"

#include "../include/common.h"
#include "../src/firewall.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

volatile sig_atomic_t exit_now = 0;

void handle_exit(int sig_num) { exit_now = 1; }

void load_and_attach_firewall(FirewallConfig config) {
  struct firewall_bpf *skel;
  int err = 0, ifindex;

  signal(SIGINT, handle_exit);

  mkdir(PIN_DIR, 0777);

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

  __u32 key = 0;
  bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key), &config,
                       sizeof(config), BPF_ANY);

  skel->links.xdp_firewall =
      bpf_program__attach_xdp(skel->progs.xdp_firewall, ifindex);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  err = bpf_link__pin(skel->links.xdp_firewall, LINK_PATH);
  if (err) {
    fprintf(stderr, "Failed to pin link: %d\n", err);
    goto cleanup;
  }

  err = bpf_map__pin(skel->maps.config_map, MAP_PATH);
  if (err) {
    fprintf(stderr, "Failed to pin map: %d\n", err);
    bpf_link__unpin(skel->links.xdp_firewall);
    goto cleanup;
  }

cleanup:
  firewall_bpf__destroy(skel);
  exit(err);
}

void reload_config(FirewallConfig config) {
  int map_fd = bpf_obj_get(MAP_PATH);

  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n", MAP_PATH,
            strerror(errno));
    exit(1);
  }
  __u32 key = 0;
  int res = bpf_map_update_elem(map_fd, &key, &config, BPF_ANY);

  if (res < 0) {
    fprintf(stderr, "Error: Failed to update map element: %s\n",
            strerror(errno));
    close(map_fd);
    exit(1);
  }

  printf("Updated Config!\n");

  close(map_fd);
}