#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "firewall.h"

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

  err = bpf_map__pin(skel->maps.config_map, CONFIG_MAP_PATH);
  if (err) {
    fprintf(stderr, "Failed to pin map: %d\n", err);
    bpf_link__unpin(skel->links.xdp_firewall);
    goto cleanup;
  }

  err = bpf_map__pin(skel->maps.manual_blacklist_map, MANUAL_BLOCK_MAP_PATH);
  if (err) {
    fprintf(stderr, "Failed to pin map: %d\n", err);
    bpf_link__unpin(skel->links.xdp_firewall);
    bpf_map__unpin(skel->maps.config_map, CONFIG_MAP_PATH);
    goto cleanup;
  }

cleanup:
  firewall_bpf__destroy(skel);
  exit(err);
}

void reload_config(FirewallConfig config) {
  int map_fd = bpf_obj_get(CONFIG_MAP_PATH);

  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            CONFIG_MAP_PATH, strerror(errno));
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

void block_ip(__u32 ip) {
  int map_fd = bpf_obj_get(MANUAL_BLOCK_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            MANUAL_BLOCK_MAP_PATH, strerror(errno));
    exit(1);
  }

  __u32 set_val = 0;

  if (bpf_map_update_elem(map_fd, &ip, &set_val, BPF_NOEXIST) < 0) {
    fprintf(stderr, "Failed to block IP: %s\n", strerror(errno));
  }

  close(map_fd);
}

void unblock_ip(__u32 ip) {
  int map_fd = bpf_obj_get(MANUAL_BLOCK_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            MANUAL_BLOCK_MAP_PATH, strerror(errno));
    exit(1);
  }

  if (bpf_map_delete_elem(map_fd, &ip) < 0) {
    fprintf(stderr, "Failed to Unblock IP: %s\n", strerror(errno));
  }

  close(map_fd);
}

__u32 *get_blocked_ips(size_t *count) {
  *count = 0;

  int map_fd = bpf_obj_get(MANUAL_BLOCK_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            MANUAL_BLOCK_MAP_PATH, strerror(errno));
    return NULL;
  }

  size_t capacity = 16;
  __u32 *ips = malloc(capacity * sizeof(__u32));
  if (!ips) {
    close(map_fd);
    return NULL;
  }

  __u32 key, next_key;

  int res = bpf_map_get_next_key(map_fd, NULL, &next_key);

  while (res == 0) {
    // Expand array if full
    if (*count >= capacity) {
      capacity *= 2;
      __u32 *tmp = realloc(ips, capacity * sizeof(__u32));
      if (!tmp) {
        free(ips);
        close(map_fd);
        *count = 0;
        return NULL;
      }
      ips = tmp;
    }

    ips[*count] = next_key;
    (*count)++;

    key = next_key;
    res = bpf_map_get_next_key(map_fd, &key, &next_key);
  }

  close(map_fd);

  if (*count == 0) {
    free(ips);
    return NULL;
  }

  return ips;
}

void print_blocked_ips() {
  size_t num_ips = 0;
  __u32 *blocked_ips = get_blocked_ips(&num_ips);

  if (blocked_ips) {
    printf("Currently blocked IPs (%zu):\n", num_ips);
    for (size_t i = 0; i < num_ips; i++) {
      // Assuming IPv4 address stored in network byte order
      unsigned char *bytes = (unsigned char *)&blocked_ips[i];
      printf(" - %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
    }
    free(blocked_ips);
  } else {
    printf("No blocked IPs found or failed to read map.\n");
  }
}