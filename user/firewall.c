#include <arpa/inet.h>
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

void block_ip(__u32 ip, __u32 prefixlen) {
  int map_fd = bpf_obj_get(MANUAL_BLOCK_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            MANUAL_BLOCK_MAP_PATH, strerror(errno));
    exit(1);
  }
  struct ipv4_lpm_key key = {.prefixlen = prefixlen, .ip = ip};
  __u32 set_val = 1;

  if (bpf_map_update_elem(map_fd, &key, &set_val, BPF_ANY) < 0) {
    fprintf(stderr, "Failed to block IP/subnet: %s\n", strerror(errno));
  } else {
    printf("Successfully blocked rule (val: 1).\n");
  }

  close(map_fd);
}

void unblock_ip(__u32 ip, __u32 prefixlen) {
  int map_fd = bpf_obj_get(MANUAL_BLOCK_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            MANUAL_BLOCK_MAP_PATH, strerror(errno));
    exit(1);
  }
  struct ipv4_lpm_key key = {.prefixlen = prefixlen, .ip = ip};
  __u32 set_val = 0;

  if (bpf_map_update_elem(map_fd, &key, &set_val, BPF_ANY) < 0) {
    fprintf(stderr, "Failed to unblock IP/subnet: %s\n", strerror(errno));
  } else {
    printf("Successfully unblocked rule (val: 0).\n");
  }

  close(map_fd);
}

struct lpm_entry {
  struct ipv4_lpm_key key;
  __u32 val;
};

struct lpm_entry *get_blocked_ips(size_t *count) {
  *count = 0;

  int map_fd = bpf_obj_get(MANUAL_BLOCK_MAP_PATH);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n",
            MANUAL_BLOCK_MAP_PATH, strerror(errno));
    return NULL;
  }

  size_t capacity = 16;
  struct lpm_entry *entries = malloc(capacity * sizeof(struct lpm_entry));
  if (!entries) {
    close(map_fd);
    return NULL;
  }

  struct ipv4_lpm_key key, next_key;

  int res = bpf_map_get_next_key(map_fd, NULL, &next_key);

  while (res == 0) {
    if (*count >= capacity) {
      capacity *= 2;
      struct lpm_entry *tmp =
          realloc(entries, capacity * sizeof(struct lpm_entry));
      if (!tmp) {
        free(entries);
        close(map_fd);
        *count = 0;
        return NULL;
      }
      entries = tmp;
    }

    // Lookup the corresponding action value for the key
    __u32 val = 0;
    bpf_map_lookup_elem(map_fd, &next_key, &val);

    entries[*count].key = next_key;
    entries[*count].val = val;
    (*count)++;

    key = next_key;
    res = bpf_map_get_next_key(map_fd, &key, &next_key);
  }

  close(map_fd);

  if (*count == 0) {
    free(entries);
    return NULL;
  }

  return entries;
}

void print_blocked_ips() {
  size_t num_entries = 0;
  struct lpm_entry *entries = get_blocked_ips(&num_entries);

  if (entries) {
    printf("Configured IP Rules (%zu):\n", num_entries);
    for (size_t i = 0; i < num_entries; i++) {
      char ip_str[INET_ADDRSTRLEN];
      struct in_addr addr = {.s_addr = entries[i].key.ip};

      if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str))) {
        printf(" - %s/%u [%s]\n", ip_str, entries[i].key.prefixlen,
               entries[i].val == 1 ? "BLOCKED" : "ALLOWED");
      }
    }
    free(entries);
  } else {
    printf("No rules found or failed to read map.\n");
  }
}