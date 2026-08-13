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

void load_and_attach_firewall(FirewallConfig config) {
  struct firewall_bpf *skel;
  int err = 0, ifindex;
  bool ingress_attached = false;
  bool egress_attached = false;

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

  err = bpf_map__pin(skel->maps.ct_map, CT_MAP_PATH);
  if (err) {
    fprintf(stderr, "Failed to pin ct_map: %s\n", strerror(-err));
    bpf_link__unpin(skel->links.xdp_firewall);
    bpf_map__unpin(skel->maps.config_map, CONFIG_MAP_PATH);
    bpf_map__unpin(skel->maps.manual_blacklist_map, MANUAL_BLOCK_MAP_PATH);
    goto cleanup;
  }

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

  // Unpin Maps/Links
  unlink(LINK_PATH);
  unlink(CONFIG_MAP_PATH);
  unlink(MANUAL_BLOCK_MAP_PATH);
  unlink(CT_MAP_PATH);

  firewall_bpf__destroy(skel);
  exit(err ? 1 : 0);
}

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

  struct bpf_tc_hook ingress_hook = {
      .sz = sizeof(struct bpf_tc_hook),
      .ifindex = ifindex,
      .attach_point = BPF_TC_INGRESS,
  };
  struct bpf_tc_opts ingress_opts = {
      .sz = sizeof(struct bpf_tc_opts),
      .flags = BPF_TC_F_REPLACE,
  };

  bpf_tc_detach(&ingress_hook, &ingress_opts);
  bpf_tc_hook_destroy(&ingress_hook);
  printf("Cleaned up TC Ingress hook\n");

  struct bpf_tc_hook egress_hook = {
      .sz = sizeof(struct bpf_tc_hook),
      .ifindex = ifindex,
      .attach_point = BPF_TC_EGRESS,
  };
  struct bpf_tc_opts egress_opts = {
      .sz = sizeof(struct bpf_tc_opts),
      .flags = BPF_TC_F_REPLACE,
  };

  bpf_tc_detach(&egress_hook, &egress_opts);
  bpf_tc_hook_destroy(&egress_hook);
  printf("Cleaned up TC Egress hook\n");

  printf("Unpinning BPF objects from %s...\n", PIN_DIR);
  unlink(LINK_PATH);
  unlink(CONFIG_MAP_PATH);
  unlink(MANUAL_BLOCK_MAP_PATH);
  unlink(CT_MAP_PATH);

  rmdir(PIN_DIR);

  printf("Firewall unloaded.\n");
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