#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "firewall.h"

#include "../include/common.h"
#include "../src/firewall.skel.h"
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


static void ensure_pin_dir_exists(const char *dir) {
  struct stat st = {0};
  if (stat(dir, &st) == -1) {
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
      fprintf(stderr, "Failed to create pin directory %s: %s\n", dir,
              strerror(errno));
    }
  }
}

static void unlink_all_pins(void) {
  unlink(LINK_PATH);
  unlink(CONFIG_MAP_PATH);
  unlink(MANUAL_BLOCK_MAP_PATH);
  unlink(MANUAL_BLOCK_MAP6_PATH);
  unlink(CT_MAP_PATH);
  unlink(CT6_MAP_PATH);
}

static int pin_map(struct bpf_map *map, const char *path) {
  int err = bpf_map__pin(map, path);
  if (err)
    fprintf(stderr, "Failed to pin map %s: %s\n", path, strerror(-err));
  return err;
}

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

  /* On any failure cleanup_pins removes every pin, so no per-map unpinning. */
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

/* ------------------------- blacklist handling ------------------------- */

static int set_rule(const struct ip_net *net, __u32 val, const char *verb) {
  const char *path =
      net->family == AF_INET6 ? MANUAL_BLOCK_MAP6_PATH : MANUAL_BLOCK_MAP_PATH;

  int map_fd = bpf_obj_get(path);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n", path,
            strerror(errno));
    return -1;
  }

  int ret;
  if (net->family == AF_INET6) {
    struct ipv6_lpm_key key = {.prefixlen = net->prefixlen};
    memcpy(key.addr, &net->addr.v6, sizeof(key.addr));
    ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
  } else {
    struct ipv4_lpm_key key = {.prefixlen = net->prefixlen, .ip = net->addr.v4};
    ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
  }

  if (ret < 0)
    fprintf(stderr, "Failed to %s IP/subnet: %s\n", verb, strerror(errno));
  else
    printf("Successfully %sed rule (val: %u).\n", verb, val);

  close(map_fd);
  return ret;
}

void block_ip(const struct ip_net *net) { set_rule(net, 1, "block"); }

void unblock_ip(const struct ip_net *net) { set_rule(net, 0, "unblock"); }

static size_t print_family(const char *path, int family) {
  int map_fd = bpf_obj_get(path);
  if (map_fd < 0) {
    fprintf(stderr, "Error: Failed to fetch pinned map from %s: %s\n", path,
            strerror(errno));
    return 0;
  }

  size_t count = 0;
  /* Large enough for either key type. */
  union {
    struct ipv4_lpm_key v4;
    struct ipv6_lpm_key v6;
  } key, next;

  int res = bpf_map_get_next_key(map_fd, NULL, &next);
  while (res == 0) {
    __u32 val = 0;
    char ip_str[INET6_ADDRSTRLEN];
    bpf_map_lookup_elem(map_fd, &next, &val);

    const char *s = NULL;
    __u32 prefixlen;
    if (family == AF_INET6) {
      s = inet_ntop(AF_INET6, next.v6.addr, ip_str, sizeof(ip_str));
      prefixlen = next.v6.prefixlen;
    } else {
      struct in_addr addr = {.s_addr = next.v4.ip};
      s = inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
      prefixlen = next.v4.prefixlen;
    }

    if (s) {
      printf(" - %s/%u [%s]\n", ip_str, prefixlen,
             val == 1 ? "BLOCKED" : "ALLOWED");
      count++;
    }

    key = next;
    res = bpf_map_get_next_key(map_fd, &key, &next);
  }

  close(map_fd);
  return count;
}

void print_blocked_ips(void) {
  printf("Configured IP Rules:\n");
  size_t n = print_family(MANUAL_BLOCK_MAP_PATH, AF_INET);
  n += print_family(MANUAL_BLOCK_MAP6_PATH, AF_INET6);
  if (n == 0)
    printf("No rules found or failed to read maps.\n");
}