#include "../src/firewall.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

volatile sig_atomic_t exit_now = 0;

void handle_exit(int sig_num) { exit_now = 1; }

int main() {
  struct firewall_bpf *skel;
  int err = 0, ifindex;

  signal(SIGINT, handle_exit);

  ifindex = if_nametoindex("eth0");
  if (ifindex == 0) {
    fprintf(stderr, "Error getting ifindex");
    return 1;
  }

  skel = firewall_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Unable to load ebpf skeleton\n");
    goto cleanup;
  }

  skel->links.xdp_firewall =
      bpf_program__attach_xdp(skel->progs.xdp_firewall, ifindex);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  while (!exit_now) {
    sleep(1);
  }

cleanup:
  firewall_bpf__destroy(skel);
  return err;
}
