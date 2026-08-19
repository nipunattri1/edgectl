# eBPF XDP & TC Firewall

High-performance, kernel-space Linux firewall leveraging **eBPF (Extended Berkeley Packet Filter)**, **XDP (eXpress Data Path)**, and **TC (Traffic Control)**.

This project filters packets at the driver/kernel boundary before SKB allocation for maximum efficiency, protecting systems against DDoS attacks, blocking specific CIDR subnets, and managing stateful connection tracking.

---

## Key Features

* **XDP Packet Filtering:** Ultra-fast drop logic executed directly at the network driver layer.
* **LPM Subnet Blacklisting:** Dynamic IP/CIDR prefix blacklisting using Longest Prefix Match (`BPF_MAP_TYPE_LPM_TRIE`).
* **DDoS Mitigation:** Rate-limiting for TCP SYN and UDP flood attacks using atomic counter tracking.
* **Stateful Connection Tracking:** Ingress/Egress packet matching via TC programs for dynamic session monitoring and automatic UDP session timeouts.
* **Hot Configuration Reloading:** Dynamic configuration parsing via INI files without restarting or detaching kernel components.

---

## Project Structure

```
.
├── config/
│   └── config.ini         # Firewall operational parameters & thresholds
├── include/
│   ├── common.h           # Shared structures (FirewallConfig, LPM keys, CT state)
│   ├── ini.h              # INI parser library header
│   └── vmlinux.h          # BPF kernel type definitions
├── src/
│   ├── main.c             # Userspace CLI manager
│   ├── config.h           # INI file parsing logic and handlers
│   ├── firewall.bpf.c     # eBPF kernel space programs (XDP, TC Ingress/Egress)
│   ├── firewall.h         # Userspace helper declarations
│   └── maps.bpf.h         # BPF map definitions (LPM trie, Hash maps, Arrays)
└── README.md

```

---

## Configuration (`config/config.ini`)

Configure interface attachment, protocol blocks, DDoS rate limits, and connection tracking parameters:

```ini
[interface]
device = eth0

[rules]
# Comma-separated list: tcp, udp, icmp
block_proto = icmp

[ddos]
# Maximum allowed packets per second per source IP
syn_rate_limit = 100
udp_rate_limit = 1000

[conn_track]
enable = true
# UDP connection timeout in nanoseconds (default: 30s)
udp_timeout_ns = 30000000000

```

---

## Building the Project

### Prerequisites

* **Linux Kernel:** 5.4 or higher with eBPF and XDP support enabled.
* **Compiler:** `clang` and `llvm` (v11+ recommended).
* **Dependencies:** `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `iproute2`.

### Build Commands

```bash
# Compile eBPF byte-code and userspace binary
make all

# Clean build artifacts
make clean

```

---

## Usage & CLI Commands

> **Note:** Managing eBPF programs and network hooks requires **root (`sudo`) privileges**.

### 1. Management Commands

* **Attach the Firewall:** Loads BPF maps, attaches XDP to the interface, and registers TC filters.
```bash
sudo ./firewall attach

```


* **Reload Configuration:** Updates running parameters (rate limits, blocked protocols) on-the-fly.
```bash
sudo build/cli reload

```


* **Detach the Firewall:** Removes XDP/TC hooks and unloads BPF maps from the kernel.
```bash
sudo build/cli detach

```



---

### 2. Manual IP/Subnet Blacklisting

The firewall uses an LPM Trie map, allowing you to block single host IPs (`/32`) or entire network subnets (`/0`–`/32`).

* **Block an IP / Subnet:**
```bash
sudo build/cli block 192.168.1.50/32
sudo build/cli block 10.0.0.0/16

```


* **Unblock an IP / Subnet:**
```bash
sudo build/cli unblock 192.168.1.50/32
sudo build/cli unblock 10.0.0.0/16
```


* **List Currently Blocked Networks:**
```bash
sudo build/cli list
```



---

## Architecture Overview

1. **XDP Hook (`SEC("xdp")`):**
* Inspects incoming Ethernet, IPv4, TCP, and UDP headers.
* Checks `block_mask` to drop specified protocols immediately.
* Performs an LPM lookup in `manual_blacklist_map` to drop blacklisted IPs.
* Tracks and drops source IPs exceeding `syn_rate_limit` or `udp_rate_limit`.


2. **TC Egress Hook (`SEC("tc/egress")`):**
* Intercepts outgoing stateful TCP/UDP packets.
* Populates the connection tracking map (`ct_map`) with tuple metadata (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`).


3. **TC Ingress Hook (`SEC("tc/ingress")`):**
* Matches incoming packets against existing sessions in `ct_map`.
* Enforces `udp_timeout_ns` session expiration logic.
* Drops non-tracked stateful ingress traffic (`TC_ACT_SHOT`).