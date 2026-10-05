# eBPF XDP & TC Firewall

High-performance, kernel-space Linux firewall leveraging **eBPF (Extended Berkeley Packet Filter)**, **XDP (eXpress Data Path)**, and **TC (Traffic Control)**, with full **IPv4 and IPv6** support.

This project filters packets at the driver/kernel boundary before SKB allocation for maximum efficiency, protecting systems against DDoS attacks, blocking specific CIDR subnets, and managing stateful connection tracking.

---

## Key Features

* **Dual-Stack (IPv4 + IPv6):** Both address families are parsed, filtered, rate-limited and tracked, including IPv6 extension headers and fragments.
* **XDP Packet Filtering:** Ultra-fast drop logic executed directly at the network driver layer.
* **LPM Subnet Blacklisting:** Dynamic IPv4 and IPv6 prefix blacklisting using Longest Prefix Match (`BPF_MAP_TYPE_LPM_TRIE`).
* **DDoS Mitigation:** Rate-limiting for TCP SYN and UDP flood attacks using atomic counter tracking. IPv4 is tracked per source address, IPv6 per source `/64`.
* **Stateful Connection Tracking:** Ingress/Egress packet matching via TC programs for dynamic session monitoring and automatic UDP session timeouts.
* **Hot Configuration Reloading:** Dynamic configuration parsing via INI files without restarting or detaching kernel components.

---

## Project Structure

```
.
├── config/
│   └── config.ini         # Firewall operational parameters & thresholds
├── include/
│   ├── common.h           # Shared structures (FirewallConfig, IPv4 LPM key, pin paths)
│   ├── ini.h              # INI parser library header
│   └── vmlinux.h          # BPF kernel type definitions
├── src/
│   ├── main.c             # Userspace CLI manager (command dispatch, IPv4/IPv6 CIDR parsing)
│   ├── config.h           # INI file parsing logic and handlers
│   ├── firewall.c         # Userspace loader: attach / detach / reload / rule management
│   ├── firewall.h         # Userspace API declarations, struct ip_net, ipv6_lpm_key
│   ├── firewall.bpf.c     # eBPF kernel programs (XDP, TC Ingress/Egress)
│   ├── utils.bpf.h        # Header parsing (IPv4/IPv6), ACL lookup, flood checks
│   └── maps.bpf.h         # BPF map definitions (LPM tries, LRU hashes, arrays)
└── README.md
```

> **Keep in sync:** `struct ipv6_lpm_key` is defined in both `src/maps.bpf.h` (kernel) and `src/firewall.h` (userspace). The two definitions must stay identical.

---

## Configuration (`config/config.ini`)

Configure interface attachment, protocol blocks, DDoS rate limits, and connection tracking parameters:

```ini
[interface]
device = eth0

[rules]
# Comma-separated list: tcp, udp, icmp, icmpv6
block_proto = icmp
# allow | deny  (policy for packets that cannot be parsed)
default = allow

[ddos]
# Maximum allowed packets per second per source
# (per IPv4 address, or per IPv6 /64 prefix)
syn_rate_limit = 100
udp_rate_limit = 1000

[conn_track]
enable = true
# UDP connection timeout in nanoseconds (default: 30s)
udp_timeout_ns = 30000000000

```

> **Warning:** blocking `icmpv6` breaks IPv6 neighbor discovery and router advertisements, which will typically cut off IPv6 connectivity on the interface.

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
sudo build/cli attach

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

The firewall uses LPM Trie maps (one per address family), allowing you to block single hosts or entire network subnets. The address family is detected automatically from the argument. If no prefix is given, `/32` (IPv4) or `/128` (IPv6) is assumed.

| Family | Valid prefix range |
|--------|--------------------|
| IPv4   | `/0` – `/32`       |
| IPv6   | `/0` – `/128`      |

* **Block an IP / Subnet:**
```bash
sudo build/cli block 192.168.1.50/32
sudo build/cli block 10.0.0.0/16
sudo build/cli block 2001:db8::1/128
sudo build/cli block 2001:db8:abcd::/48

```


* **Unblock an IP / Subnet:**
```bash
sudo build/cli unblock 192.168.1.50/32
sudo build/cli unblock 10.0.0.0/16
sudo build/cli unblock 2001:db8:abcd::/48
```


* **List Currently Blocked Networks (IPv4 and IPv6):**
```bash
sudo build/cli list
```



---

## Architecture Overview

1. **XDP Hook (`SEC("xdp")`):**
* Inspects Ethernet, IPv4/IPv6, TCP, and UDP headers. For IPv6 it walks the extension header chain (hop-by-hop, routing, destination options, fragment, AH; up to 8 headers) to find the real upper-layer protocol.
* Non-first IPv4 and IPv6 fragments are treated as having no L4 header.
* Checks `block_mask` against the upper-layer protocol to drop specified protocols immediately.
* Performs an LPM lookup in `manual_blacklist_map` (IPv4) or `manual_blacklist6_map` (IPv6) to drop blacklisted sources.
* Tracks and drops sources exceeding `syn_rate_limit` or `udp_rate_limit` (per IPv4 address, or per IPv6 `/64`).
* Packets that cannot be parsed (malformed, unsupported EtherType such as ARP or VLAN-tagged frames, or more than 8 IPv6 extension headers) follow the `default` policy.


2. **TC Egress Hook (`SEC("tc/egress")`):**
* Intercepts outgoing stateful TCP/UDP packets.
* Populates the connection tracking map (`ct_map` for IPv4, `ct6_map` for IPv6) with tuple metadata (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`).


3. **TC Ingress Hook (`SEC("tc/ingress")`):**
* Matches incoming packets against existing sessions in `ct_map` / `ct6_map`.
* Enforces `udp_timeout_ns` session expiration logic.
* Drops non-tracked stateful ingress TCP/UDP traffic (`TC_ACT_SHOT`).
* Non-TCP/UDP traffic (including ICMPv6, which IPv6 needs for neighbor discovery and path MTU discovery) is not subject to connection tracking and passes.

### BPF Maps

| Map | Type | Key | Purpose |
|-----|------|-----|---------|
| `config_map` | ARRAY | `u32` | Runtime configuration |
| `manual_blacklist_map` | LPM_TRIE | `ipv4_lpm_key` | IPv4 blocklist |
| `manual_blacklist6_map` | LPM_TRIE | `ipv6_lpm_key` | IPv6 blocklist |
| `syn_flood_map` / `udp_flood_map` | LRU_HASH | IPv4 address | IPv4 rate limiting |
| `syn6_flood_map` / `udp6_flood_map` | LRU_HASH | IPv6 `/64` prefix | IPv6 rate limiting |
| `ct_map` | LRU_HASH | `connection_key` | IPv4 connection tracking |
| `ct6_map` | LRU_HASH | `connection_key6` | IPv6 connection tracking |

All maps are pinned under `PIN_DIR` so the CLI can manage rules while the firewall is running.


## pending stuff (extra, not in task)
**1. Dynamic Rule Management & Policy Engine**

* **Port-Based Rules:** Expand XDP filtering to block or allow specific destination ports or port ranges alongside protocol checks.
* **Geofencing / Country Blocking:** Integrate MaxMind GeoIP maps directly into eBPF to drop traffic originating from specific ASN or country codes.
* **Dynamic Whitelisting:** Implement a priority-based rule set where whitelisted IPs bypass all rate limits and packet drops.

**2. Advanced Security & Anomaly Detection**

* **TCP SYN Cookies:** Implement stateless SYN cookie generation inside XDP to handle massive SYN floods without exhausting map memory.
* **Deep Packet Inspection (DPI):** Parse HTTP headers or DNS queries in XDP/TC to block known malicious user-agents or DNS amplification vectors.
* **Connection State Machine Expansion:** Track full TCP state transitions (`SYN`, `SYN-ACK`, `ESTABLISHED`, `FIN`, `RST`) rather than binary timestamp tracking.
* **ICMPv6 Filtering:** Allow-list essential ICMPv6 types (neighbor discovery, packet-too-big) while filtering the rest, instead of an all-or-nothing `icmpv6` block.
* **VLAN / ARP Handling:** Parse 802.1Q tags and pass or track ARP explicitly rather than relying on the `default` policy.

**3. Observability & Monitoring**

* **Prometheus Metrics Exporter:** Expose kernel counters via an HTTP `/metrics` endpoint for real-time monitoring of drop reasons, throughput, and active connections.
* **Grafana Dashboard:** Build a pre-configured Grafana dashboard visualizing live network traffic, drop rates per vector, and top offender IPs.
* **eBPF Ring Buffer Event Logging:** Replace standard `bpf_printk` debug calls with high-performance `BPF_MAP_TYPE_RINGBUF` to send blocked packet metadata to user space in real time.

**4. Architecture & Production Readiness**

* **CO-RE (Compile Once – Run Everywhere):** Migrate to BPF CO-RE using `libbpf` and `bpftool` so the binary runs across different kernel versions without needing kernel headers locally.
* **ebpf/xdp Native & Offload Support:** Add CLI options to force `XDP_FLAGS_SKB_MODE` (generic), `XDP_FLAGS_DRV_MODE` (native driver), or hardware offload onto supported NICs.
* **REST API / gRPC Controller:** Build a daemon allowing external microservices or orchestration tools to update firewall rules programmatically.
* **Project Restructure:** Split kernel (`bpf/`) and userspace (`src/`) code, move shared types and pin paths into a single `include/shared/` header, and add `BPF_PROG_TEST_RUN` tests for the parsers.