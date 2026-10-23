# Edgewall (edgectl)

Edgewall is a high-performance eBPF-driven network firewall and connection tracking engine for Linux systems. Designed to operate directly within the kernel network path via XDP (eXpress Data Path) and Traffic Control (TC) hooks, Edgewall provides low-latency packet filtering, stateful connection tracking, dynamically configurable IP/subnet blocking, and automated volumetric flood protection.

---

## Features

- **XDP Packet Filtering**: Drops unauthorized network traffic early at the network interface layer to maximize packet processing throughput and minimize CPU overhead.
- **TC Stateful Inspection**: Implements stateful connection tracking at the Traffic Control ingress and egress layers for TCP and UDP flows.
- **LPM Tries for IP/Subnet Blocking**: Efficient Longest Prefix Match (LPM) trie lookups supporting both IPv4 and IPv6 CIDR blocklists.
- **DoS/DDoS Protection**: Kernel-side rate checks to detect and drop TCP SYN flood and UDP flood attacks in real time.
- **Dynamic Policy Reloads**: Update firewall policies and dynamic configuration on the fly without interrupting active kernel attachments or dropping packets.
- **CLI Management**: Complete Go-based command line utility (`edgectl`) to manage pinned maps, rule sets, state inspections, and BPF link lifecycles.

---

## Architecture Overview

Edgewall is split into a kernel-space eBPF processing pipeline and a user-space control subsystem:

1. **Kernel Space (`bpf/`)**
   - `xdp_firewall`: Early packet filtering, protocol mask checks, LPM trie lookup for blocked subnets, and flood detection.
   - `handle_egress`: Inspects outbound traffic to populate stateful connection tracking maps (`ct_map` and `ct6_map`).
   - `handle_ingress`: Validates incoming packets against existing stateful connection records, automatically refreshing active flows or dropping untracked inbound attempts.

2. **User Space (`cmd/`, `internal/`, `user/`)**
   - **Go Control Subsystem (`cmd/`, `internal/`)**: Built on `cilium/ebpf` to handle BPF skeleton generation, map pinning, configuration parsing, and CLI interactions.
   - **C Control Binary (`user/`)**: Alternative lightweight C-based utility for managing map states and skeleton lifecycles using `libbpf`.

---

## Prerequisites

- **OS**: Linux kernel version 5.8 or higher (supports BPF ring buffers, LPM tries, and pinned links).
- **Toolchain Requirements**:
  - `clang` and `llvm` (version 12+)
  - `libbpf-dev` / `libbpf` headers
  - `go` (version 1.20+)
  - `make` or `just`
  - `bpftool` (optional, for header generation)

---

## Installation and Building

Clone the repository and build the project artifacts:

```bash
git clone https://github.com/your-org/edgewall.git
cd edgewall
```

### Build using Make

```bash
# Build eBPF programs and Go CLI binary
make build

# Install binary to system path
sudo make install
```

### Build using Just

```bash
just build
```

The generated CLI executable will be placed in `build/edgewall` or installed to `/usr/local/bin/edgectl`.

---

## Usage Guide

`edgectl` requires root privileges (or `CAP_BPF` and `CAP_NET_ADMIN`) to attach programs and manipulate kernel maps.

### Command Structure

```text
eBPF firewall control

Usage:
  edgectl [command]

Available Commands:
  attach      Load and attach the firewall
  block       Block an IP or subnet
  detach      Detach firewall and cleanup
  help        Help about any command
  list        List blocked IPs/subnets
  reload      Reload configuration from config file
  unblock     Unblock an IP or subnet

Flags:
      --config string       config file (default: /etc/edgectl/edgectl.yaml)
  -h, --help                help for edgectl
      --log-level string    debug | info | warn | error (default "info")
      --pin-dir string      bpffs directory for pinned links and maps (default "/sys/fs/bpf/edgectl")
  -v, --version             version for edgectl
```

### Common Workflows

1. **Attach the Firewall**

   Attach XDP and TC programs to a specific network interface:

   ```bash
   sudo edgectl attach --config config/config.yaml
   ```

2. **Block an IP Address or Subnet**

   Dynamically insert IPv4/IPv6 addresses or CIDRs into the LPM trie map:

   ```bash
   sudo edgectl block 192.168.1.50
   sudo edgectl block 10.0.0.0/8
   sudo edgectl block 2001:db8::/32
   ```

3. **List Active Block Rules**

   ```bash
   sudo edgectl list
   ```

4. **Unblock an IP Address or Subnet**

   ```bash
   sudo edgectl unblock 192.168.1.50
   ```

5. **Reload Runtime Configuration**

   Update settings in `/etc/edgectl/edgectl.yaml` and reload parameters directly into BPF maps:

   ```bash
   sudo edgectl reload
   ```

6. **Detach and Cleanup**

   Remove BPF programs from interfaces and unpin maps:

   ```bash
   sudo edgectl detach
   ```

---

## Configuration

Configuration files use standard YAML syntax. A default configuration template is available in `config/config.yaml`:

```yaml
# edgectl configuration
# Copy to /etc/edgectl/edgectl.yaml or use --config flag

interface:
  device: "enp7s0"        # Network interface to protect (required for attach)
  mode: "generic"    # XDP mode: auto | generic | driver | native | offload

rules:
  block_proto: []   # Protocols to block: icmp, igmp, tcp, udp, gre, esp, ah, icmpv6
  default: "allow" # allow | disallow - default action for unparseable packets

ddos:
  enable: false
  syn_rate_limit: 100    # Max SYN packets/sec per source IPv4 or /64 IPv6
  udp_rate_limit: 1000   # Max UDP packets/sec per source IPv4 or /64 IPv6

conn_track:
  enable: true
  udp_timeout_ns: 30000000000  # UDP connection timeout (30s)

pin_dir: "/sys/fs/bpf/edgectl"  # bpffs directory for pinned maps/links
log_level: "info"                # debug | info | warn | error
```

---

## Development and Testing

### Re-generating eBPF Bindings

If you make modifications to the C eBPF code inside `bpf/`:

```bash
# Rebuild eBPF bytecode and regenerate Go skeletons
go generate ./...
```

### Running Tests

Run unit tests across the Go control modules:

```bash
go test -v ./...
```

---

## Project Directory Layout

```text
.
├── bpf/                # C eBPF source code (XDP, TC programs, maps, helpers)
├── build/              # Output binary build path
├── cmd/                # Cobra CLI commands (attach, block, detach, list, etc.)
├── config/             # YAML configuration templates
├── docs/               # Technical documentation
├── include/            # Kernel headers (vmlinux.h)
├── internal/           # Internal Go packages (config loader, BPF map management, code generator)
├── user/               # Legacy C-based controller and headers
├── Makefile            # Build recipes
└── main.go             # CLI entry point
```

---

## License

The eBPF kernel programs (`bpf/`) are licensed under the GNU General Public License v2.0 (GPL-2.0). The user-space CLI components are provided under the MIT License.