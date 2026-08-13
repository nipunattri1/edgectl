# XDP Firewall - L1
- attach an XDP program to a network interface and safely read packet headers.
- Blocks all ICMPv4 packets (note it lets every ipv6 packet pass through)
- Log the dropped packet size to the trace pipe for basic observability.

# XDP Firewall - L2
- attach an XDP program to a network interface and safely read packet headers.
- config based protocol block list, (supports blocking multiple block list)
- Allow or disallow specific subnets or ips using the cli

## cli docs

- build using `make all`

```bash
# attach the ebpf program to network interface defined in config/config.ini (allow multi protocol block)
sudo build/cli attach

# edit protocol list and reload using
sudo build/cli reload

# block a specific ip or subnet (google in this case)
sudo build/cli block 142.251.155.0/24

# unblock a spcific ip from that subnet
sudo build/cli unblock 142.251.155.1

# List all current rules
sudo build/cli list
```

# XDP Firewall - L3
 - Rate Limiting & DDoS Mitigation
 - included syn and udp flood detection.
Figure out how to track packet rates and timestamps per source IP. If an IP exceeds a predefined threshold (e.g., > 100 packets per second), automatically drop subsequent packets from that source.
