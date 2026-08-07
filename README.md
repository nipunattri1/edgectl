# XDP Firewall - L1
- attach an XDP program to a network interface and safely read packet headers.
- Blocks all ICMPv4 packets (note it lets every ipv6 packet pass through)
- Log the dropped packet size to the trace pipe for basic observability.