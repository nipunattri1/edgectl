package bpf

import "github.com/cilium/ebpf/link"

type FirewallConfig struct {
	Device       [16]byte
	BlockMask    uint64
	EnableTC     uint8
	DefaultAllow uint8
	SynRateLimit uint32
	UdpRateLimit uint32
	UdpTimeoutNs uint64
}

type Loader struct {
	objects *firewallObjects
	links   []link.Link
	iface   string
	ifindex int
}
