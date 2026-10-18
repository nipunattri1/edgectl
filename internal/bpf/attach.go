package bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// loadAndAttach loads the firewall objects and attaches XDP + TCX.
func loadAndAttach(iface string) error {
	objs := firewallObjects{}
	if err := loadFirewallObjects(&objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}

	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("iface: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewall,
		Interface: ni.Index,
	})
	if err != nil {
		return fmt.Errorf("xdp attach: %w", err)
	}
	_ = xdpLink

	// TCX ingress
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.HandleIngress,
		Interface: ni.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("tcx ingress: %w", err)
	}
	_ = ingressLink

	// TCX egress
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.HandleEgress,
		Interface: ni.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("tcx egress: %w", err)
	}
	_ = egressLink

	return nil
}

func load()  {}
func attach() {}
