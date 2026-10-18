package bpf

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const PIN_DIR = "/sys/fs/bpf/xdp_firewall"

var (
	ConfigMapPath       = filepath.Join(PIN_DIR, "config_map")
	ManualBlockMapPath  = filepath.Join(PIN_DIR, "manual_block_map")
	ManualBlockMap6Path = filepath.Join(PIN_DIR, "manual_blacklist6_map")
	CTMapPath           = filepath.Join(PIN_DIR, "ct_map")
	CT6MapPath          = filepath.Join(PIN_DIR, "ct6_map")
	LinkPath            = filepath.Join(PIN_DIR, "prog_link")
)

type LoadConfig struct {
	Device         string
	BlockMask      uint64
	SynRateLimit   uint32
	UdpRateLimit   uint32
	UdpTimeoutNs   uint64
	DefaultAllow   uint8
	EnableTC       uint8
}

// NewLoader creates a loader, loads BPF objects, and attaches to interface
func NewLoader(cfg LoadConfig) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}

	ni, err := net.InterfaceByName(cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("iface %s: %w", cfg.Device, err)
	}

	spec, err := loadFirewall()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	objs := firewallObjects{}
	collOpts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
		},
		Maps: ebpf.MapOptions{
			PinPath: PIN_DIR,
		},
	}

	if err := spec.LoadAndAssign(&objs, collOpts); err != nil {
		if ve, ok := err.(*ebpf.VerifierError); ok {
			return nil, fmt.Errorf("verifier: %+v", ve)
		}
		return nil, fmt.Errorf("load objects: %w", err)
	}

	fwCfg := FirewallConfig{
		BlockMask:      cfg.BlockMask,
		EnableTC:       cfg.EnableTC,
		DefaultAllow:   cfg.DefaultAllow,
		SynRateLimit:   cfg.SynRateLimit,
		UdpRateLimit:   cfg.UdpRateLimit,
		UdpTimeoutNs:   cfg.UdpTimeoutNs,
	}
	copy(fwCfg.Device[:], cfg.Device)

	key := uint32(0)
	if err := objs.ConfigMap.Update(&key, &fwCfg, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("config map: %w", err)
	}

	l := &Loader{
		objects: &objs,
		links:   make([]link.Link, 0),
		iface:   cfg.Device,
		ifindex: ni.Index,
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewall,
		Interface: ni.Index,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("xdp attach: %w", err)
	}
	l.links = append(l.links, xdpLink)

	if cfg.EnableTC != 0 {
		if err := l.attachTCX(objs.HandleIngress, objs.HandleEgress); err != nil {
			l.Close()
			return nil, err
		}
	}

	if err := xdpLink.Pin(LinkPath); err != nil {
		l.Close()
		return nil, fmt.Errorf("pin link: %w", err)
	}

	if err := os.MkdirAll(PIN_DIR, 0755); err != nil {
		l.Close()
		return nil, fmt.Errorf("pin dir: %w", err)
	}

	for _, p := range []string{ConfigMapPath, ManualBlockMapPath, ManualBlockMap6Path, CTMapPath, CT6MapPath} {
		if _, err := os.Stat(p); err != nil {
			l.Close()
			return nil, fmt.Errorf("map not pinned %s: %w", p, err)
		}
	}

	return l, nil
}

func (l *Loader) attachTCX(ingressProg, egressProg *ebpf.Program) error {
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   ingressProg,
		Interface: l.ifindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("tcx ingress: %w", err)
	}
	l.links = append(l.links, ingressLink)

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   egressProg,
		Interface: l.ifindex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("tcx egress: %w", err)
	}
	l.links = append(l.links, egressLink)

	if err := ingressLink.Pin(filepath.Join(PIN_DIR, "tc_ingress_link")); err != nil {
		return fmt.Errorf("pin tc ingress: %w", err)
	}
	if err := egressLink.Pin(filepath.Join(PIN_DIR, "tc_egress_link")); err != nil {
		return fmt.Errorf("pin tc egress: %w", err)
	}
	return nil
}

func (l *Loader) UpdateConfig(cfg LoadConfig) error {
	fwCfg := FirewallConfig{
		BlockMask:      cfg.BlockMask,
		EnableTC:       cfg.EnableTC,
		DefaultAllow:   cfg.DefaultAllow,
		SynRateLimit:   cfg.SynRateLimit,
		UdpRateLimit:   cfg.UdpRateLimit,
		UdpTimeoutNs:   cfg.UdpTimeoutNs,
	}
	copy(fwCfg.Device[:], cfg.Device)

	key := uint32(0)
	return l.objects.ConfigMap.Update(&key, &fwCfg, ebpf.UpdateAny)
}

func (l *Loader) Close() error {
	var errs []error

	for _, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link: %w", err))
		}
	}

	for _, p := range []string{LinkPath, filepath.Join(PIN_DIR, "tc_ingress_link"), filepath.Join(PIN_DIR, "tc_egress_link"), ConfigMapPath, ManualBlockMapPath, ManualBlockMap6Path, CTMapPath, CT6MapPath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("unpin %s: %w", p, err))
		}
	}

	if l.objects != nil {
		l.objects.Close()
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

func LoadPinned(pinPath string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	spec, err := loadFirewall()
	if err != nil {
		return nil, err
	}

	objs := firewallObjects{}
	collOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}

	if err := spec.LoadAndAssign(&objs, collOpts); err != nil {
		return nil, fmt.Errorf("load pinned: %w", err)
	}

	return &Loader{
		objects: &objs,
		links:   nil,
	}, nil
}
