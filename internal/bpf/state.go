package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/nipunattri1/edgectl/internal/config"
	"github.com/nipunattri1/edgectl/internal/gen"
)

func Attach(cfg config.Config) error {

	fwCfg, err := cfg.ToBpfConfig()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("memlock: %w", err)
	}

	ni, err := net.InterfaceByName(cfg.Interface.Device)
	if err != nil {
		return fmt.Errorf("iface %s: %w", cfg.Interface.Device, err)
	}

	if err := os.MkdirAll(cfg.PinDir, 0755); err != nil {
		return fmt.Errorf("pin dir: %w", err)
	}

	spec, err := gen.LoadEdgectl()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	objs := gen.EdgectlObjects{}
	collOpts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
		},
		Maps: ebpf.MapOptions{
			PinPath: cfg.PinDir,
		},
	}

	if err := spec.LoadAndAssign(&objs, collOpts); err != nil {
		if ve, ok := err.(*ebpf.VerifierError); ok {
			return fmt.Errorf("verifier: %+v", ve)
		}
		return fmt.Errorf("load objects: %w", err)
	}

	key := uint32(0)
	if err := objs.ConfigMap.Update(&key, &fwCfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("config map: %w", err)
	}

	xdpOpts := link.XDPOptions{
		Program:   objs.XdpFirewall,
		Interface: ni.Index,
	}
	switch cfg.Interface.Mode {
	case "generic":
		xdpOpts.Flags = link.XDPGenericMode
	case "driver", "native":
		xdpOpts.Flags = link.XDPDriverMode
	case "offload":
		xdpOpts.Flags = link.XDPOffloadMode
	}

	xdpLink, err := link.AttachXDP(xdpOpts)
	if err != nil {
		return fmt.Errorf("xdp attach: %w", err)
	}

	if fwCfg.EnableTc != 0 {
		if err := attachTCX(objs.HandleIngress, objs.HandleEgress, ni.Index, cfg); err != nil {
			return err
		}
	}

	if err := xdpLink.Pin(filepath.Join(cfg.PinDir, xdpPin)); err != nil {
		return fmt.Errorf("pin xdp link: %w", err)
	}

	return nil
}

func attachTCX(ingressProg, egressProg *ebpf.Program, ifIndex int, cfg config.Config) error {
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   ingressProg,
		Interface: ifIndex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("tcx ingress: %w", err)
	}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   egressProg,
		Interface: ifIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("tcx egress: %w", err)
	}

	if err := ingressLink.Pin(filepath.Join(cfg.PinDir, tcInPin)); err != nil {
		return fmt.Errorf("pin tc ingress: %w", err)
	}
	if err := egressLink.Pin(filepath.Join(cfg.PinDir, tcEgPin)); err != nil {
		return fmt.Errorf("pin tc egress: %w", err)
	}
	return nil
}

func DetachAll(pinDir string) error {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return fmt.Errorf("reading pin-dir: %w", err)
	}
	for _, e := range entries {
		path := filepath.Join(pinDir, e.Name())

		// Links first: removing the last reference detaches the program
		if l, err := link.LoadPinnedLink(path, nil); err == nil {
			_ = l.Unpin()
			_ = l.Close()
			continue
		}
		// Anything else (maps, programs): just drop the pin
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("removing item: %w", err)
		}
	}
	return os.Remove(pinDir) // empty dir on bpffs can be removed
}

// ReloadConfig reads the current config from the pinned map and updates
// only the runtime-configurable fields. This allows reload without requiring
// interface.device (which is only needed for initial attach).
func ReloadConfig(cfg config.Config) error {
	key := uint32(0)

	newCfg, err := cfg.ToBpfConfig()
	if err != nil {
		return fmt.Errorf("failed to convert config to ebpf map")
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(cfg.PinDir, gen.EdgectlMapConfigMap), nil)
	if err != nil {
		return fmt.Errorf("fetching map: %w", err)
	}

	return m.Update(&key, &newCfg, ebpf.UpdateExist)
}

type BlockedIP struct {
	CIDR    string
	Blocked bool
	Family  string
}

func ListIPs(cfg config.Config) ([]BlockedIP, error) {
	var result []BlockedIP

	v4, err := listFamily(filepath.Join(cfg.PinDir, gen.EdgectlMapManualBlacklistMap), "ipv4")
	if err != nil {
		return nil, err
	}
	result = append(result, v4...)

	v6, err := listFamily(filepath.Join(cfg.PinDir, gen.EdgectlMapManualBlacklist6Map), "ipv6")
	if err != nil {
		return nil, err
	}
	result = append(result, v6...)

	return result, nil
}

func listFamily(path, family string) ([]BlockedIP, error) {
	mapFD, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, fmt.Errorf("load map %s: %w", path, err)
	}
	defer mapFD.Close()

	var result []BlockedIP
	var key, next []byte

	for err := mapFD.NextKey(nil, &next); err == nil; err = mapFD.NextKey(&key, &next) {
		var val uint32
		if err := mapFD.Lookup(&next, &val); err != nil {
			continue
		}

		key = next
		var cidr string
		if family == "ipv4" {
			if len(next) < 8 {
				continue
			}
			prefixLen := binary.BigEndian.Uint32(next[0:4])
			ip := net.IPv4(next[4], next[5], next[6], next[7])
			cidr = fmt.Sprintf("%s/%d", ip.String(), prefixLen)
		} else {
			if len(next) < 20 {
				continue
			}
			prefixLen := binary.BigEndian.Uint32(next[0:4])
			ip := make(net.IP, 16)
			copy(ip, next[4:20])
			cidr = fmt.Sprintf("%s/%d", ip.String(), prefixLen)
		}

		result = append(result, BlockedIP{
			CIDR:    cidr,
			Blocked: val == 1,
			Family:  family,
		})
	}

	return result, nil
}

func updateLPM(net *IPNet, val uint32, cfg config.Config) error {
	var path string
	var mapFD *ebpf.Map
	var err error

	if net.Family == "ipv4" {
		path = filepath.Join(cfg.PinDir, gen.EdgectlMapManualBlacklistMap)
		ip4 := net.IP.To4()
		var ipBytes [4]byte
		copy(ipBytes[:], ip4)
		ipVal := binary.BigEndian.Uint32(ipBytes[:])

		// Concrete type instead of `any`
		key := gen.EdgectlIpv4LpmKey{
			Prefixlen: uint32(net.PrefixLen),
			Ip:        ipVal,
		}

		mapFD, err = ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
		if err != nil {
			return fmt.Errorf("load map %s: %w", path, err)
		}
		defer mapFD.Close()

		return mapFD.Update(&key, &val, ebpf.UpdateAny)
	} else {
		path = filepath.Join(cfg.PinDir, gen.EdgectlMapManualBlacklist6Map)
		ip6 := net.IP.To16()
		var ipBytes [16]byte
		copy(ipBytes[:], ip6)

		// Concrete type instead of `any`
		key := gen.EdgectlIpv6LpmKey{
			Prefixlen: uint32(net.PrefixLen),
			Addr:      ipBytes,
		}

		mapFD, err = ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
		if err != nil {
			return fmt.Errorf("load map %s: %w", path, err)
		}
		defer mapFD.Close()

		return mapFD.Update(&key, &val, ebpf.UpdateAny)
	}
}

func deleteLPM(net *IPNet, cfg config.Config) error {
	var path string
	var mapFD *ebpf.Map
	var err error

	if net.Family == "ipv4" {
		path = filepath.Join(cfg.PinDir, gen.EdgectlMapManualBlacklistMap)
		ip4 := net.IP.To4()
		var ipBytes [4]byte
		copy(ipBytes[:], ip4)
		ipVal := binary.BigEndian.Uint32(ipBytes[:])

		key := gen.EdgectlIpv4LpmKey{
			Prefixlen: uint32(net.PrefixLen),
			Ip:        ipVal,
		}

		mapFD, err = ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
		if err != nil {
			return fmt.Errorf("load map %s: %w", path, err)
		}
		defer mapFD.Close()

		return mapFD.Delete(&key)
	} else {
		path = filepath.Join(cfg.PinDir, gen.EdgectlMapManualBlacklist6Map)
		ip6 := net.IP.To16()
		var ipBytes [16]byte
		copy(ipBytes[:], ip6)

		key := gen.EdgectlIpv6LpmKey{
			Prefixlen: uint32(net.PrefixLen),
			Addr:      ipBytes,
		}

		mapFD, err = ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
		if err != nil {
			return fmt.Errorf("load map %s: %w", path, err)
		}
		defer mapFD.Close()

		return mapFD.Delete(&key)
	}
}

func BlockIP(net *IPNet, cfg config.Config) error {
	return updateLPM(net, 1, cfg)
}

func UnblockIP(net *IPNet, cfg config.Config) error {
	return deleteLPM(net, cfg)
}
