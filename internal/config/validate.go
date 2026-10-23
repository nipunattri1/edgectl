package config

import (
	"fmt"
	"math"
	"os"
	"strings"
)

// ProtocolNumbers lists the protocols that fit in the kernel's 64-bit block mask.
var ProtocolNumbers = map[string]uint8{
	"icmp":      1,
	"igmp":      2,
	"tcp":       6,
	"udp":       17,
	"gre":       47,
	"esp":       50,
	"ah":        51,
	"icmpv6":    58,
	"ipv6-icmp": 58,
}

func (cfg *Config) Validate() error {
	switch cfg.Interface.Mode {
	case "", "auto", "generic", "driver", "native", "offload":
	default:
		return fmt.Errorf("invalid mode %q (auto, generic, driver, offload)", cfg.Interface.Mode)
	}

	if _, err := cfg.ToBpfConfig(); err != nil {
		return err
	}

	return nil
}

// ValidateConfigOnly validates only the config fields needed for config map update
// (used by reload command which doesn't need interface.device)
func (cfg *Config) ValidateConfigOnly() error {
	switch cfg.Interface.Mode {
	case "", "auto", "generic", "driver", "native", "offload":
	default:
		return fmt.Errorf("invalid mode %q (auto, generic, driver, offload)", cfg.Interface.Mode)
	}

	// Validate block_proto without device
	for _, name := range cfg.Rules.BlockProto {
		if _, ok := ProtocolNumbers[strings.ToLower(strings.TrimSpace(name))]; !ok {
			return fmt.Errorf("unknown protocol %q", name)
		}
	}

	// Validate rate limits
	if cfg.DDoS.SynRateLimit > math.MaxUint32 {
		return fmt.Errorf("ddos.syn_rate_limit %d exceeds %d", cfg.DDoS.SynRateLimit, uint64(math.MaxUint32))
	}
	if cfg.DDoS.UDPRateLimit > math.MaxUint32 {
		return fmt.Errorf("ddos.udp_rate_limit %d exceeds %d", cfg.DDoS.UDPRateLimit, uint64(math.MaxUint32))
	}

	return nil
}

func ValidateRuntime(pinDir string) error {
	// Check if pinned maps exist
	required := []string{
		"config_map",
		"manual_blacklist_map",
		"manual_blacklist6_map",
		"ct_map",
		"ct6_map",
		"prog_link",
	}

	for _, name := range required {
		path := pinDir + "/" + name
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("missing pinned object %s: %w", name, err)
		}
	}
	return nil
}
