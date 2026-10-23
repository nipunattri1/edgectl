package config

import (
	"fmt"
	"math"
	"strings"

	"github.com/nipunattri1/xdp-firewall/internal/gen"
)

type Config struct {
	Interface struct {
		Device string `mapstructure:"device"`
		Mode   string `mapstructure:"mode"`
	} `mapstructure:"interface"`
	Rules struct {
		BlockProto     []string  `mapstructure:"block_proto"`
		AllowAsDefault IsAllowed `mapstructure:"default"`
	} `mapstructure:"rules"`
	DDoS struct {
		Enabled      bool   `mapstructure:"enable"`
		SynRateLimit uint64 `mapstructure:"syn_rate_limit"`
		UDPRateLimit uint64 `mapstructure:"udp_rate_limit"`
	} `mapstructure:"ddos"`
	ConnTrack struct {
		Enable       bool   `mapstructure:"enable"`
		UdpTimeoutNs uint64 `mapstructure:"udp_timeout_ns"`
	} `mapstructure:"conn_track"`
	PinDir   string `mapstructure:"pin_dir"`
	LogLevel string `mapstructure:"log_level"`
}

// protocolNumbers lists the protocols that fit in the kernel's 64-bit block mask.
var protocolNumbers = map[string]uint8{
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

// ToBpfConfig converts the CLI config into the FirewallConfig map value.
func (cfg *Config) ToBpfConfig() (gen.EdgeWallFirewallConfig, error) {
	var fw gen.EdgeWallFirewallConfig

	if cfg.Interface.Device == "" {
		return fw, fmt.Errorf("interface.device is required")
	}
	if len(cfg.Interface.Device) >= len(fw.Device) {
		return fw, fmt.Errorf("interface.device %q is longer than %d bytes", cfg.Interface.Device, len(fw.Device)-1)
	}
	for i, c := range cfg.Interface.Device {
		fw.Device[i] = int8(c)
	}

	for _, name := range cfg.Rules.BlockProto {
		proto, ok := protocolNumbers[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return fw, fmt.Errorf("unknown protocol %q", name)
		}
		fw.BlockMask |= uint64(1) << proto
	}

	if cfg.Rules.AllowAsDefault {
		fw.DefaultAllow = 1
	}
	if cfg.ConnTrack.Enable {
		fw.EnableTc = 1
	}
	if cfg.DDoS.SynRateLimit > math.MaxUint32 {
		return fw, fmt.Errorf("ddos.syn_rate_limit %d exceeds %d", cfg.DDoS.SynRateLimit, uint64(math.MaxUint32))
	}
	if cfg.DDoS.UDPRateLimit > math.MaxUint32 {
		return fw, fmt.Errorf("ddos.udp_rate_limit %d exceeds %d", cfg.DDoS.UDPRateLimit, uint64(math.MaxUint32))
	}
	if cfg.DDoS.Enabled {
		fw.SynRateLimit = uint32(cfg.DDoS.SynRateLimit)
		fw.UdpRateLimit = uint32(cfg.DDoS.UDPRateLimit)
	}
	fw.UdpTimeoutNs = cfg.ConnTrack.UdpTimeoutNs

	return fw, nil
}
