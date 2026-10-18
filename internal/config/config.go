package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Interface struct {
		Device string `yaml:"device"`
	} `yaml:"interface"`
	Rules struct {
		BlockMask   uint64 `yaml:"block_proto"`
		DefaultAllow uint8 `yaml:"default"`
	} `yaml:"rules"`
	DDoS struct {
		SynRateLimit uint32 `yaml:"syn_rate_limit"`
		UdpRateLimit uint32 `yaml:"udp_rate_limit"`
	} `yaml:"ddos"`
	ConnTrack struct {
		Enable         uint8  `yaml:"enable"`
		UdpTimeoutNs   uint64 `yaml:"udp_timeout_ns"`
	} `yaml:"conn_track"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
