package main

import (
	"github.com/nipunattri1/xdp-firewall/cli/internal/bpf"
	"github.com/nipunattri1/xdp-firewall/cli/internal/config"
	"github.com/spf13/cobra"
)

func reloadCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			l, err := bpf.LoadPinned("/sys/fs/bpf/xdp_firewall")
			if err != nil {
				return err
			}
			return l.UpdateConfig(bpf.LoadConfig{
				Device:         cfg.Interface.Device,
				BlockMask:      cfg.Rules.BlockMask,
				SynRateLimit:   cfg.DDoS.SynRateLimit,
				UdpRateLimit:   cfg.DDoS.UdpRateLimit,
				UdpTimeoutNs:   cfg.ConnTrack.UdpTimeoutNs,
				DefaultAllow:   cfg.Rules.DefaultAllow,
				EnableTC:       cfg.ConnTrack.Enable,
			})
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "Config file path")
	return cmd
}
