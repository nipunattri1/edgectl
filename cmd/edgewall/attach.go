package main

import (
	"fmt"

	"github.com/nipunattri1/xdp-firewall/cli/internal/bpf"
	"github.com/nipunattri1/xdp-firewall/cli/internal/config"
	"github.com/spf13/cobra"
)

func attachCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach firewall to interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			l, err := bpf.NewLoader(bpf.LoadConfig{
				Device:         cfg.Interface.Device,
				BlockMask:      cfg.Rules.BlockMask,
				SynRateLimit:   cfg.DDoS.SynRateLimit,
				UdpRateLimit:   cfg.DDoS.UdpRateLimit,
				UdpTimeoutNs:   cfg.ConnTrack.UdpTimeoutNs,
				DefaultAllow:   cfg.Rules.DefaultAllow,
				EnableTC:       cfg.ConnTrack.Enable,
			})
			if err != nil {
				return err
			}
			fmt.Println("Firewall attached")
			_ = l
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "Config file path")
	return cmd
}
