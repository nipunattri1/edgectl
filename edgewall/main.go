package main

import (
	"fmt"
	"os"

	"github.com/nipunattri1/xdp-firewall/cli/internal/bpf"
	"github.com/nipunattri1/xdp-firewall/cli/internal/config"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "edgewall",
		Short: "XDP/TC eBPF Firewall",
	}

	rootCmd.AddCommand(attachCmd(), detachCmd(), reloadCmd(), blockCmd(), unblockCmd(), listCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
				Device:       cfg.Interface.Device,
				BlockMask:    cfg.Rules.BlockMask,
				SynRateLimit: cfg.DDoS.SynRateLimit,
				UdpRateLimit: cfg.DDoS.UdpRateLimit,
				UdpTimeoutNs: cfg.ConnTrack.UdpTimeoutNs,
				DefaultAllow: cfg.Rules.DefaultAllow,
				EnableTC:     cfg.ConnTrack.Enable,
			})
			if err != nil {
				return err
			}
			fmt.Println("Firewall attached")
			_ = l // keep alive
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "Config file path")
	return cmd
}

func detachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detach",
		Short: "Detach firewall",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := bpf.LoadPinned("/sys/fs/bpf/xdp_firewall")
			if err != nil {
				return err
			}
			return l.Close()
		},
	}
}

func reloadCmd() *cobra.Command {
	var cfgPath string
	return &cobra.Command{
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
				Device:       cfg.Interface.Device,
				BlockMask:    cfg.Rules.BlockMask,
				SynRateLimit: cfg.DDoS.SynRateLimit,
				UdpRateLimit: cfg.DDoS.UdpRateLimit,
				UdpTimeoutNs: cfg.ConnTrack.UdpTimeoutNs,
				DefaultAllow: cfg.Rules.DefaultAllow,
				EnableTC:     cfg.ConnTrack.Enable,
			})
		},
	}
}

func blockCmd() *cobra.Command {
	return &cobra.Command{Use: "block", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}
func unblockCmd() *cobra.Command {
	return &cobra.Command{Use: "unblock", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}
func listCmd() *cobra.Command {
	return &cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}
