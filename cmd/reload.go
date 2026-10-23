package cmd

import (
	"fmt"

	"github.com/nipunattri1/xdp-firewall/internal/bpf"
	"github.com/spf13/cobra"
)

func newReloadCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload configuration from config file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.cfg.Validate(); err != nil {
				return fmt.Errorf("config validation: %w", err)
			}
			if err := bpf.ReloadConfig(a.cfg); err != nil {
				return fmt.Errorf("update config: %w", err)
			}

			fmt.Println("Configuration reloaded.")
			return nil
		},
	}
}
