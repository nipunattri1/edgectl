package cmd

import (
	"fmt"

	"github.com/nipunattri1/xdp-firewall/internal/bpf"
	"github.com/spf13/cobra"
)

func newDetachCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "detach",
		Short: "Detach firewall and cleanup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := bpf.DetachAll(a.cfg.PinDir); err != nil {
				return fmt.Errorf("detach: %w", err)
			}

			fmt.Println("Detached.")
			return nil
		},
	}
}
