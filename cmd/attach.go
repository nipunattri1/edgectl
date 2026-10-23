package cmd

import (
	"fmt"

	"github.com/nipunattri1/xdp-firewall/internal/bpf"
	"github.com/spf13/cobra"
)

func newAttachCmd(a *app) *cobra.Command {
	c := &cobra.Command{
		Use:   "attach",
		Short: "Load and attach the firewall",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if f := cmd.Flags().Lookup("interface"); f.Changed {
				a.cfg.Interface.Device = f.Value.String()
			}
			if f := cmd.Flags().Lookup("mode"); f.Changed {
				a.cfg.Interface.Mode = f.Value.String()
			}
			return a.cfg.Validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runAttach()
		},
	}

	f := c.Flags()
	f.String("interface", "", "network interface to protect (required)")
	f.String("mode", "", "XDP mode: auto | generic | driver | offload")

	return c
}

func (a *app) runAttach() error {
	err := bpf.Attach(a.cfg)
	if err != nil {
		return fmt.Errorf("attach %s: %w", a.cfg.Interface.Device, err)
	}

	fmt.Println("Attached.")
	return nil
}
