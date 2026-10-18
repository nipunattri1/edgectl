package main

import (
	"github.com/nipunattri1/xdp-firewall/cli/internal/bpf"
	"github.com/spf13/cobra"
)

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
