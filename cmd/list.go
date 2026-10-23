package cmd

import (
	"fmt"

	"github.com/nipunattri1/xdp-firewall/internal/bpf"
	"github.com/spf13/cobra"
)

func newListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List blocked IPs/subnets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {

			ips, err := bpf.ListIPs(a.cfg)
			if err != nil {
				return fmt.Errorf("list IPs: %w", err)
			}

			if len(ips) == 0 {
				fmt.Println("No rules found.")
				return nil
			}

			fmt.Println("Configured IP Rules:")
			for _, ip := range ips {
				status := "ALLOWED"
				if ip.Blocked {
					status = "BLOCKED"
				}
				fmt.Printf(" - %s [%s] (%s)\n", ip.CIDR, status, ip.Family)
			}
			return nil
		},
	}
}
