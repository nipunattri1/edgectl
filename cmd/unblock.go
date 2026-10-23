package cmd

import (
	"fmt"
	"net"

	"github.com/nipunattri1/xdp-firewall/internal/bpf"
	"github.com/spf13/cobra"
)

func newUnblockCmd(a *app) *cobra.Command {
	var ipv6 bool

	c := &cobra.Command{
		Use:   "unblock <CIDR>",
		Short: "Unblock an IP or subnet",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cidr := args[0]

			family := "ipv4"
			if ipv6 {
				family = "ipv6"
			}

			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
			}

			ones, bits := ipNet.Mask.Size()
			if family == "ipv4" && bits != 32 {
				return fmt.Errorf("CIDR %q is not IPv4", cidr)
			}
			if family == "ipv6" && bits != 128 {
				return fmt.Errorf("CIDR %q is not IPv6", cidr)
			}

			netIP := &bpf.IPNet{
				IP:        ipNet.IP,
				PrefixLen: ones,
				Family:    family,
			}

			if err := bpf.UnblockIP(netIP, a.cfg); err != nil {
				return fmt.Errorf("unblock %s: %w", cidr, err)
			}

			fmt.Printf("Unblocked %s\n", cidr)
			return nil
		},
	}

	c.Flags().BoolVarP(&ipv6, "6", "6", false, "IPv6 address")
	return c
}