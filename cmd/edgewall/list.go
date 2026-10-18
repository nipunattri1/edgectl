package main

import "github.com/spf13/cobra"

func listCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Short: "List blocked IPs", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}
