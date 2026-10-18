package main

import "github.com/spf13/cobra"

func blockCmd() *cobra.Command {
	return &cobra.Command{Use: "block", Short: "Block IP/subnet", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}

func unblockCmd() *cobra.Command {
	return &cobra.Command{Use: "unblock", Short: "Unblock IP/subnet", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}
