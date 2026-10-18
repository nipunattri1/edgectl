package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nipunattri1/xdp-firewall/cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type app struct {
	v   *viper.Viper
	cfg config.Config
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func NewRootCmd() *cobra.Command {
	a := &app{v: viper.New()}
	var cfgFile string

	root := &cobra.Command{
		Use:           "edgewall",
		Short:         "A Firewall on the edge",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := a.v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			return a.load(cfgFile)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file")
	pf.String("pin-dir", "/sys/fs/bpf/edgewall", "bpffs directory for pinned links")
	pf.String("log-level", "info", "debug|info|warn|error")

	// Explicitly map dashed flags to the underscored config keys.
	// Precedence stays: flag > env > file > flag default.
	a.v.BindPFlag("pin_dir", pf.Lookup("pin-dir"))
	a.v.BindPFlag("log_level", pf.Lookup("log-level"))

	root.AddCommand(
		newStartCmd(a),
		newApplyCmd(a),
		newListCmd(a),
		newDetachCmd(a),
	)
	return root
}

func newDetachCmd(a *app) *cobra.Command {
	panic("unimplemented")
}

func newListCmd(a *app) *cobra.Command {
	panic("unimplemented")
}

func newApplyCmd(a *app) *cobra.Command {
	panic("unimplemented")
}

func (a *app) load(cfgFile string) error {
	a.v.SetEnvPrefix("EBPFCTL")
	a.v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	a.v.AutomaticEnv()

	if cfgFile != "" {
		a.v.SetConfigFile(cfgFile)
	} else {
		a.v.SetConfigName("edgewall")
		a.v.AddConfigPath(".")
		a.v.AddConfigPath("/etc/edgewall")
	}
	if err := a.v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	return a.v.Unmarshal(&a.cfg)
}
