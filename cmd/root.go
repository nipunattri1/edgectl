package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nipunattri1/edgectl/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "dev"

type app struct {
	v      *viper.Viper
	cfg    config.Config
	pinDir string
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
		Use:           "edgectl",
		Short:         "eBPF firewall control",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if isMetaCommand(cmd) {
				return nil
			}
			return a.loadCfgFile(cfgFile)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default: /etc/edgectl/edgectl.yaml)")
	pf.String("pin-dir", "/sys/fs/bpf/edgectl", "bpffs directory for pinned links and maps")
	pf.String("log-level", "info", "debug | info | warn | error")

	a.v.BindPFlag("pin_dir", pf.Lookup("pin-dir"))
	a.v.BindPFlag("log_level", pf.Lookup("log-level"))

	root.AddCommand(
		newAttachCmd(a),
		newDetachCmd(a),
		newReloadCmd(a),
		newListCmd(a),
		newBlockCmd(a),
		newUnblockCmd(a),
	)
	return root
}

func (a *app) loadCfgFile(cfgFile string) error {
	a.v.SetEnvPrefix("EDGE")
	a.v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	a.v.AutomaticEnv()
	a.v.SetDefault("ddos.enable", true)

	if cfgFile != "" {
		a.v.SetConfigFile(cfgFile)
	} else {
		a.v.SetConfigName("edgectl")
		a.v.SetConfigType("yaml")
		a.v.AddConfigPath(".")
		a.v.AddConfigPath("/etc/edgectl")
	}

	if err := a.v.ReadInConfig(); err != nil {
		if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound || cfgFile != "" {
			return fmt.Errorf("read config: %w", err)
		}
	}

	if err := a.v.Unmarshal(&a.cfg, viper.DecodeHook(config.IsAllowedHook())); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	a.pinDir = a.v.GetString("pin_dir")
	if a.cfg.PinDir == "" {
		a.cfg.PinDir = a.pinDir
	}

	switch a.v.GetString("log_level") {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log level %q", a.v.GetString("log_level"))
	}
	return nil
}

func isMetaCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			return true
		}
	}
	return false
}
