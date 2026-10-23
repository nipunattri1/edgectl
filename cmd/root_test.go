package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestNewAttachCmd(t *testing.T) {
	a := &app{}
	c := newAttachCmd(a)

	if c.Use != "attach" {
		t.Errorf("Use = %q, want 'attach'", c.Use)
	}
	if c.Short != "Load and attach the firewall" {
		t.Errorf("Short = %q", c.Short)
	}

	// Check flags
	hasInterface := false
	hasMode := false
	c.Flags().VisitAll(func(f *pflag.Flag) {
		switch f.Name {
		case "interface":
			hasInterface = true
			if f.DefValue != "" {
				t.Errorf("interface flag default = %q, want empty", f.DefValue)
			}
		case "mode":
			hasMode = true
			if f.DefValue != "" {
				t.Errorf("mode flag default = %q, want empty", f.DefValue)
			}
		}
	})

	if !hasInterface {
		t.Error("missing --interface flag")
	}
	if !hasMode {
		t.Error("missing --mode flag")
	}
}

func TestNewDetachCmd(t *testing.T) {
	a := &app{}
	c := newDetachCmd(a)

	if c.Use != "detach" {
		t.Errorf("Use = %q, want 'detach'", c.Use)
	}
	if c.Short != "Detach firewall and cleanup" {
		t.Errorf("Short = %q", c.Short)
	}
	if c.Args == nil {
		t.Error("detach should have Args set")
	}
	// cobra.NoArgs is a function, test it works
	if err := c.Args(c, []string{}); err != nil {
		t.Errorf("detach with no args should pass: %v", err)
	}
	if err := c.Args(c, []string{"extra"}); err == nil {
		t.Error("detach with args should fail")
	}
}

func TestNewReloadCmd(t *testing.T) {
	a := &app{}
	c := newReloadCmd(a)

	if c.Use != "reload" {
		t.Errorf("Use = %q, want 'reload'", c.Use)
	}
	if c.Short != "Reload configuration from config file" {
		t.Errorf("Short = %q", c.Short)
	}
}

func TestNewListCmd(t *testing.T) {
	a := &app{}
	c := newListCmd(a)

	if c.Use != "list" {
		t.Errorf("Use = %q, want 'list'", c.Use)
	}
	if c.Short != "List blocked IPs/subnets" {
		t.Errorf("Short = %q", c.Short)
	}
}

func TestNewBlockCmd(t *testing.T) {
	a := &app{}
	c := newBlockCmd(a)

	if c.Use != "block <ipv4|ipv6>[/prefix]" {
		t.Errorf("Use = %q", c.Use)
	}
	if c.Short != "Block IP or subnet" {
		t.Errorf("Short = %q", c.Short)
	}
	if c.Args == nil {
		t.Error("block should have Args set")
	}
	// cobra.ExactArgs(1) is a function, test it works
	if err := c.Args(c, []string{"192.168.1.1/32"}); err != nil {
		t.Errorf("block with 1 arg should pass: %v", err)
	}
	if err := c.Args(c, []string{}); err == nil {
		t.Error("block with 0 args should fail")
	}
	if err := c.Args(c, []string{"a", "b"}); err == nil {
		t.Error("block with 2 args should fail")
	}
}

func TestNewUnblockCmd(t *testing.T) {
	a := &app{}
	c := newUnblockCmd(a)

	if c.Use != "unblock <ipv4|ipv6>[/prefix]" {
		t.Errorf("Use = %q", c.Use)
	}
	if c.Short != "Unblock IP or subnet" {
		t.Errorf("Short = %q", c.Short)
	}
	if c.Args == nil {
		t.Error("unblock should have Args set")
	}
	// cobra.ExactArgs(1) is a function, test it works
	if err := c.Args(c, []string{"192.168.1.1/32"}); err != nil {
		t.Errorf("unblock with 1 arg should pass: %v", err)
	}
	if err := c.Args(c, []string{}); err == nil {
		t.Error("unblock with 0 args should fail")
	}
	if err := c.Args(c, []string{"a", "b"}); err == nil {
		t.Error("unblock with 2 args should fail")
	}
}

func TestRootCmd_CommandsRegistered(t *testing.T) {
	root := NewRootCmd()

	expectedCmds := []string{"attach", "detach", "reload", "list", "block", "unblock"}
	for _, name := range expectedCmds {
		found := false
		for _, c := range root.Commands() {
			if c.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing command: %s", name)
		}
	}
	// help and completion are auto-added by Cobra at execution time
}

func TestRootCmd_GlobalFlags(t *testing.T) {
	root := NewRootCmd()

	expectedFlags := []string{"config", "pin-dir", "log-level"}
	for _, name := range expectedFlags {
		if f := root.PersistentFlags().Lookup(name); f == nil {
			t.Errorf("missing global flag: %s", name)
		}
	}
	// help and version are auto-added by Cobra
}

func TestRootCmd_DefaultPinDir(t *testing.T) {
	root := NewRootCmd()
	f := root.PersistentFlags().Lookup("pin-dir")
	if f == nil {
		t.Fatal("pin-dir flag not found")
	}
	if f.DefValue != "/sys/fs/bpf/edgectl" {
		t.Errorf("pin-dir default = %q, want /sys/fs/bpf/edgectl", f.DefValue)
	}
}

func TestIsMetaCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmdName string
		want    bool
	}{
		{"help", "help", true},
		{"completion", "completion", true},
		{"attach", "attach", false},
		{"detach", "detach", false},
		{"reload", "reload", false},
		{"list", "list", false},
		{"block", "block", false},
		{"unblock", "unblock", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cobra.Command{Use: tt.cmdName}
			got := isMetaCommand(c)
			if got != tt.want {
				t.Errorf("isMetaCommand(%q) = %v, want %v", tt.cmdName, got, tt.want)
			}
		})
	}
}

func TestRootCmd_Help(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"--help"})
	err := root.Execute()
	if err != nil {
		t.Errorf("help command failed: %v", err)
	}
}

func TestAttachCmd_Help(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"attach", "--help"})
	err := root.Execute()
	if err != nil {
		t.Errorf("attach --help failed: %v", err)
	}
}

func TestBlockCmd_Help(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"block", "--help"})
	err := root.Execute()
	if err != nil {
		t.Errorf("block --help failed: %v", err)
	}
}

func TestInvalidCommand(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"invalidcmd"})
	err := root.Execute()
	if err == nil {
		t.Error("invalid command should error")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("error should mention unknown command: %v", err)
	}
}
