package config

import (
	"strings"
	"testing"
)

func TestValidateRuntime(t *testing.T) {
	tests := []struct {
		name    string
		pinDir  string
		wantErr bool
	}{
		{
			name:    "nonexistent dir",
			pinDir:  "/nonexistent/path",
			wantErr: true,
		},
		{
			name:    "empty dir",
			pinDir:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuntime(tt.pinDir)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateForAttach_RootCheck(t *testing.T) {
	// This test documents the root check behavior
	cfg := Config{}
	cfg.Interface.Device = "lo"
	cfg.Interface.Mode = "native"

	err := cfg.Validate()
	// In test environment, we expect root check to fail
	if err == nil {
		// If running as root, that's fine too
		return
	}
	if err.Error() != "attaching requires root or CAP_BPF + CAP_NET_ADMIN" {
		t.Errorf("expected root error, got: %v", err)
	}
}

func TestValidateForAttach_MissingDevice(t *testing.T) {
	cfg := Config{}
	cfg.Interface.Mode = "native"

	err := cfg.Validate()
	if err == nil {
		t.Error("missing device should error")
	}
	if !strings.Contains(err.Error(), "interface.device is required") {
		t.Errorf("error should mention interface.device: %v", err)
	}
}

func TestValidateForAttach_InvalidMode(t *testing.T) {
	cfg := Config{}
	cfg.Interface.Device = "lo"
	cfg.Interface.Mode = "invalid"

	err := cfg.Validate()
	if err == nil {
		t.Error("invalid mode should error")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("error should mention invalid mode: %v", err)
	}
}
