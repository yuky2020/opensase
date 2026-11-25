//go:build linux

package edge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckIPForwardFile(t *testing.T) {
	dir := t.TempDir()

	pEnabled := filepath.Join(dir, "enabled")
	if err := os.WriteFile(pEnabled, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	pDisabled := filepath.Join(dir, "disabled")
	if err := os.WriteFile(pDisabled, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}

	pEmpty := filepath.Join(dir, "empty")
	if err := os.WriteFile(pEmpty, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	pMissing := filepath.Join(dir, "missing")

	tests := []struct {
		name        string
		path        string
		wantErr     bool
		errContains string
	}{
		{
			name:    "enabled",
			path:    pEnabled,
			wantErr: false,
		},
		{
			name:        "disabled",
			path:        pDisabled,
			wantErr:     true,
			errContains: "IPv4 forwarding is disabled in the Edge network namespace",
		},
		{
			name:        "empty",
			path:        pEmpty,
			wantErr:     true,
			errContains: "IPv4 forwarding is disabled in the Edge network namespace",
		},
		{
			name:    "missing",
			path:    pMissing,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkIPForwardFile(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkIPForwardFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errContains)) {
				t.Fatalf("checkIPForwardFile() error = %v, want substring %q", err, tt.errContains)
			}
		})
	}
}
