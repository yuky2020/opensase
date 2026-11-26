//go:build linux

package posture

import (
	"testing"
)

func TestCollectLinux(t *testing.T) {
	p := Collect()
	if p.OS != "linux" {
		t.Errorf("expected OS linux, got %q", p.OS)
	}
	if p.ClientVersion == "" {
		t.Errorf("expected non-empty ClientVersion")
	}
	// On Linux ScreenLock, Firewall, and Managed must be nil
	if p.ScreenLock != nil {
		t.Errorf("expected ScreenLock nil, got %v", p.ScreenLock)
	}
	if p.Firewall != nil {
		t.Errorf("expected Firewall nil, got %v", p.Firewall)
	}
	if p.Managed != nil {
		t.Errorf("expected Managed nil, got %v", p.Managed)
	}
}
