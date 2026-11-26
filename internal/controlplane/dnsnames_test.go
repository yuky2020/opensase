package controlplane

import (
	"testing"

	"github.com/yuky2020/opensase/pkg/store"
)

func TestDeviceDNSNames(t *testing.T) {
	for in, want := range map[string]string{"Pixel 9 Pro": "pixel-9-pro", "  --Ünïcode--  ": "n-code", "": "dev-1", "a__b": "a-b"} {
		if got := dnsLabel(in, "dev-1"); got != want {
			t.Errorf("dnsLabel(%q) = %q, want %q", in, got, want)
		}
	}
	act := []store.ActiveSnapshot{
		{Device: store.Device{ID: "aaaaaaaa-1", TenantID: "acme", UserID: "alice", Name: "Laptop"}},
		{Device: store.Device{ID: "bbbbbbbb-2", TenantID: "acme", UserID: "alice", Name: "laptop"}},
		{Device: store.Device{ID: "cccccccc-3", TenantID: "beta", UserID: "alice", Name: "laptop"}},
	}
	got := deviceDNSNames(act)
	if got["aaaaaaaa-1"] != "laptop.alice" || got["bbbbbbbb-2"] != "laptop-bbbbbb.alice" || got["cccccccc-3"] != "laptop.alice" {
		t.Fatalf("names %v", got)
	}
}
