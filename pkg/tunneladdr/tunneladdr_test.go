package tunneladdr

import (
	"net/netip"
	"testing"
)

func TestPlan(t *testing.T) {
	a4, a6 := AddrAt(2)
	if a4 != netip.MustParseAddr("100.64.0.2") || a6 != netip.MustParseAddr("fd7a:5a5e::2") {
		t.Fatalf("offset 2: %v %v", a4, a6)
	}
	tests := []struct {
		off  uint32
		want bool
	}{{0, false}, {1, false}, {2, true}, {MaxOffset, true}, {MaxOffset + 1, false}}
	for _, tc := range tests {
		if Usable(tc.off) != tc.want {
			t.Errorf("Usable(%d) = %v", tc.off, !tc.want)
		}
	}
	// 100.96.0.0 is offset 0x200000: the private app range is skipped.
	syn := uint32(0x200000)
	if a, _ := AddrAt(syn); a != netip.MustParseAddr("100.96.0.0") || Usable(syn) {
		t.Fatalf("synthetic start %v usable %v", a, Usable(syn))
	}
	next := NextUsable(syn)
	if a, _ := AddrAt(next); a != netip.MustParseAddr("100.112.0.0") || !Usable(next) {
		t.Fatalf("next usable after the private app range: %v", a)
	}
	if NextUsable(0) != 2 || NextUsable(MaxOffset+1) != 0 {
		t.Fatal("bounds")
	}
}
