package main

import (
	"net/netip"
	"testing"
)

func TestWindowsRoutePlan(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	ipA := netip.MustParseAddr("1.2.3.4")
	ipB := netip.MustParseAddr("5.6.7.8")

	tests := []struct {
		name        string
		cfg         netConfig
		bypassIPs   []netip.Addr
		gw          netip.Addr
		wantPrefix  []string
		wantTunnel  []bool
		wantNextHop []netip.Addr
	}{
		{
			name: "ipv4 only with bypass hosts",
			cfg: netConfig{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: []netip.Addr{ipA, ipB},
			gw:        gw,
			wantPrefix: []string{
				"1.2.3.4/32",
				"5.6.7.8/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:  []bool{false, false, true, true},
			wantNextHop: []netip.Addr{gw, gw, {}, {}},
		},
		{
			name: "ipv4 and ipv6 with split routes",
			cfg: netConfig{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				IPv6: "fd00::2/128",
				MTU:  1420,
			},
			bypassIPs: []netip.Addr{ipA},
			gw:        gw,
			wantPrefix: []string{
				"1.2.3.4/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:  []bool{false, true, true, true, true},
			wantNextHop: []netip.Addr{gw, {}, {}, {}, {}},
		},
		{
			name: "duplicate bypass addresses deduplicated",
			cfg: netConfig{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: []netip.Addr{ipA, ipB, ipA, ipB, ipA},
			gw:        gw,
			wantPrefix: []string{
				"1.2.3.4/32",
				"5.6.7.8/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:  []bool{false, false, true, true},
			wantNextHop: []netip.Addr{gw, gw, {}, {}},
		},
		{
			name: "no bypass hosts",
			cfg: netConfig{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: nil,
			gw:        gw,
			wantPrefix: []string{
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:  []bool{true, true},
			wantNextHop: []netip.Addr{{}, {}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsRoutePlan(tc.cfg, tc.bypassIPs, tc.gw)
			if len(got) != len(tc.wantPrefix) {
				t.Fatalf("got %d routes, want %d", len(got), len(tc.wantPrefix))
			}
			for i, r := range got {
				if r.Destination.String() != tc.wantPrefix[i] {
					t.Errorf("route[%d] prefix = %s, want %s", i, r.Destination, tc.wantPrefix[i])
				}
				if r.Tunnel != tc.wantTunnel[i] {
					t.Errorf("route[%d] tunnel = %v, want %v", i, r.Tunnel, tc.wantTunnel[i])
				}
				if r.NextHop != tc.wantNextHop[i] {
					t.Errorf("route[%d] nextHop = %s, want %s", i, r.NextHop, tc.wantNextHop[i])
				}
				if r.Metric != 1 {
					t.Errorf("route[%d] metric = %d, want 1", i, r.Metric)
				}
			}
		})
	}
}
