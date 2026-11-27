package clientnet

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestWindowsRoutePlan(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	gw6 := netip.MustParseAddr("fe80::1")
	ipA := netip.MustParseAddr("1.2.3.4")
	ipB := netip.MustParseAddr("5.6.7.8")
	ip6A := netip.MustParseAddr("2001:db8::10")
	ip6B := netip.MustParseAddr("2001:db8::20")
	mappedA := netip.MustParseAddr("::ffff:1.2.3.4")

	tests := []struct {
		name          string
		cfg           Config
		bypassIPs     []netip.Addr
		gw4           netip.Addr
		gw6           netip.Addr
		ipv6Enabled   bool
		wantPrefix    []string
		wantTunnel    []bool
		wantBlackhole []bool
		wantNextHop   []netip.Addr
	}{
		{
			name: "ipv4 only with bypass hosts and ipv6 disabled",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: []netip.Addr{ipA, ipB},
			gw4:       gw,
			wantPrefix: []string{
				"1.2.3.4/32",
				"5.6.7.8/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:    []bool{false, false, true, true},
			wantBlackhole: []bool{false, false, false, false},
			wantNextHop:   []netip.Addr{gw, gw, {}, {}},
		},
		{
			name: "ipv4 and ipv6 with split routes",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				IPv6: "fd00::2/128",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ipA},
			gw4:         gw,
			ipv6Enabled: true,
			wantPrefix: []string{
				"1.2.3.4/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, false, false},
			wantNextHop:   []netip.Addr{gw, {}, {}, {}, {}},
		},
		{
			name: "duplicate bypass addresses deduplicated",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: []netip.Addr{ipA, ipB, ipA, ipB, ipA},
			gw4:       gw,
			wantPrefix: []string{
				"1.2.3.4/32",
				"5.6.7.8/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:    []bool{false, false, true, true},
			wantBlackhole: []bool{false, false, false, false},
			wantNextHop:   []netip.Addr{gw, gw, {}, {}},
		},
		{
			name: "no bypass hosts with ipv6 disabled",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: nil,
			gw4:       gw,
			wantPrefix: []string{
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:    []bool{true, true},
			wantBlackhole: []bool{false, false},
			wantNextHop:   []netip.Addr{{}, {}},
		},
		{
			name: "ipv6 bypass host gets a /128 via the ipv6 gateway",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				IPv6: "fd7a:5a5e::2/128",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ip6A},
			gw4:         gw,
			gw6:         gw6,
			ipv6Enabled: true,
			wantPrefix: []string{
				"2001:db8::10/128",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, false, false},
			wantNextHop:   []netip.Addr{gw6, {}, {}, {}, {}},
		},
		{
			name: "mixed ipv4 and ipv6 bypass hosts deduplicated, mapped ipv4 treated as ipv4",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				IPv6: "fd7a:5a5e::2/128",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ipA, ip6A, ipA, ip6A, mappedA, ip6B},
			gw4:         gw,
			gw6:         gw6,
			ipv6Enabled: true,
			wantPrefix: []string{
				"1.2.3.4/32",
				"2001:db8::10/128",
				"2001:db8::20/128",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, false, false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, false, false, false, false},
			wantNextHop:   []netip.Addr{gw, gw6, gw6, {}, {}, {}, {}},
		},
		{
			name: "ipv6-only host: ipv4 bypass hosts get no route",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				IPv6: "fd7a:5a5e::2/128",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ipA, ip6A},
			gw6:         gw6,
			ipv6Enabled: true,
			wantPrefix: []string{
				"2001:db8::10/128",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, false, false},
			wantNextHop:   []netip.Addr{gw6, {}, {}, {}, {}},
		},
		{
			name: "ipv4-only host with ipv6 disabled: ipv6 bypass hosts get no route",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs: []netip.Addr{ip6A, ipA},
			gw4:       gw,
			wantPrefix: []string{
				"1.2.3.4/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
			},
			wantTunnel:    []bool{false, true, true},
			wantBlackhole: []bool{false, false, false},
			wantNextHop:   []netip.Addr{gw, {}, {}},
		},
		{
			name: "no tunnel ipv6 with ipv6 enabled and gw6 installs blackhole split routes and keeps /128 bypass",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ipA, ip6A},
			gw4:         gw,
			gw6:         gw6,
			ipv6Enabled: true,
			wantPrefix: []string{
				"1.2.3.4/32",
				"2001:db8::10/128",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, false, true, true},
			wantNextHop:   []netip.Addr{gw, gw6, {}, {}, {}, {}},
		},
		{
			name: "no tunnel ipv6 with ipv6 enabled and no gw6 still installs blackhole split routes",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ipA},
			gw4:         gw,
			ipv6Enabled: true,
			wantPrefix: []string{
				"1.2.3.4/32",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, true, true},
			wantNextHop:   []netip.Addr{gw, {}, {}, {}, {}},
		},
		{
			name: "no tunnel ipv6 with physical gw6 installs blackhole even if ipv6Enabled is false",
			cfg: Config{
				Dev:  "OpenSASE",
				IPv4: "100.64.0.2",
				MTU:  1420,
			},
			bypassIPs:   []netip.Addr{ip6A},
			gw4:         gw,
			gw6:         gw6,
			ipv6Enabled: false,
			wantPrefix: []string{
				"2001:db8::10/128",
				"0.0.0.0/1",
				"128.0.0.0/1",
				"::/1",
				"8000::/1",
			},
			wantTunnel:    []bool{false, true, true, true, true},
			wantBlackhole: []bool{false, false, false, true, true},
			wantNextHop:   []netip.Addr{gw6, {}, {}, {}, {}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsRoutePlan(tc.cfg, tc.bypassIPs, tc.gw4, tc.gw6, tc.ipv6Enabled)
			if len(got) != len(tc.wantPrefix) {
				t.Fatalf("got %d routes, want %d: %v", len(got), len(tc.wantPrefix), got)
			}
			for i, r := range got {
				if r.Destination.String() != tc.wantPrefix[i] {
					t.Errorf("route %d prefix: got %s, want %s", i, r.Destination, tc.wantPrefix[i])
				}
				if r.Tunnel != tc.wantTunnel[i] {
					t.Errorf("route %d tunnel: got %v, want %v", i, r.Tunnel, tc.wantTunnel[i])
				}
				if r.Blackhole != tc.wantBlackhole[i] {
					t.Errorf("route %d blackhole: got %v, want %v", i, r.Blackhole, tc.wantBlackhole[i])
				}
				if r.NextHop != tc.wantNextHop[i] {
					t.Errorf("route %d nextHop: got %s, want %s", i, r.NextHop, tc.wantNextHop[i])
				}
			}
		})
	}
}

func TestPickDefaultGateway(t *testing.T) {
	def4 := netip.MustParsePrefix("0.0.0.0/0")
	def6 := netip.MustParsePrefix("::/0")
	gwA := netip.MustParseAddr("192.168.1.1")
	gwB := netip.MustParseAddr("10.0.0.1")
	gw6A := netip.MustParseAddr("fe80::1")
	gw6B := netip.MustParseAddr("fe80::2")

	tests := []struct {
		name string
		rows []defaultRouteCandidate
		v6   bool
		want int
	}{
		{
			name: "no rows",
			want: -1,
		},
		{
			name: "lowest metric ipv4 default wins",
			rows: []defaultRouteCandidate{
				{Destination: def4, NextHop: gwA, Metric: 50},
				{Destination: def4, NextHop: gwB, Metric: 25},
			},
			want: 1,
		},
		{
			name: "equal metric keeps the first row",
			rows: []defaultRouteCandidate{
				{Destination: def4, NextHop: gwA, Metric: 25},
				{Destination: def4, NextHop: gwB, Metric: 25},
			},
			want: 0,
		},
		{
			name: "tunnel, on-link and non-default rows are skipped",
			rows: []defaultRouteCandidate{
				{Destination: def4, NextHop: gwB, Metric: 1, Tunnel: true},
				{Destination: def4, NextHop: netip.IPv4Unspecified(), Metric: 2},
				{Destination: def4, Metric: 3},
				{Destination: netip.MustParsePrefix("10.0.0.0/8"), NextHop: gwB, Metric: 4},
				{Destination: def4, NextHop: gwA, Metric: 90},
			},
			want: 4,
		},
		{
			name: "ipv4 lookup ignores ipv6 defaults",
			rows: []defaultRouteCandidate{
				{Destination: def6, NextHop: gw6A, Metric: 1},
				{Destination: def4, NextHop: gwA, Metric: 50},
			},
			want: 1,
		},
		{
			name: "ipv6 lookup picks lowest metric ::/0 via link-local gateway",
			rows: []defaultRouteCandidate{
				{Destination: def4, NextHop: gwA, Metric: 1},
				{Destination: def6, NextHop: gw6A, Metric: 40},
				{Destination: def6, NextHop: gw6B, Metric: 30},
			},
			v6:   true,
			want: 2,
		},
		{
			name: "ipv6 lookup skips tunnel, on-link, non-default and mismatched next hop",
			rows: []defaultRouteCandidate{
				{Destination: def6, NextHop: gw6A, Metric: 1, Tunnel: true},
				{Destination: def6, NextHop: netip.IPv6Unspecified(), Metric: 2},
				{Destination: def6, NextHop: gwA, Metric: 3},
				{Destination: netip.MustParsePrefix("2000::/3"), NextHop: gw6B, Metric: 4},
			},
			v6:   true,
			want: -1,
		},
		{
			name: "ipv4-only host has no ipv6 gateway",
			rows: []defaultRouteCandidate{
				{Destination: def4, NextHop: gwA, Metric: 1},
			},
			v6:   true,
			want: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickDefaultGateway(tc.rows, tc.v6); got != tc.want {
				t.Errorf("pickDefaultGateway() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestApplyWindowsRoutesRollbackOrder(t *testing.T) {
	gw4 := netip.MustParseAddr("192.168.1.1")
	gw6 := netip.MustParseAddr("fe80::1")
	bypass := []netip.Addr{
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("2001:db8::10"),
	}
	dualStackPlan := windowsRoutePlan(
		Config{Dev: "OpenSASE", IPv4: "100.64.0.2", IPv6: "fd7a:5a5e::2/128", MTU: 1280},
		bypass, gw4, gw6, true,
	)
	blackholePlan := windowsRoutePlan(
		Config{Dev: "OpenSASE", IPv4: "100.64.0.2", MTU: 1280},
		bypass, gw4, gw6, true,
	)

	tests := []struct {
		name         string
		routes       []plannedRoute
		failOnPrefix string
		wantErr      bool
		wantSetup    []string
		wantUndo     []string
	}{
		{
			name:   "normal disconnect removes tunnel routes before bypass routes in reverse order",
			routes: dualStackPlan,
			wantSetup: []string{
				"add-bypass:198.51.100.10/32",
				"add-bypass:2001:db8::10/128",
				"add-tun:0.0.0.0/1",
				"add-tun:128.0.0.0/1",
				"add-tun:::/1",
				"add-tun:8000::/1",
			},
			wantUndo: []string{
				"del-tun:8000::/1",
				"del-tun:::/1",
				"del-tun:128.0.0.0/1",
				"del-tun:0.0.0.0/1",
				"del-bypass:2001:db8::10/128",
				"del-bypass:198.51.100.10/32",
			},
		},
		{
			name:         "failure on IPv6 tunnel route rolls back tunnel routes then bypass routes in reverse order",
			routes:       dualStackPlan,
			failOnPrefix: "8000::/1",
			wantErr:      true,
			wantSetup: []string{
				"add-bypass:198.51.100.10/32",
				"add-bypass:2001:db8::10/128",
				"add-tun:0.0.0.0/1",
				"add-tun:128.0.0.0/1",
				"add-tun:::/1",
				"add-tun:8000::/1",
				"del-tun:::/1",
				"del-tun:128.0.0.0/1",
				"del-tun:0.0.0.0/1",
				"del-bypass:2001:db8::10/128",
				"del-bypass:198.51.100.10/32",
			},
		},
		{
			name:         "failure on IPv6 blackhole route rolls back earlier tunnel and bypass routes in reverse order",
			routes:       blackholePlan,
			failOnPrefix: "::/1",
			wantErr:      true,
			wantSetup: []string{
				"add-bypass:198.51.100.10/32",
				"add-bypass:2001:db8::10/128",
				"add-tun:0.0.0.0/1",
				"add-tun:128.0.0.0/1",
				"add-tun:::/1",
				"del-tun:128.0.0.0/1",
				"del-tun:0.0.0.0/1",
				"del-bypass:2001:db8::10/128",
				"del-bypass:198.51.100.10/32",
			},
		},
		{
			name:         "failure on second bypass route rolls back first bypass route only",
			routes:       dualStackPlan,
			failOnPrefix: "2001:db8::10/128",
			wantErr:      true,
			wantSetup: []string{
				"add-bypass:198.51.100.10/32",
				"add-bypass:2001:db8::10/128",
				"del-bypass:198.51.100.10/32",
			},
		},
		{
			name:         "failure on first route performs no deletions",
			routes:       dualStackPlan,
			failOnPrefix: "198.51.100.10/32",
			wantErr:      true,
			wantSetup: []string{
				"add-bypass:198.51.100.10/32",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			ops := windowsRouteOps{
				addTunnel: func(r plannedRoute) error {
					p := r.Destination.String()
					events = append(events, "add-tun:"+p)
					if p == tc.failOnPrefix {
						return errors.New("simulated add tunnel route error")
					}
					return nil
				},
				deleteTunnel: func(r plannedRoute) {
					events = append(events, "del-tun:"+r.Destination.String())
				},
				addBypass: func(r plannedRoute) error {
					p := r.Destination.String()
					events = append(events, "add-bypass:"+p)
					if p == tc.failOnPrefix {
						return errors.New("simulated add bypass route error")
					}
					return nil
				},
				deleteBypass: func(r plannedRoute) {
					events = append(events, "del-bypass:"+r.Destination.String())
				},
			}

			undo, err := applyWindowsRoutes(tc.routes, ops)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !slices.Equal(events, tc.wantSetup) {
				t.Errorf("setup events:\ngot:  %v\nwant: %v", events, tc.wantSetup)
			}
			if tc.wantErr {
				return
			}

			events = nil
			undo()
			if !slices.Equal(events, tc.wantUndo) {
				t.Errorf("undo events:\ngot:  %v\nwant: %v", events, tc.wantUndo)
			}

			// Calling undo a second time must be a no-op.
			events = nil
			undo()
			if len(events) != 0 {
				t.Errorf("second undo produced unexpected events: %v", events)
			}
		})
	}
}

func TestRollbackStackOrder(t *testing.T) {
	tests := []struct {
		name  string
		steps []string
		want  []string
	}{
		{
			name:  "full teardown runs in LIFO order",
			steps: []string{"dns4", "dns6", "flush-routes", "routes", "nrpt", "killswitch"},
			want:  []string{"killswitch", "nrpt", "routes", "flush-routes", "dns6", "dns4"},
		},
		{
			name:  "empty stack is a no-op",
			steps: nil,
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rb rollbackStack
			var got []string
			rb.push(nil)
			for _, label := range tc.steps {
				rb.push(func() {
					got = append(got, label)
				})
			}
			rb.run()
			if !slices.Equal(got, tc.want) {
				t.Errorf("rollback order: got %v, want %v", got, tc.want)
			}
			got = nil
			rb.run()
			if len(got) != 0 {
				t.Errorf("second run produced unexpected calls: %v", got)
			}
		})
	}
}

func TestSplitTunnelDNSAndNRPT(t *testing.T) {
	v4 := netip.MustParseAddr("100.64.0.1")
	v6 := netip.MustParseAddr("fd7a:5a5e::1")

	tests := []struct {
		name      string
		servers   []string
		includeV6 bool
		want4     []netip.Addr
		want6     []netip.Addr
		wantAll   []netip.Addr
		wantNRPT  string
	}{
		{
			name:      "dual-stack splits, unmaps, strips zones and deduplicates",
			servers:   []string{" 100.64.0.1 ", "fd7a:5a5e::1", "::ffff:100.64.0.1", "fd7a:5a5e::1%eth0", "not-an-ip"},
			includeV6: true,
			want4:     []netip.Addr{v4},
			want6:     []netip.Addr{v6},
			wantAll:   []netip.Addr{v4, v6},
			wantNRPT:  "100.64.0.1;fd7a:5a5e::1",
		},
		{
			name:      "no tunnel IPv6 omits IPv6 resolvers so NRPT does not target blackholed IPv6",
			servers:   []string{"100.64.0.1", "fd7a:5a5e::1"},
			includeV6: false,
			want4:     []netip.Addr{v4},
			want6:     nil,
			wantAll:   []netip.Addr{v4},
			wantNRPT:  "100.64.0.1",
		},
		{
			name:      "empty or invalid servers",
			servers:   []string{"", "bad"},
			includeV6: true,
			want4:     nil,
			want6:     nil,
			wantAll:   nil,
			wantNRPT:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got4, got6, gotAll := splitTunnelDNS(tc.servers, tc.includeV6)
			if !slices.Equal(got4, tc.want4) {
				t.Errorf("dns4: got %v, want %v", got4, tc.want4)
			}
			if !slices.Equal(got6, tc.want6) {
				t.Errorf("dns6: got %v, want %v", got6, tc.want6)
			}
			if !slices.Equal(gotAll, tc.wantAll) {
				t.Errorf("all: got %v, want %v", gotAll, tc.wantAll)
			}
			if gotNRPT := formatNRPTServers(gotAll); gotNRPT != tc.wantNRPT {
				t.Errorf("formatNRPTServers: got %q, want %q", gotNRPT, tc.wantNRPT)
			}
		})
	}
}

func TestTunnelRouteNextHop(t *testing.T) {
	explicit := netip.MustParseAddr("100.64.0.1")
	tests := []struct {
		name  string
		route plannedRoute
		want  netip.Addr
	}{
		{
			name:  "IPv4 tunnel route defaults to 0.0.0.0",
			route: plannedRoute{Destination: netip.MustParsePrefix("0.0.0.0/1"), Tunnel: true},
			want:  netip.IPv4Unspecified(),
		},
		{
			name:  "IPv6 tunnel route defaults to ::",
			route: plannedRoute{Destination: netip.MustParsePrefix("::/1"), Tunnel: true},
			want:  netip.IPv6Unspecified(),
		},
		{
			name:  "explicit next hop is preserved",
			route: plannedRoute{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: explicit, Tunnel: true},
			want:  explicit,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tunnelRouteNextHop(tc.route); got != tc.want {
				t.Errorf("tunnelRouteNextHop() = %s, want %s", got, tc.want)
			}
		})
	}
}
