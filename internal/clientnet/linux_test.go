//go:build linux

package clientnet

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRouteCommands(t *testing.T) {
	ctx := context.Background()
	cmds, err := routeCommands(ctx, "osase0", "100.64.0.2/32", "fd00::2/128", 1420, []string{"127.0.0.1"})
	if err != nil {
		// If running in a test container without default route, routeCommands returns error.
		t.Logf("routeCommands returned err (no default gateway in test environment): %v", err)
		return
	}
	if len(cmds) < 4 {
		t.Fatalf("expected at least 4 commands, got %d", len(cmds))
	}
	var foundAddr4, foundAddr6, foundUp, foundSplit1, foundSplit2 bool
	for _, c := range cmds {
		s := strings.Join(c.args, " ")
		if strings.Contains(s, "address replace 100.64.0.2/32 dev osase0") {
			foundAddr4 = true
		}
		if strings.Contains(s, "-6 address replace fd00::2/128 dev osase0") {
			foundAddr6 = true
		}
		if strings.Contains(s, "link set dev osase0 mtu 1420 up") {
			foundUp = true
		}
		if strings.Contains(s, "route replace 0.0.0.0/1 dev osase0") {
			foundSplit1 = true
		}
		if strings.Contains(s, "route replace 128.0.0.0/1 dev osase0") {
			foundSplit2 = true
		}
	}
	if !foundAddr4 {
		t.Errorf("missing IPv4 address command")
	}
	if !foundAddr6 {
		t.Errorf("missing IPv6 address command")
	}
	if !foundUp {
		t.Errorf("missing link up command")
	}
	if !foundSplit1 || !foundSplit2 {
		t.Errorf("missing split route commands")
	}
}

func joinIPCmds(cmds []ipCmd) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = strings.Join(c.args, " ")
	}
	return out
}

func joinUndoCmds(cmds []ipCmd) []string {
	var out []string
	for _, c := range cmds {
		if len(c.undoArgs) > 0 {
			out = append(out, strings.Join(c.undoArgs, " "))
		}
	}
	return out
}

func fixedGW(gw, dev string, err error) func(context.Context) (string, string, error) {
	return func(context.Context) (string, string, error) {
		return gw, dev, err
	}
}

func fixedLookup(m map[string][]netip.Addr) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		addrs, ok := m[host]
		if !ok {
			return nil, errors.New("host not found")
		}
		return addrs, nil
	}
}

func fixedBool(v bool) func() bool {
	return func() bool { return v }
}

func TestRouteCommandsIPv6Bypass(t *testing.T) {
	ip4A := netip.MustParseAddr("198.51.100.10")
	ip6A := netip.MustParseAddr("2001:db8::10")
	noGW6 := errors.New("no IPv6 default route")

	tests := []struct {
		name     string
		bypass   []string
		deps     routeDeps
		wantCmds []string
		wantUndo []string
	}{
		{
			name:   "dual-stack bypass hostname via gateway",
			bypass: []string{"edge.example.test"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("fe80::1", "eth0", nil),
				lookupIP:    fixedLookup(map[string][]netip.Addr{"edge.example.test": {ip4A, ip6A}}),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
			},
		},
		{
			name:   "on-link IPv6 gateway omits via",
			bypass: []string{"2001:db8::20"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("", "eth0", nil),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"-6 route replace 2001:db8::20/128 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"-6 route del 2001:db8::20/128 dev eth0",
			},
		},
		{
			name:   "duplicate and v4-mapped bypass addresses deduplicated",
			bypass: []string{"edge.example.test", "2001:db8::10", "::ffff:198.51.100.10"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("fe80::1", "eth0", nil),
				lookupIP:    fixedLookup(map[string][]netip.Addr{"edge.example.test": {ip4A, ip6A, ip6A}}),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
			},
		},
		{
			name:   "ipv4-only host skips IPv6 bypass route",
			bypass: []string{"edge.example.test"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("", "", noGW6),
				lookupIP:    fixedLookup(map[string][]netip.Addr{"edge.example.test": {ip4A, ip6A}}),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmds, err := routeCommandsWith(context.Background(), "osase0", "100.64.0.2/32", "fd7a:5a5e::2/128", 1280, tc.bypass, tc.deps)
			if err != nil {
				t.Fatalf("routeCommandsWith: %v", err)
			}
			if got := joinIPCmds(cmds); !slices.Equal(got, tc.wantCmds) {
				t.Errorf("cmds:\ngot:  %v\nwant: %v", got, tc.wantCmds)
			}
			if got := joinUndoCmds(cmds); !slices.Equal(got, tc.wantUndo) {
				t.Errorf("undo:\ngot:  %v\nwant: %v", got, tc.wantUndo)
			}
		})
	}
}

func TestRouteCommandsIPv6OnlyHost(t *testing.T) {
	ip4A := netip.MustParseAddr("198.51.100.10")
	ip6A := netip.MustParseAddr("2001:db8::10")
	noGW4 := errors.New("no IPv4 default route")
	noGW6 := errors.New("no IPv6 default route")

	tests := []struct {
		name     string
		bypass   []string
		deps     routeDeps
		wantCmds []string
		wantUndo []string
		wantErr  bool
	}{
		{
			name:   "IPv6-only host installs v6 bypass and dual-stack tunnel routes",
			bypass: []string{"edge.example.test"},
			deps: routeDeps{
				defaultGW4:  fixedGW("", "", noGW4),
				defaultGW6:  fixedGW("fe80::1", "eth0", nil),
				lookupIP:    fixedLookup(map[string][]netip.Addr{"edge.example.test": {ip4A, ip6A}}),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
			},
		},
		{
			name:   "IPv6-only host with on-link default route",
			bypass: []string{"2001:db8::5"},
			deps: routeDeps{
				defaultGW4:  fixedGW("", "", noGW4),
				defaultGW6:  fixedGW("", "enp1s0", nil),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"-6 route replace 2001:db8::5/128 dev enp1s0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"-6 route del 2001:db8::5/128 dev enp1s0",
			},
		},
		{
			name:   "neither IPv4 nor IPv6 default route fails",
			bypass: []string{"2001:db8::5"},
			deps: routeDeps{
				defaultGW4:  fixedGW("", "", noGW4),
				defaultGW6:  fixedGW("", "", noGW6),
				ipv6Enabled: fixedBool(true),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmds, err := routeCommandsWith(context.Background(), "osase0", "100.64.0.2/32", "fd7a:5a5e::2/128", 1280, tc.bypass, tc.deps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got := joinIPCmds(cmds); !slices.Equal(got, tc.wantCmds) {
				t.Errorf("cmds:\ngot:  %v\nwant: %v", got, tc.wantCmds)
			}
			if got := joinUndoCmds(cmds); !slices.Equal(got, tc.wantUndo) {
				t.Errorf("undo:\ngot:  %v\nwant: %v", got, tc.wantUndo)
			}
		})
	}
}

func TestRouteCommandsNoTunnelIPv6Blackhole(t *testing.T) {
	noGW6 := errors.New("no IPv6 default route")

	tests := []struct {
		name     string
		bypass   []string
		deps     routeDeps
		wantCmds []string
		wantUndo []string
	}{
		{
			name:   "kernel IPv6 enabled installs unreachable split routes and keeps v6 bypass",
			bypass: []string{"198.51.100.10", "2001:db8::10"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("fe80::1", "eth0", nil),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace unreachable ::/1",
				"-6 route replace unreachable 8000::/1",
			},
			wantUndo: []string{
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
				"-6 route del unreachable ::/1",
				"-6 route del unreachable 8000::/1",
			},
		},
		{
			name:   "kernel IPv6 enabled without v6 default route still installs unreachable split routes",
			bypass: []string{"198.51.100.10"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("", "", noGW6),
				ipv6Enabled: fixedBool(true),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace unreachable ::/1",
				"-6 route replace unreachable 8000::/1",
			},
			wantUndo: []string{
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route del unreachable ::/1",
				"-6 route del unreachable 8000::/1",
			},
		},
		{
			name:   "kernel IPv6 disabled omits unreachable split routes",
			bypass: []string{"198.51.100.10"},
			deps: routeDeps{
				defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
				defaultGW6:  fixedGW("", "", noGW6),
				ipv6Enabled: fixedBool(false),
			},
			wantCmds: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
			},
			wantUndo: []string{
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmds, err := routeCommandsWith(context.Background(), "osase0", "100.64.0.2/32", "", 1280, tc.bypass, tc.deps)
			if err != nil {
				t.Fatalf("routeCommandsWith: %v", err)
			}
			if got := joinIPCmds(cmds); !slices.Equal(got, tc.wantCmds) {
				t.Errorf("cmds:\ngot:  %v\nwant: %v", got, tc.wantCmds)
			}
			if got := joinUndoCmds(cmds); !slices.Equal(got, tc.wantUndo) {
				t.Errorf("undo:\ngot:  %v\nwant: %v", got, tc.wantUndo)
			}
			for _, cmd := range cmds {
				if cmd.optional {
					t.Errorf("unexpected optional command %q", strings.Join(cmd.args, " "))
				}
			}
		})
	}
}

func TestParseDefaultRoute(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		wantGW  string
		wantDev string
	}{
		{
			name:    "IPv4 via gateway",
			out:     "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
			wantGW:  "192.168.1.1",
			wantDev: "eth0",
		},
		{
			name:    "IPv4 on-link",
			out:     "default dev ppp0 scope link\n",
			wantGW:  "",
			wantDev: "ppp0",
		},
		{
			name:    "IPv6 link-local gateway",
			out:     "default via fe80::1 dev eth0 proto ra metric 100 pref medium\n",
			wantGW:  "fe80::1",
			wantDev: "eth0",
		},
		{
			name:    "IPv6 on-link",
			out:     "default dev eth0 metric 1024 pref medium\n",
			wantGW:  "",
			wantDev: "eth0",
		},
		{
			name:    "multiple default routes keeps first line pair",
			out:     "default via fe80::1 dev eth0 metric 100\ndefault via fe80::2 dev wlan0 metric 600\n",
			wantGW:  "fe80::1",
			wantDev: "eth0",
		},
		{
			name:    "source-routed IPv6 default",
			out:     "default from 2001:db8:1::/64 via fe80::1 dev eth0 proto ra metric 1024\n",
			wantGW:  "fe80::1",
			wantDev: "eth0",
		},
		{
			name:    "unreachable default ignored",
			out:     "unreachable default dev lo metric 4294967295\n",
			wantGW:  "",
			wantDev: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw, dev := parseDefaultRoute([]byte(tc.out))
			if gw != tc.wantGW || dev != tc.wantDev {
				t.Errorf("parseDefaultRoute = (%q, %q), want (%q, %q)", gw, dev, tc.wantGW, tc.wantDev)
			}
		})
	}
}

func TestIPv6EnabledFile(t *testing.T) {
	dir := t.TempDir()
	enabled := filepath.Join(dir, "enabled")
	disabled := filepath.Join(dir, "disabled")
	if err := os.WriteFile(enabled, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disabled, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "disable_ipv6=0", path: enabled, want: true},
		{name: "disable_ipv6=1", path: disabled, want: false},
		{name: "missing sysctl", path: filepath.Join(dir, "missing"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ipv6EnabledFile(tc.path); got != tc.want {
				t.Errorf("ipv6EnabledFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestApplyIPCommandsTeardownAndFallback(t *testing.T) {
	deps := routeDeps{
		defaultGW4:  fixedGW("192.168.1.1", "eth0", nil),
		defaultGW6:  fixedGW("fe80::1", "eth0", nil),
		ipv6Enabled: fixedBool(true),
	}
	cmds, err := routeCommandsWith(context.Background(), "osase0", "100.64.0.2/32", "fd7a:5a5e::2/128", 1280, []string{"198.51.100.10", "2001:db8::10"}, deps)
	if err != nil {
		t.Fatalf("routeCommandsWith: %v", err)
	}

	tests := []struct {
		name      string
		failMatch []string
		wantErr   bool
		wantRan   []string
		wantUndo  []string
	}{
		{
			name: "normal teardown removes bypass routes in reverse order",
			wantRan: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace ::/1 dev osase0",
				"-6 route replace 8000::/1 dev osase0",
			},
			wantUndo: []string{
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
			},
		},
		{
			name:      "partial setup failure rolls back already-installed bypass routes",
			failMatch: []string{"route replace 0.0.0.0/1 dev osase0"},
			wantErr:   true,
			wantRan: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
			},
		},
		{
			name:      "tunnel IPv6 failure falls back to unreachable split routes",
			failMatch: []string{"-6 address replace fd7a:5a5e::2/128 dev osase0"},
			wantRan: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace unreachable ::/1",
				"-6 route replace unreachable 8000::/1",
			},
			wantUndo: []string{
				"-6 route del unreachable 8000::/1",
				"-6 route del unreachable ::/1",
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
			},
		},
		{
			name:      "tunnel IPv6 and unreachable fallback failure rolls back all routes",
			failMatch: []string{"-6 address replace fd7a:5a5e::2/128 dev osase0", "-6 route replace unreachable 8000::/1"},
			wantErr:   true,
			wantRan: []string{
				"address replace 100.64.0.2/32 dev osase0",
				"-6 address replace fd7a:5a5e::2/128 dev osase0",
				"link set dev osase0 mtu 1280 up",
				"route replace 198.51.100.10/32 via 192.168.1.1 dev eth0",
				"-6 route replace 2001:db8::10/128 via fe80::1 dev eth0",
				"route replace 0.0.0.0/1 dev osase0",
				"route replace 128.0.0.0/1 dev osase0",
				"-6 route replace unreachable ::/1",
				"-6 route replace unreachable 8000::/1",
				"-6 route del unreachable ::/1",
				"-6 route del 2001:db8::10/128 via fe80::1 dev eth0",
				"route del 198.51.100.10/32 via 192.168.1.1 dev eth0",
			},
		},
	}

	log := slog.New(slog.DiscardHandler)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ran []string
			runner := func(_ context.Context, c ipCmd, _ *slog.Logger) error {
				line := strings.Join(c.args, " ")
				ran = append(ran, line)
				if slices.Contains(tc.failMatch, line) {
					return errors.New("simulated ip failure")
				}
				return nil
			}
			undo, err := applyIPCommands(context.Background(), cmds, runner, log)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !slices.Equal(ran, tc.wantRan) {
				t.Errorf("setup calls:\ngot:  %v\nwant: %v", ran, tc.wantRan)
			}
			if tc.wantErr {
				return
			}
			ran = nil
			undo()
			if !slices.Equal(ran, tc.wantUndo) {
				t.Errorf("undo calls:\ngot:  %v\nwant: %v", ran, tc.wantUndo)
			}
		})
	}
}

func TestSetResolvConfFallback(t *testing.T) {
	tests := []struct {
		name         string
		initial      string
		hasInitial   bool
		initialBak   string
		hasBak       bool
		servers      []string
		wantOK       bool
		wantActive   string
		wantRestored string
		wantExists   bool
	}{
		{
			name:         "writes dual-stack nameservers and restores original",
			initial:      "nameserver 192.168.1.1\n",
			hasInitial:   true,
			servers:      []string{"100.64.0.1", "fd7a:5a5e::1", "100.64.0.1"},
			wantOK:       true,
			wantActive:   resolvConfMarker + "\nnameserver 100.64.0.1\nnameserver fd7a:5a5e::1\n",
			wantRestored: "nameserver 192.168.1.1\n",
			wantExists:   true,
		},
		{
			name:         "restart after crash preserves original backup",
			initial:      resolvConfMarker + "\nnameserver 100.64.0.1\n",
			hasInitial:   true,
			initialBak:   "nameserver 192.168.1.53\n",
			hasBak:       true,
			servers:      []string{"100.64.0.1", "fd7a:5a5e::1"},
			wantOK:       true,
			wantActive:   resolvConfMarker + "\nnameserver 100.64.0.1\nnameserver fd7a:5a5e::1\n",
			wantRestored: "nameserver 192.168.1.53\n",
			wantExists:   true,
		},
		{
			name:       "creates resolv.conf when absent and removes on undo",
			hasInitial: false,
			servers:    []string{"100.64.0.1"},
			wantOK:     true,
			wantActive: resolvConfMarker + "\nnameserver 100.64.0.1\n",
			wantExists: false,
		},
		{
			name:         "invalid servers leave resolv.conf untouched",
			initial:      "nameserver 192.168.1.1\n",
			hasInitial:   true,
			servers:      []string{"not-an-ip"},
			wantOK:       false,
			wantRestored: "nameserver 192.168.1.1\n",
			wantExists:   true,
		},
	}

	log := slog.New(slog.DiscardHandler)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			resolvPath := filepath.Join(dir, "resolv.conf")
			backupPath := filepath.Join(dir, "resolv.conf.opensase.bak")
			if tc.hasInitial {
				if err := os.WriteFile(resolvPath, []byte(tc.initial), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.hasBak {
				if err := os.WriteFile(backupPath, []byte(tc.initialBak), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			undo, ok := setResolvConfFallback(resolvPath, backupPath, tc.servers, log)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				got, err := os.ReadFile(resolvPath)
				if err != nil {
					t.Fatalf("read resolv.conf: %v", err)
				}
				if string(got) != tc.wantRestored {
					t.Errorf("resolv.conf modified: got %q, want %q", got, tc.wantRestored)
				}
				return
			}

			gotActive, err := os.ReadFile(resolvPath)
			if err != nil {
				t.Fatalf("read active resolv.conf: %v", err)
			}
			if string(gotActive) != tc.wantActive {
				t.Errorf("active resolv.conf:\ngot:  %q\nwant: %q", gotActive, tc.wantActive)
			}

			undo()

			if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("backup file still exists after undo: err=%v", err)
			}
			gotAfter, err := os.ReadFile(resolvPath)
			if tc.wantExists {
				if err != nil {
					t.Fatalf("read restored resolv.conf: %v", err)
				}
				if string(gotAfter) != tc.wantRestored {
					t.Errorf("restored resolv.conf:\ngot:  %q\nwant: %q", gotAfter, tc.wantRestored)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Errorf("expected resolv.conf to be removed, got err=%v content=%q", err, gotAfter)
			}
		})
	}
}
