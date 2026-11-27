package clientnet

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func TestKillSwitchScript(t *testing.T) {
	s := killSwitchScript("osase0", []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")})
	for _, want := range []string{
		"delete table inet opensase_killswitch",
		"policy drop;",
		`oifname "lo" accept`,
		`oifname "osase0" accept`,
		"ip daddr { 198.51.100.1, 203.0.113.9 } accept",
		"ip6 daddr { 2001:db8::1 } accept",
		"udp sport 68 udp dport 67 accept",
		"nd-neighbor-solicit",
		"reject",
		"chain forward {",
		"type filter hook forward priority 0; policy drop;",
		`iifname "osase0" accept`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(killSwitchScript("osase0", nil), "daddr") {
		t.Error("empty allow list must not produce an empty set")
	}
}

func TestKillSwitchForwardChain(t *testing.T) {
	tests := []struct {
		name      string
		tunDev    string
		allow     []netip.Addr
		wantFwd   []string
		wantOut   []string
		forbidFwd []string
	}{
		{
			name:   "default tun includes forward drop chain for tunnel only",
			tunDev: "osase0",
			allow:  []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")},
			wantFwd: []string{
				"type filter hook forward priority 0; policy drop;",
				`oifname "osase0" accept`,
				`iifname "osase0" accept`,
			},
			wantOut: []string{
				"ip daddr { 198.51.100.1 } accept",
				"ip6 daddr { 2001:db8::1 } accept",
			},
			forbidFwd: []string{"daddr", `oifname "lo"`},
		},
		{
			name:   "custom tun and duplicate/mapped/zoned allow entries normalized",
			tunDev: "tun1",
			allow: []netip.Addr{
				netip.MustParseAddr("198.51.100.1"),
				netip.MustParseAddr("::ffff:198.51.100.1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("fe80::1%eth0"),
			},
			wantFwd: []string{
				"type filter hook forward priority 0; policy drop;",
				`oifname "tun1" accept`,
				`iifname "tun1" accept`,
			},
			wantOut: []string{
				"ip daddr { 198.51.100.1 } accept",
				"ip6 daddr { 2001:db8::1, fe80::1 } accept",
			},
			forbidFwd: []string{"daddr", "%eth0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := killSwitchScript(tc.tunDev, tc.allow)
			outPart, fwdPart, ok := strings.Cut(s, "\tchain forward {\n")
			if !ok {
				t.Fatalf("script missing forward chain:\n%s", s)
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(outPart, want) {
					t.Errorf("output chain lacks %q:\n%s", want, outPart)
				}
			}
			for _, want := range tc.wantFwd {
				if !strings.Contains(fwdPart, want) {
					t.Errorf("forward chain lacks %q:\n%s", want, fwdPart)
				}
			}
			for _, forbid := range tc.forbidFwd {
				if strings.Contains(fwdPart, forbid) {
					t.Errorf("forward chain unexpectedly contains %q:\n%s", forbid, fwdPart)
				}
			}
		})
	}
}

func TestEnableKillSwitch(t *testing.T) {
	var scripts []string
	orig, origLook := nft, lookNft
	nft = func(_ context.Context, script string, _ ...string) error {
		scripts = append(scripts, script)
		return nil
	}
	lookNft = func() error { return nil }
	defer func() { nft, lookNft = orig, origLook }()
	undo, err := enableKillSwitch(context.Background(), "osase0", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	undo()
	if len(scripts) != 2 || !strings.Contains(scripts[0], "policy drop") || strings.Contains(scripts[1], "policy drop") || !strings.Contains(scripts[1], "delete table inet opensase_killswitch") {
		t.Fatalf("scripts %q", scripts)
	}
	if got := resolveAllow(context.Background(), []string{"192.0.2.7", "::ffff:192.0.2.8"}); len(got) != 2 || !got[1].Is4() {
		t.Fatalf("resolveAllow %v", got)
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
