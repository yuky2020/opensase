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
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(killSwitchScript("osase0", nil), "daddr") {
		t.Error("empty allow list must not produce an empty set")
	}
}

func TestEnableKillSwitch(t *testing.T) {
	var scripts []string
	orig, origLook := nft, lookNft
	nft = func(_ context.Context, script string, _ ...string) error { scripts = append(scripts, script); return nil }
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
