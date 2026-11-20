package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseGatewayCIDRs(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"10.30.0.0/24", []string{"10.30.0.0/24"}, false},
		{" 10.30.0.7/24 , 192.168.1.0/24 ", []string{"10.30.0.0/24", "192.168.1.0/24"}, false},
		{"", nil, true},
		{"0.0.0.0/0", nil, true},
		{"fd00::/64", nil, true},
		{"10.30.0.0", nil, true},
	}
	for _, tc := range tests {
		got, err := parseGatewayCIDRs(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%q: err %v", tc.in, err)
		}
		var s []string
		for _, p := range got {
			s = append(s, p.String())
		}
		if !slices.Equal(s, tc.want) {
			t.Errorf("%q: %v want %v", tc.in, s, tc.want)
		}
	}
}

// fakeIPT records iptables calls; -C (check) fails so jumps are inserted.
func fakeIPT(t *testing.T, failOn string) *[]string {
	t.Helper()
	var calls []string
	old, oldFwd := iptables, enableForwarding
	t.Cleanup(func() { iptables, enableForwarding = old, oldFwd })
	iptables = func(_ context.Context, args ...string) error {
		c := strings.Join(args, " ")
		calls = append(calls, c)
		if strings.Contains(c, " -C ") || (failOn != "" && strings.Contains(c, failOn)) {
			return errors.New("no")
		}
		return nil
	}
	enableForwarding = func() error { calls = append(calls, "FORWARDING ON"); return nil }
	return &calls
}

func TestSetupGatewayRulesAndKillSwitch(t *testing.T) {
	calls := fakeIPT(t, "")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	cleanup, err := setupGateway(context.Background(), "osase0", cidrs, netip.MustParseAddr("100.64.0.1"), log)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(*calls, "\n")
	for _, want := range []string{
		"-t filter -I FORWARD 1 -j OSASE_GW_FWD",
		"-t filter -A OSASE_GW_FWD -s 10.30.0.0/24 -o osase0 -j ACCEPT",
		"-t filter -A OSASE_GW_FWD -s 10.30.0.0/24 -j DROP",
		"-t filter -A OSASE_GW_FWD -i osase0 -j DROP",
		"-t nat -A OSASE_GW_NAT -s 10.30.0.0/24 -o osase0 -j MASQUERADE",
		"-t nat -A OSASE_GW_DNS -s 10.30.0.0/24 -p udp --dport 53 -j DNAT --to-destination 100.64.0.1:53",
		"-t mangle -A OSASE_GW_MSS -o osase0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
	// ACCEPT via the tunnel comes before the subnet DROP; forwarding goes on last.
	if strings.Index(all, "-o osase0 -j ACCEPT") > strings.Index(all, "-s 10.30.0.0/24 -j DROP") {
		t.Error("DROP before ACCEPT")
	}
	if (*calls)[len(*calls)-1] != "FORWARDING ON" {
		t.Errorf("forwarding not enabled last: %v", (*calls)[len(*calls)-1])
	}

	*calls = nil
	cleanup()
	all = strings.Join(*calls, "\n")
	if strings.Contains(all, "-D FORWARD -j OSASE_GW_FWD") || strings.Contains(all, "-X OSASE_GW_FWD") {
		t.Error("kill switch chain removed")
	}
	for _, want := range []string{"-t filter -A OSASE_GW_FWD -s 10.30.0.0/24 -j DROP", "-t nat -X OSASE_GW_NAT", "-t mangle -X OSASE_GW_MSS"} {
		if !strings.Contains(all, want) {
			t.Errorf("teardown missing %q", want)
		}
	}
}

func TestSetupGatewayFailureKeepsForwardingOff(t *testing.T) {
	calls := fakeIPT(t, "MASQUERADE")
	_, err := setupGateway(context.Background(), "osase0", []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}, netip.MustParseAddr("100.64.0.1"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("want error")
	}
	if slices.Contains(*calls, "FORWARDING ON") {
		t.Fatal("forwarding enabled after a failed setup")
	}
}
