package edge

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestKernelRoutesSync(t *testing.T) {
	a, b := netip.MustParsePrefix("10.30.0.0/24"), netip.MustParsePrefix("10.40.0.0/24")
	var calls []string
	fail := false
	kr := newKernelRoutes("wg0", nil)
	kr.runner = func(_ context.Context, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if fail {
			return errors.New("boom")
		}
		return nil
	}
	steps := []struct {
		name  string
		want  []netip.Prefix
		fail  bool
		calls []string
	}{
		{"install two", []netip.Prefix{a, b}, false, []string{"route replace 10.30.0.0/24 dev wg0", "route replace 10.40.0.0/24 dev wg0"}},
		{"unchanged", []netip.Prefix{b, a}, false, nil},
		{"remove one", []netip.Prefix{b}, false, []string{"route del 10.30.0.0/24 dev wg0"}},
		{"add fails", []netip.Prefix{a, b}, true, []string{"route replace 10.30.0.0/24 dev wg0"}},
		{"retried next time", []netip.Prefix{a, b}, false, []string{"route replace 10.30.0.0/24 dev wg0"}},
		{"ipv6 ignored", []netip.Prefix{a, b, netip.MustParsePrefix("fd00::/64")}, false, nil},
	}
	for _, s := range steps {
		calls, fail = nil, s.fail
		kr.sync(context.Background(), s.want)
		if !slices.Equal(calls, s.calls) {
			t.Errorf("%s: calls %q, want %q", s.name, calls, s.calls)
		}
	}
}

func TestKernelRoutesNoTUN(t *testing.T) {
	kr := newKernelRoutes("", nil)
	kr.runner = func(context.Context, ...string) error { t.Fatal("runner called without a TUN"); return nil }
	kr.sync(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")})
}
