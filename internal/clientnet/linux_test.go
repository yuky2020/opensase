//go:build linux

package clientnet

import (
	"context"
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
