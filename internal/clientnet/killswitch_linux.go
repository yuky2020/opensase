package clientnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// Linux kill switch (issue #79): while the tunnel is up, an nftables table of its own drops
// every packet that leaves outside the tunnel, except to the Edge and Control Plane
// addresses (bypass hosts), loopback, DHCP and IPv6 neighbour discovery. Removing the table
// on disconnect restores normal traffic. If the daemon dies, the table stays and the machine
// stays offline until `opensase disconnect` or a reboot (the table is not persistent).

const ksTable = "opensase_killswitch"

// killSwitchScript returns the nft script installing the kill switch.
func killSwitchScript(tunDev string, allow []netip.Addr) string {
	var v4, v6 []string
	for _, a := range allow {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	var b strings.Builder
	// Delete-and-create in one transaction: re-running replaces the old rules atomically.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n", ksTable, ksTable, ksTable)
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority 0; policy drop;\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	fmt.Fprintf(&b, "\t\toifname %q accept\n", tunDev)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } accept\n", strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } accept\n", strings.Join(v6, ", "))
	}
	b.WriteString("\t\tudp sport 68 udp dport 67 accept\n")
	b.WriteString("\t\tudp sport 546 udp dport 547 accept\n")
	b.WriteString("\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
	b.WriteString("\t\treject\n\t}\n}\n")
	return b.String()
}

// resolveAllow resolves the bypass hosts to the addresses the kill switch lets through.
func resolveAllow(ctx context.Context, hosts []string) []netip.Addr {
	var out []netip.Addr
	for _, h := range hosts {
		if a, err := netip.ParseAddr(h); err == nil {
			out = append(out, a.Unmap())
			continue
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		if err != nil {
			continue
		}
		for _, a := range ips {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// lookNft checks that nft is installed; a variable so tests can skip the check.
var lookNft = func() error { _, err := exec.LookPath("nft"); return err }

// nft runs nft with a script on stdin; a variable so tests can record it.
var nft = func(ctx context.Context, script string, args ...string) error {
	cmd := exec.CommandContext(ctx, "nft", args...) //nolint:gosec // G204: fixed binary and arguments
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// enableKillSwitch installs the kill switch and returns the function that removes it.
func enableKillSwitch(ctx context.Context, tunDev string, allow []netip.Addr, log *slog.Logger) (func(), error) {
	if lookNft() != nil {
		return nil, errors.New("nft not found: install nftables, or turn the kill switch off with the tenant policy's disableKillSwitch")
	}
	if err := nft(ctx, killSwitchScript(tunDev, allow), "-f", "-"); err != nil {
		return nil, err
	}
	log.Info("kill switch on: traffic outside the tunnel is blocked", "allowed", len(allow))
	return func() { //nolint:contextcheck // runs at teardown, after the connect request's context is gone
		if err := nft(context.Background(), fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", ksTable, ksTable), "-f", "-"); err != nil {
			log.Error("kill switch not removed; run: nft delete table inet "+ksTable, "err", err)
			return
		}
		log.Info("kill switch off")
	}, nil
}

func cleanupKillSwitchPlatform(ctx context.Context) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	return nft(ctx, fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", ksTable, ksTable), "-f", "-")
}
