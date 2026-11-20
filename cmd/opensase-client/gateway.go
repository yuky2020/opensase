package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// Workload Gateway mode (ADR-0015): forward the traffic of the gateway CIDRs into the tunnel,
// masqueraded to the tunnel address, with workload DNS diverted to the Edge resolver, TCP MSS
// clamping, and fail-closed forwarding. All rules live in dedicated chains.

// Gateway chains and the built-in chains that jump to them.
var gatewayChains = []struct{ table, chain, from string }{
	{"filter", "OSASE_GW_FWD", "FORWARD"},
	{"nat", "OSASE_GW_NAT", "POSTROUTING"},
	{"nat", "OSASE_GW_DNS", "PREROUTING"},
	{"mangle", "OSASE_GW_MSS", "FORWARD"},
}

// parseGatewayCIDRs parses the -gateway flag: comma-separated IPv4 prefixes.
func parseGatewayCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("-gateway: %w", err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("-gateway: %s: only IPv4 subnets are forwarded (IPv6 forwarding stays off)", p)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("-gateway: %s would forward everything; list the workload subnets", p)
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("-gateway: no subnet given")
	}
	return out, nil
}

// gatewayRules returns the iptables rules (table, chain, rule args) for the gateway CIDRs.
// dns is the Edge resolver the workloads' port-53 traffic is sent to.
func gatewayRules(tun string, cidrs []netip.Prefix, dns netip.Addr) [][]string {
	r := [][]string{
		// Return traffic of forwarded connections.
		{"filter", "OSASE_GW_FWD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		// Nothing unsolicited from the tunnel into the subnets.
		{"filter", "OSASE_GW_FWD", "-i", tun, "-j", "DROP"},
	}
	for _, c := range cidrs {
		s := c.String()
		r = append(r,
			[]string{"filter", "OSASE_GW_FWD", "-s", s, "-o", tun, "-j", "ACCEPT"},
			// Fail closed: workload traffic never leaves another way.
			[]string{"filter", "OSASE_GW_FWD", "-s", s, "-j", "DROP"},
			[]string{"nat", "OSASE_GW_NAT", "-s", s, "-o", tun, "-j", "MASQUERADE"},
			[]string{"nat", "OSASE_GW_DNS", "-s", s, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dns.String() + ":53"},
			[]string{"nat", "OSASE_GW_DNS", "-s", s, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", dns.String() + ":53"},
		)
	}
	r = append(r,
		[]string{"mangle", "OSASE_GW_MSS", "-o", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		[]string{"mangle", "OSASE_GW_MSS", "-i", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	)
	return r
}

// iptables runs iptables with args; it is a variable so tests can record the calls.
var iptables = func(ctx context.Context, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "iptables", append([]string{"-w"}, args...)...) //nolint:gosec // G204: fixed binary; args are built from parsed prefixes and constants
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// setupGateway enables IPv4 forwarding and installs the gateway rules. It returns a cleanup
// function that removes them.
func setupGateway(ctx context.Context, tun string, cidrs []netip.Prefix, dns netip.Addr, log *slog.Logger) (func(), error) {
	cleanup := func() { teardownGateway(context.WithoutCancel(ctx), cidrs, log) }
	for _, c := range gatewayChains {
		// Create (or reuse after an unclean exit) and empty the chain.
		_ = iptables(ctx, "-t", c.table, "-N", c.chain)
		if err := iptables(ctx, "-t", c.table, "-F", c.chain); err != nil {
			return nil, err
		}
		if iptables(ctx, "-t", c.table, "-C", c.from, "-j", c.chain) != nil {
			if err := iptables(ctx, "-t", c.table, "-I", c.from, "1", "-j", c.chain); err != nil {
				cleanup()
				return nil, err
			}
		}
	}
	for _, r := range gatewayRules(tun, cidrs, dns) {
		if err := iptables(ctx, append([]string{"-t", r[0], "-A", r[1]}, r[2:]...)...); err != nil {
			cleanup()
			return nil, err
		}
	}
	// Forwarding goes on only once the fail-closed rules are in place.
	if err := enableForwarding(); err != nil {
		cleanup()
		return nil, err
	}
	log.Info("workload gateway active", "subnets", fmt.Sprint(cidrs), "tun", tun, "dns", dns.String())
	return cleanup, nil
}

// teardownGateway removes the NAT, DNS and MSS rules but leaves a kill switch: the filter
// chain keeps dropping forwarded traffic from the gateway subnets, so workloads never reach
// the network outside the tunnel while the gateway is down. The next start replaces it.
func teardownGateway(ctx context.Context, cidrs []netip.Prefix, log *slog.Logger) {
	for _, c := range gatewayChains {
		if c.table == "filter" {
			_ = iptables(ctx, "-t", c.table, "-F", c.chain)
			for _, p := range cidrs {
				if err := iptables(ctx, "-t", c.table, "-A", c.chain, "-s", p.String(), "-j", "DROP"); err != nil {
					log.Error("gateway kill switch not installed", "subnet", p.String(), "err", err)
				}
			}
			continue
		}
		for range 8 { // remove every jump (duplicates after unclean exits)
			if iptables(ctx, "-t", c.table, "-D", c.from, "-j", c.chain) != nil {
				break
			}
		}
		_ = iptables(ctx, "-t", c.table, "-F", c.chain)
		if err := iptables(ctx, "-t", c.table, "-X", c.chain); err != nil {
			log.Debug("gateway chain not removed", "table", c.table, "chain", c.chain, "err", err)
		}
	}
	log.Info("workload gateway stopped; forwarding from its subnets stays blocked", "subnets", fmt.Sprint(cidrs))
}

const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// enableForwarding turns IPv4 forwarding on (a container must allow it with the
// net.ipv4.ip_forward sysctl). IPv6 forwarding is deliberately left alone (off).
var enableForwarding = func() error {
	b, err := os.ReadFile(ipForwardPath)
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0o644); err != nil { //nolint:gosec // G306: procfs sysctl, mode unused
		return fmt.Errorf("enable IPv4 forwarding (%s): %w", ipForwardPath, err)
	}
	return nil
}
