//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	defaultTUNName  = "osase0"
	defaultHostname = "linux-client"
)

func gatewaySupported() bool {
	return true
}

func checkTUNPrerequisites() error {
	return nil
}

type ipCmd struct {
	args     []string
	optional bool // IPv6 steps: tolerated when IPv6 is disabled in the container
}

// routeCommands builds the ip(8) commands: interface address, host routes for the bypass
// hosts via the current IPv4 default gateway, then 0.0.0.0/1 + 128.0.0.0/1 (and ::/1 +
// 8000::/1) into the TUN, which override the default route without deleting it.
func routeCommands(ctx context.Context, dev, ipv4, ipv6 string, mtu int, bypass []string) ([]ipCmd, error) {
	var cmds []ipCmd
	add := func(optional bool, args ...string) { cmds = append(cmds, ipCmd{args: args, optional: optional}) }
	if ipv4 == "" {
		return nil, errors.New("session returned no tunnel IPv4 address")
	}
	add(false, "address", "replace", ipv4, "dev", dev)
	if ipv6 != "" {
		add(true, "-6", "address", "replace", ipv6, "dev", dev)
	}
	add(false, "link", "set", "dev", dev, "mtu", fmt.Sprint(mtu), "up")

	gw, gwDev, err := defaultGateway(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range bypass {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
		if err != nil {
			// Not fatal: the Edge must work while the Control Plane is unreachable (ADR-0014).
			// The session is already up, so the Edge host resolved; an unresolvable Control
			// Plane host just gets no bypass route, and reaches it through the tunnel later.
			slog.WarnContext(ctx, "bypass host does not resolve; no bypass route", "host", h, "err", err)
			continue
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				if gw != "" {
					add(false, "route", "replace", ip4.String()+"/32", "via", gw, "dev", gwDev)
				} else {
					add(false, "route", "replace", ip4.String()+"/32", "dev", gwDev)
				}
			}
		}
	}
	add(false, "route", "replace", "0.0.0.0/1", "dev", dev)
	add(false, "route", "replace", "128.0.0.0/1", "dev", dev)
	if ipv6 != "" {
		add(true, "-6", "route", "replace", "::/1", "dev", dev)
		add(true, "-6", "route", "replace", "8000::/1", "dev", dev)
	}
	return cmds, nil
}

// defaultGateway parses `ip -4 route show default`.
func defaultGateway(ctx context.Context) (gw, dev string, err error) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route show default: %w", err)
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			if dev == "" {
				dev = f[i+1]
			}
		}
	}
	if dev == "" {
		return "", "", errors.New("no IPv4 default route to reach the Control Plane and Edge")
	}
	return gw, dev, nil
}

func runIP(ctx context.Context, c ipCmd, log *slog.Logger) error {
	out, err := exec.CommandContext(ctx, "ip", c.args...).CombinedOutput() //nolint:gosec // G204: fixed binary; args built by routeCommands from the session config
	if err != nil {
		lvl := slog.LevelError
		if c.optional {
			lvl = slog.LevelWarn
		}
		log.Log(ctx, lvl, "ip command failed", "cmd", "ip "+strings.Join(c.args, " "), "err", err, "out", strings.TrimSpace(string(out)))
		return fmt.Errorf("ip %s: %w", strings.Join(c.args, " "), err)
	}
	log.Info("configured", "cmd", "ip "+strings.Join(c.args, " "))
	return nil
}

func configureNetwork(ctx context.Context, _ tun.Device, c netConfig) (undo func(), err error) {
	cmds, err := routeCommands(ctx, c.Dev, c.IPv4, c.IPv6, c.MTU, c.Bypass)
	if err != nil {
		return nil, err
	}
	log := slog.Default()
	for _, cmd := range cmds {
		if err := runIP(ctx, cmd, log); err != nil && !cmd.optional {
			return nil, err
		}
	}
	if len(c.DNS) > 0 {
		fmt.Fprintf(os.Stderr, "# DNS: point /etc/resolv.conf at %s to use the tunnel resolver (DNS policy applies to all UDP/53 anyway)\n", strings.Join(c.DNS, ", "))
	}
	return func() {}, nil
}

func printRouteInstructions(c netConfig) {
	cmds, err := routeCommands(context.Background(), c.Dev, c.IPv4, c.IPv6, c.MTU, c.Bypass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "# Routes are not configured (no -routes); error computing routes: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stderr, "# Routes are not configured (no -routes). Run:")
	for _, cmd := range cmds {
		fmt.Fprintln(os.Stderr, "ip "+strings.Join(cmd.args, " "))
	}
	if len(c.DNS) > 0 {
		fmt.Fprintf(os.Stderr, "# DNS: point /etc/resolv.conf at %s to use the tunnel resolver (DNS policy applies to all UDP/53 anyway)\n", strings.Join(c.DNS, ", "))
	}
}

type gatewayConfig struct {
	name          string
	gwCIDRs       []netip.Prefix
	gnvCIDRs      []netip.Prefix
	dns           []string
	geneveListen  string
	gatewayRouted bool
}

func setupGatewayPlatform(ctx context.Context, cfg gatewayConfig, log *slog.Logger) (func(), error) {
	dns := netip.MustParseAddr("100.64.0.1")
	for _, d := range cfg.dns {
		if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
			dns = a
			break
		}
	}
	var gnvCloser func()
	gnvDev := ""
	if cfg.geneveListen != "" {
		gnvDev = geneveTUNName
		gnvIngress, err := startGeneveIngress(ctx, cfg.geneveListen, cfg.gnvCIDRs, log)
		if err != nil {
			return nil, fmt.Errorf("geneve ingress: %w", err)
		}
		gnvCloser = func() { _ = gnvIngress.Close() }
		log.Info("geneve ingress active", "listen", cfg.geneveListen, "tun", geneveTUNName)
	}
	cleanup, err := setupGateway(ctx, cfg.name, cfg.gwCIDRs, dns, log, cfg.gatewayRouted, gnvDev, cfg.gnvCIDRs)
	if err != nil {
		if gnvCloser != nil {
			gnvCloser()
		}
		return nil, fmt.Errorf("workload gateway: %w", err)
	}
	return func() {
		cleanup()
		if gnvCloser != nil {
			gnvCloser()
		}
	}, nil
}
