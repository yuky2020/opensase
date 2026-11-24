//go:build linux

package clientnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const defaultTUNName = "osase0"

func defaultTUNNamePlatform() string {
	return defaultTUNName
}

func createTUNPlatform(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
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

func configurePlatform(ctx context.Context, _ tun.Device, c Config, log *slog.Logger) (undo func(), err error) {
	cmds, err := routeCommands(ctx, c.Dev, c.IPv4, c.IPv6, c.MTU, c.Bypass)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
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

func printRouteInstructionsPlatform(c Config) {
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
