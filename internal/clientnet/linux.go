//go:build linux

package clientnet

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
	defaultTUNName       = "osase0"
	ipv6DisablePath      = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	resolvConfPath       = "/etc/resolv.conf"
	resolvConfBackupPath = "/etc/resolv.conf.opensase.bak"
	resolvConfMarker     = "# Managed by OpenSASE"
)

func defaultTUNNamePlatform() string {
	return defaultTUNName
}

func createTUNPlatform(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

type ipCmd struct {
	args         []string
	undoArgs     []string // teardown command (e.g. route del for bypass or unreachable routes)
	optional     bool     // IPv6 steps: tolerated when IPv6 is disabled in the container
	ipv6Fallback bool     // if this fails while kernel IPv6 is enabled, fall back to unreachable split routes
}

type routeDeps struct {
	defaultGW4  func(ctx context.Context) (gw, dev string, err error)
	defaultGW6  func(ctx context.Context) (gw, dev string, err error)
	lookupIP    func(ctx context.Context, host string) ([]netip.Addr, error)
	ipv6Enabled func() bool
}

func lookupHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func systemRouteDeps() routeDeps {
	return routeDeps{
		defaultGW4:  defaultGateway,
		defaultGW6:  defaultGateway6,
		lookupIP:    lookupHostIPs,
		ipv6Enabled: ipv6Enabled,
	}
}

// ipv6Enabled reports whether IPv6 is enabled in the network namespace
// (net.ipv6.conf.all.disable_ipv6 == 0).
func ipv6Enabled() bool {
	return ipv6EnabledFile(ipv6DisablePath)
}

func ipv6EnabledFile(path string) bool {
	b, err := os.ReadFile(path) //nolint:gosec // G304: fixed /proc path, parameter only for tests
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "0"
}

func ipv6BlackholeCmds() []ipCmd {
	return []ipCmd{
		{
			args:     []string{"-6", "route", "replace", "unreachable", "::/1"},
			undoArgs: []string{"-6", "route", "del", "unreachable", "::/1"},
		},
		{
			args:     []string{"-6", "route", "replace", "unreachable", "8000::/1"},
			undoArgs: []string{"-6", "route", "del", "unreachable", "8000::/1"},
		},
	}
}

// routeCommands builds the ip(8) commands: interface addresses, host routes (/32 and /128)
// for the bypass hosts via the current IPv4/IPv6 default gateways, then 0.0.0.0/1 +
// 128.0.0.0/1 (and ::/1 + 8000::/1, or unreachable IPv6 split routes when kernel IPv6 is
// enabled without a tunnel IPv6 address), which override the default route without deleting it.
func routeCommands(ctx context.Context, dev, ipv4, ipv6 string, mtu int, bypass []string) ([]ipCmd, error) {
	return routeCommandsWith(ctx, dev, ipv4, ipv6, mtu, bypass, systemRouteDeps())
}

func routeCommandsWith(ctx context.Context, dev, ipv4, ipv6 string, mtu int, bypass []string, deps routeDeps) ([]ipCmd, error) {
	var cmds []ipCmd
	add := func(optional, ipv6Fallback bool, undoArgs []string, args ...string) {
		cmds = append(cmds, ipCmd{
			args:         args,
			undoArgs:     undoArgs,
			optional:     optional,
			ipv6Fallback: ipv6Fallback,
		})
	}
	if ipv4 == "" && ipv6 == "" {
		return nil, errors.New("session returned no tunnel address")
	}
	ipv6On := deps.ipv6Enabled != nil && deps.ipv6Enabled()

	if ipv4 != "" {
		add(false, false, nil, "address", "replace", ipv4, "dev", dev)
	}
	if ipv6 != "" {
		add(!ipv6On, ipv6On, nil, "-6", "address", "replace", ipv6, "dev", dev)
	}
	add(false, false, nil, "link", "set", "dev", dev, "mtu", fmt.Sprint(mtu), "up")

	var gw4, gwDev4 string
	var err4 error
	if deps.defaultGW4 != nil {
		gw4, gwDev4, err4 = deps.defaultGW4(ctx)
	} else {
		err4 = errors.New("no IPv4 default route")
	}
	hasGW4 := err4 == nil && gwDev4 != ""

	var gw6, gwDev6 string
	var err6 error
	if deps.defaultGW6 != nil {
		gw6, gwDev6, err6 = deps.defaultGW6(ctx)
	} else {
		err6 = errors.New("no IPv6 default route")
	}
	hasGW6 := err6 == nil && gwDev6 != ""

	if !hasGW4 && !hasGW6 {
		return nil, fmt.Errorf("no IPv4 or IPv6 default route to reach the Control Plane and Edge (ipv4: %w; ipv6: %w)", err4, err6)
	}

	seen := make(map[netip.Addr]bool)
	for _, h := range bypass {
		var addrs []netip.Addr
		if a, err := netip.ParseAddr(h); err == nil {
			addrs = []netip.Addr{a}
		} else {
			if deps.lookupIP == nil {
				continue
			}
			var lerr error
			addrs, lerr = deps.lookupIP(ctx, h)
			if lerr != nil {
				// Not fatal: the Edge must work while the Control Plane is unreachable (ADR-0014).
				// The session is already up, so the Edge host resolved; an unresolvable Control
				// Plane host just gets no bypass route, and reaches it through the tunnel later.
				slog.WarnContext(ctx, "bypass host does not resolve; no bypass route", "host", h, "err", lerr)
				continue
			}
		}
		for _, a := range addrs {
			a = a.Unmap().WithZone("")
			if !a.IsValid() || seen[a] {
				continue
			}
			seen[a] = true
			if a.Is4() {
				if !hasGW4 {
					continue
				}
				dst := a.String() + "/32"
				if gw4 != "" {
					add(false, false, []string{"route", "del", dst, "via", gw4, "dev", gwDev4},
						"route", "replace", dst, "via", gw4, "dev", gwDev4)
				} else {
					add(false, false, []string{"route", "del", dst, "dev", gwDev4},
						"route", "replace", dst, "dev", gwDev4)
				}
			} else {
				if !hasGW6 {
					continue
				}
				dst := a.String() + "/128"
				if gw6 != "" {
					add(false, false, []string{"-6", "route", "del", dst, "via", gw6, "dev", gwDev6},
						"-6", "route", "replace", dst, "via", gw6, "dev", gwDev6)
				} else {
					add(false, false, []string{"-6", "route", "del", dst, "dev", gwDev6},
						"-6", "route", "replace", dst, "dev", gwDev6)
				}
			}
		}
	}

	if ipv4 != "" {
		add(false, false, nil, "route", "replace", "0.0.0.0/1", "dev", dev)
		add(false, false, nil, "route", "replace", "128.0.0.0/1", "dev", dev)
	}
	if ipv6 != "" {
		add(!ipv6On, ipv6On, nil, "-6", "route", "replace", "::/1", "dev", dev)
		add(!ipv6On, ipv6On, nil, "-6", "route", "replace", "8000::/1", "dev", dev)
	} else if ipv6On {
		cmds = append(cmds, ipv6BlackholeCmds()...)
	}
	return cmds, nil
}

// parseDefaultRoute extracts the gateway (empty for on-link routes) and device from the
// first default route line returned by `ip [-4|-6] route show default`.
func parseDefaultRoute(out []byte) (gw, dev string) {
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		var lineGW, lineDev string
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				if lineGW == "" {
					lineGW = f[i+1]
				}
			case "dev":
				if lineDev == "" {
					lineDev = f[i+1]
				}
			}
		}
		if lineDev != "" {
			return lineGW, lineDev
		}
	}
	return "", ""
}

// defaultGateway parses `ip -4 route show default`.
func defaultGateway(ctx context.Context) (gw, dev string, err error) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip -4 route show default: %w", err)
	}
	gw, dev = parseDefaultRoute(out)
	if dev == "" {
		return "", "", errors.New("no IPv4 default route")
	}
	return gw, dev, nil
}

// defaultGateway6 parses `ip -6 route show default`.
func defaultGateway6(ctx context.Context) (gw, dev string, err error) {
	out, err := exec.CommandContext(ctx, "ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip -6 route show default: %w", err)
	}
	gw, dev = parseDefaultRoute(out)
	if dev == "" {
		return "", "", errors.New("no IPv6 default route")
	}
	return gw, dev, nil
}

type ipRunner func(ctx context.Context, c ipCmd, log *slog.Logger) error

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

// applyIPCommands executes cmds in order and returns an undo function that removes every
// installed bypass and blackhole route in reverse order. On any non-optional failure, it
// rolls back already-installed routes before returning the error. If a tunnel IPv6 command
// marked ipv6Fallback fails, it installs unreachable ::/1 and 8000::/1 split routes so IPv6
// cannot leak around the tunnel, failing closed if those also fail.
func applyIPCommands(ctx context.Context, cmds []ipCmd, run ipRunner, log *slog.Logger) (func(), error) {
	var undoCmds [][]string
	rollback := func() { //nolint:contextcheck // runs at teardown, after the connect request's context is gone
		for i := len(undoCmds) - 1; i >= 0; i-- {
			_ = run(context.Background(), ipCmd{args: undoCmds[i], optional: true}, log)
		}
	}

	var needV6Blackhole bool
	for _, cmd := range cmds {
		if cmd.ipv6Fallback && needV6Blackhole {
			continue
		}
		if err := run(ctx, cmd, log); err != nil {
			if cmd.optional {
				continue
			}
			if cmd.ipv6Fallback {
				log.WarnContext(ctx, "tunnel IPv6 setup failed; falling back to unreachable IPv6 split routes", "err", err)
				needV6Blackhole = true
				continue
			}
			rollback()
			return nil, err
		}
		if len(cmd.undoArgs) > 0 {
			undoCmds = append(undoCmds, cmd.undoArgs)
		}
	}

	if needV6Blackhole {
		for _, cmd := range ipv6BlackholeCmds() {
			if err := run(ctx, cmd, log); err != nil {
				rollback()
				return nil, fmt.Errorf("install IPv6 blackhole route: %w", err)
			}
			if len(cmd.undoArgs) > 0 {
				undoCmds = append(undoCmds, cmd.undoArgs)
			}
		}
	}

	return rollback, nil
}

func configurePlatform(ctx context.Context, _ tun.Device, c Config, log *slog.Logger) (undo func(), err error) {
	if log == nil {
		log = slog.Default()
	}
	// Resolve bypass addresses for the kill switch before installing split routes into the TUN,
	// since the TUN may not be carrying packets yet (e.g. headless CLI).
	var allow []netip.Addr
	if c.KillSwitch {
		allow = resolveAllow(ctx, c.Bypass)
	}
	cmds, err := routeCommands(ctx, c.Dev, c.IPv4, c.IPv6, c.MTU, c.Bypass)
	if err != nil {
		return nil, err
	}
	undoRoutes, err := applyIPCommands(ctx, cmds, runIP, log)
	if err != nil {
		return nil, err
	}
	undo = undoRoutes
	if c.KillSwitch {
		undoKS, err := enableKillSwitch(ctx, c.Dev, allow, log)
		if err != nil {
			undo()
			return nil, fmt.Errorf("kill switch: %w", err)
		}
		prev := undo
		undo = func() { undoKS(); prev() }
	}
	if len(c.DNS) > 0 {
		if undoDNS, ok := setTunnelDNS(ctx, c.Dev, c.DNS, log); ok {
			prev := undo
			undo = func() { undoDNS(); prev() }
		} else {
			fmt.Fprintf(os.Stderr, "# DNS: point /etc/resolv.conf at %s to use the tunnel resolver\n", strings.Join(c.DNS, ", "))
		}
	}
	return undo, nil
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

// setTunnelDNS configures system DNS to use the tunnel resolvers: systemd-resolved via
// resolvectl when available, otherwise a managed /etc/resolv.conf backup/restore fallback.
func setTunnelDNS(ctx context.Context, dev string, servers []string, log *slog.Logger) (func(), bool) {
	if undo, ok := setResolvectlDNS(ctx, dev, servers, log); ok {
		return undo, true
	}
	return setResolvConfFallback(resolvConfPath, resolvConfBackupPath, servers, log)
}

// setResolvectlDNS makes systemd-resolved send every query to the tunnel resolver (the "~."
// routing domain), so name resolution works with the kill switch on. It reports false when
// resolvectl is not available or fails.
func setResolvectlDNS(ctx context.Context, dev string, servers []string, log *slog.Logger) (func(), bool) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return nil, false
	}
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, "resolvectl", args...).CombinedOutput() //nolint:gosec // G204: fixed binary; args from the session config
		if err != nil {
			return fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run(append([]string{"dns", dev}, servers...)...); err != nil {
		log.Warn("tunnel DNS not set", "err", err)
		return nil, false
	}
	if err := run("domain", dev, "~."); err != nil {
		log.Warn("tunnel DNS routing domain not set", "err", err)
	}
	_ = run("default-route", dev, "yes")
	log.Info("DNS goes to the tunnel resolver", "servers", strings.Join(servers, ","))
	return func() {
		if err := exec.Command("resolvectl", "revert", dev).Run(); err != nil { //nolint:gosec,noctx // G204: fixed binary; runs at teardown without a request context
			log.Warn("tunnel DNS not reverted", "err", err)
		}
	}, true
}

func formatResolvConf(servers []string) ([]byte, bool) {
	var b strings.Builder
	b.WriteString(resolvConfMarker)
	b.WriteByte('\n')
	count := 0
	seen := make(map[netip.Addr]bool)
	for _, s := range servers {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if seen[a] {
			continue
		}
		seen[a] = true
		fmt.Fprintf(&b, "nameserver %s\n", a.String())
		count++
	}
	if count == 0 {
		return nil, false
	}
	return []byte(b.String()), true
}

// setResolvConfFallback backs up resolvPath to backupPath and writes the tunnel
// nameservers in place (in-place writes work on bind-mounted /etc/resolv.conf in
// containers where rename fails with EBUSY). The returned undo restores the original
// content and removes backupPath.
func setResolvConfFallback(resolvPath, backupPath string, servers []string, log *slog.Logger) (func(), bool) {
	content, ok := formatResolvConf(servers)
	if !ok {
		return nil, false
	}

	var orig []byte
	var existed bool
	cur, err := os.ReadFile(resolvPath) //nolint:gosec // G304: fixed /etc/resolv.conf path, parameter only for tests
	switch {
	case err == nil:
		existed = true
		orig = cur
	case errors.Is(err, os.ErrNotExist):
		existed = false
	default:
		log.Warn("read resolv.conf failed; tunnel DNS not set", "path", resolvPath, "err", err)
		return nil, false
	}

	// If a previous run crashed before restoring resolv.conf, preserve its backup rather
	// than overwriting the backup with our generated file.
	reusedBackup := false
	if existed && strings.HasPrefix(string(cur), resolvConfMarker) {
		if bak, berr := os.ReadFile(backupPath); berr == nil { //nolint:gosec // G304: fixed backup path, parameter only for tests
			orig = bak
			reusedBackup = true
		}
	}

	wroteBackup := false
	if existed && !reusedBackup {
		if err := os.WriteFile(backupPath, orig, 0o600); err != nil { //nolint:gosec // G703: fixed backup path, parameter only for tests
			log.Warn("write resolv.conf backup failed; keeping backup in memory", "path", backupPath, "err", err)
		} else {
			wroteBackup = true
		}
	}

	if err := os.WriteFile(resolvPath, content, 0o644); err != nil { //nolint:gosec // G306,G703: /etc/resolv.conf must be world-readable
		if wroteBackup {
			_ = os.Remove(backupPath)
		}
		log.Warn("write resolv.conf failed; tunnel DNS not set", "path", resolvPath, "err", err)
		return nil, false
	}
	log.Info("DNS goes to the tunnel resolver via resolv.conf", "path", resolvPath, "servers", strings.Join(servers, ","))

	return func() {
		if existed {
			if err := os.WriteFile(resolvPath, orig, 0o644); err != nil { //nolint:gosec // G306,G703: /etc/resolv.conf must be world-readable
				log.Warn("restore resolv.conf failed", "path", resolvPath, "err", err)
				return
			}
		} else {
			if err := os.Remove(resolvPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Warn("remove managed resolv.conf failed", "path", resolvPath, "err", err)
				return
			}
		}
		if wroteBackup || reusedBackup {
			if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Warn("remove resolv.conf backup failed", "path", backupPath, "err", err)
			}
		}
	}, true
}
