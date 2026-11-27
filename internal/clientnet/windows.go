//go:build windows

package clientnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/yuky2020/opensase/internal/wfp"
)

const defaultTUNName = "OpenSASE"

// Name Resolution Policy Table (NRPT) catch-all rule. While the tunnel is up,
// the namespace "." (every name) is resolved only by the tunnel resolvers, so
// smart multi-homed name resolution cannot race A/AAAA queries to the physical
// interfaces' resolvers (DHCP, IPv6 RDNSS/DHCPv6) when the kill switch is off.
const (
	nrptRuleKey                 = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{2f6b4c1e-8d3a-4f57-b9e0-6a1c5d7e3b42}`
	nrptGroupPolicyKey          = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	nrptVersion                 = 2
	nrptConfigGenericDNSServers = 0x8
)

func defaultTUNNamePlatform() string {
	return defaultTUNName
}

func checkWintunPrerequisites() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	dllPath := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if _, err := os.Stat(dllPath); err != nil {
		return fmt.Errorf("wintun.dll not found next to executable (%s): place the signed wintun.dll from the official Wintun distribution in the same directory as %s", dllPath, filepath.Base(exe))
	}
	return nil
}

func createTUNPlatform(name string, mtu int) (tun.Device, error) {
	if err := checkWintunPrerequisites(); err != nil {
		return nil, err
	}
	return tun.CreateTUN(name, mtu)
}

func printRouteInstructionsPlatform(_ Config) {
	_, _ = fmt.Fprintln(os.Stderr, "# Routes are not configured (no -routes). Run with -routes to configure Wintun adapter routes and DNS.") // best-effort diagnostic hint
}

func parseIPAddress(s string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// physicalGateway is the default gateway of one address family on a physical
// interface. A zero nextHop means the family has no physical default route.
type physicalGateway struct {
	luid    winipcfg.LUID
	ifIndex uint32
	nextHop netip.Addr
}

// findPhysicalDefaultGateway returns the lowest-metric default gateway of the
// address family that does not leave through the tunnel adapter. It returns a
// zero physicalGateway and no error when the family has no default route.
func findPhysicalDefaultGateway(tunLUID winipcfg.LUID, family winipcfg.AddressFamily) (physicalGateway, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return physicalGateway{}, fmt.Errorf("get IP forward table: %w", err)
	}
	cands := make([]defaultRouteCandidate, len(rows))
	for i := range rows {
		cands[i] = defaultRouteCandidate{
			Destination: rows[i].DestinationPrefix.Prefix(),
			NextHop:     rows[i].NextHop.Addr(),
			Metric:      rows[i].Metric,
			Tunnel:      rows[i].InterfaceLUID == tunLUID,
		}
	}
	best := pickDefaultGateway(cands, family == windows.AF_INET6)
	if best < 0 {
		return physicalGateway{}, nil
	}
	return physicalGateway{
		luid:    rows[best].InterfaceLUID,
		ifIndex: rows[best].InterfaceIndex,
		nextHop: cands[best].NextHop,
	}, nil
}

// findPhysicalDefaultGateways discovers the physical default gateway of each
// address family. It fails only when neither family has one, so IPv4-only,
// IPv6-only and dual-stack hosts are all supported.
func findPhysicalDefaultGateways(ctx context.Context, tunLUID winipcfg.LUID, log *slog.Logger) (gw4, gw6 physicalGateway, err error) {
	gw4, err4 := findPhysicalDefaultGateway(tunLUID, windows.AF_INET)
	gw6, err6 := findPhysicalDefaultGateway(tunLUID, windows.AF_INET6)
	if !gw4.nextHop.IsValid() && !gw6.nextHop.IsValid() {
		return physicalGateway{}, physicalGateway{}, errors.Join(
			errors.New("no IPv4 or IPv6 default route found on a physical interface"), err4, err6)
	}
	if err4 != nil {
		log.WarnContext(ctx, "IPv4 default route lookup failed", "err", err4)
	}
	if err6 != nil {
		log.WarnContext(ctx, "IPv6 default route lookup failed", "err", err6)
	}
	if !gw4.nextHop.IsValid() {
		log.InfoContext(ctx, "no physical IPv4 default route: IPv4 bypass hosts get no bypass route")
	}
	if !gw6.nextHop.IsValid() {
		log.InfoContext(ctx, "no physical IPv6 default route: IPv6 bypass hosts get no bypass route")
	}
	return gw4, gw6, nil
}

func configurePlatform(ctx context.Context, dev tun.Device, c Config, log *slog.Logger) (undo func(), err error) {
	if log == nil {
		log = slog.Default()
	}
	var tunLUID winipcfg.LUID
	if nt, ok := dev.(interface{ LUID() uint64 }); ok {
		tunLUID = winipcfg.LUID(nt.LUID())
	} else {
		iface, err := net.InterfaceByName(c.Dev)
		if err != nil {
			return nil, fmt.Errorf("lookup interface %s: %w", c.Dev, err)
		}
		tunLUID, err = winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			return nil, fmt.Errorf("luid from index %d: %w", iface.Index, err)
		}
	}

	var tunIfIndex uint32
	if iface, err := net.InterfaceByName(c.Dev); err == nil {
		tunIfIndex = uint32(iface.Index)
	}

	gw4, gw6, err := findPhysicalDefaultGateways(ctx, tunLUID, log)
	if err != nil {
		return nil, err
	}

	// Resolve the bypass hosts (IPv4 and IPv6) before the tunnel DNS and the DNS
	// policy rule are set: the physical resolvers must still answer.
	var bypassIPs []netip.Addr
	addBypassAddr := func(host string, addr netip.Addr) {
		addr = addr.Unmap().WithZone("")
		if !addr.IsValid() {
			return
		}
		bypassIPs = append(bypassIPs, addr)
		if (addr.Is4() && !gw4.nextHop.IsValid()) || (addr.Is6() && !gw6.nextHop.IsValid()) {
			log.WarnContext(ctx, "no physical default route for the bypass address family; no bypass route", "host", host, "ip", addr)
		}
	}
	for _, h := range c.Bypass {
		if a, err := netip.ParseAddr(h); err == nil {
			addBypassAddr(h, a)
			continue
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
		if err != nil {
			log.WarnContext(ctx, "bypass host does not resolve; no bypass route", "host", h, "err", err)
			continue
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				addBypassAddr(h, addr)
			}
		}
	}

	// From here on the adapter, its DNS, the routing table, the DNS policy rule
	// and the kill switch are modified in order. Every step pushes its teardown
	// onto rb so both error rollback and normal disconnect undo in exact LIFO
	// order: kill switch -> NRPT -> tunnel routes -> bypass routes -> DNS.
	var rb rollbackStack
	defer func() {
		if err != nil {
			rb.run()
		}
	}()

	ipif, err := tunLUID.IPInterface(windows.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("get IPv4 interface: %w", err)
	}
	ipif.NLMTU = uint32(c.MTU)
	ipif.Metric = 1
	ipif.UseAutomaticMetric = false
	if err := ipif.Set(); err != nil {
		return nil, fmt.Errorf("set IPv4 interface MTU/metric: %w", err)
	}

	// Configure the IPv6 tunnel interface. When c.IPv6 is set, any error is
	// fatal so we never leave ::/1 and 8000::/1 unconfigured. When c.IPv6 is
	// empty, we still configure the AF_INET6 interface metric when IPv6 is
	// enabled on the host so ::/1 and 8000::/1 blackhole sink routes can be
	// installed into Wintun and prevent IPv6 leaks over the physical NIC.
	var ipv6On bool
	if c.IPv6 != "" {
		ipif6, err := tunLUID.IPInterface(windows.AF_INET6)
		if err != nil {
			return nil, fmt.Errorf("get IPv6 interface: %w", err)
		}
		ipif6.NLMTU = uint32(c.MTU)
		ipif6.Metric = 1
		ipif6.UseAutomaticMetric = false
		if err := ipif6.Set(); err != nil {
			return nil, fmt.Errorf("set IPv6 interface MTU/metric: %w", err)
		}
		ipv6On = true
	} else if ipif6, err := tunLUID.IPInterface(windows.AF_INET6); err == nil {
		ipif6.NLMTU = uint32(c.MTU)
		ipif6.Metric = 1
		ipif6.UseAutomaticMetric = false
		if err := ipif6.Set(); err != nil {
			return nil, fmt.Errorf("set IPv6 sink interface MTU/metric: %w", err)
		}
		ipv6On = true
	} else {
		if gw6.nextHop.IsValid() {
			return nil, fmt.Errorf("get IPv6 interface for IPv6 blackhole: %w", err)
		}
		log.InfoContext(ctx, "IPv6 disabled on tunnel adapter; skipping IPv6 blackhole routes", "err", err)
	}

	ip4Addr, err := parseIPAddress(c.IPv4)
	if err != nil {
		return nil, fmt.Errorf("parse tunnel IPv4 %q: %w", c.IPv4, err)
	}
	ip4Addr = ip4Addr.Unmap().WithZone("")
	if !ip4Addr.Is4() {
		return nil, fmt.Errorf("tunnel IPv4 %q is not an IPv4 address", c.IPv4)
	}
	ip4Prefix := netip.PrefixFrom(ip4Addr, 32)
	if err := tunLUID.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{ip4Prefix}); err != nil {
		return nil, fmt.Errorf("set tunnel IPv4 address %s: %w", ip4Prefix, err)
	}

	if c.IPv6 != "" {
		ip6Addr, err := parseIPAddress(c.IPv6)
		if err != nil {
			return nil, fmt.Errorf("parse tunnel IPv6 %q: %w", c.IPv6, err)
		}
		ip6Addr = ip6Addr.Unmap().WithZone("")
		if !ip6Addr.Is6() {
			return nil, fmt.Errorf("tunnel IPv6 %q is not an IPv6 address", c.IPv6)
		}
		ip6Prefix := netip.PrefixFrom(ip6Addr, 128)
		if err := tunLUID.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{ip6Prefix}); err != nil {
			return nil, fmt.Errorf("set tunnel IPv6 address %s: %w", ip6Prefix, err)
		}
	}

	dns4, dns6, tunnelDNS := splitTunnelDNS(c.DNS, c.IPv6 != "")
	if len(dns4) > 0 {
		if err := tunLUID.SetDNS(windows.AF_INET, dns4, nil); err != nil {
			return nil, fmt.Errorf("set tunnel IPv4 DNS: %w", err)
		}
		rb.push(func() {
			_ = tunLUID.FlushDNS(windows.AF_INET) // best-effort teardown of tunnel IPv4 DNS
		})
	}
	if len(dns6) > 0 {
		if err := tunLUID.SetDNS(windows.AF_INET6, dns6, nil); err != nil {
			return nil, fmt.Errorf("set tunnel IPv6 DNS: %w", err)
		}
		rb.push(func() {
			_ = tunLUID.FlushDNS(windows.AF_INET6) // best-effort teardown of tunnel IPv6 DNS
		})
	}

	// Safety sweep after individual route deletions remove tunnel and bypass routes.
	rb.push(func() {
		_ = tunLUID.FlushRoutes(windows.AF_INET) // best-effort teardown of remaining tunnel IPv4 routes
		if ipv6On {
			_ = tunLUID.FlushRoutes(windows.AF_INET6) // best-effort teardown of remaining tunnel IPv6 routes
		}
	})

	gatewayFor := func(r plannedRoute) physicalGateway {
		if r.Destination.Addr().Is4() {
			return gw4
		}
		return gw6
	}

	routes := windowsRoutePlan(c, bypassIPs, gw4.nextHop, gw6.nextHop, ipv6On)
	undoRoutes, err := applyWindowsRoutes(routes, windowsRouteOps{
		addTunnel: func(r plannedRoute) error {
			nh := tunnelRouteNextHop(r)
			if err := tunLUID.AddRoute(r.Destination, nh, r.Metric); err != nil {
				return fmt.Errorf("add tunnel route %s: %w", r.Destination, err)
			}
			if r.Blackhole {
				log.InfoContext(ctx, "configured IPv6 blackhole route", "prefix", r.Destination, "gateway", nh, "interface", tunIfIndex)
			} else {
				log.InfoContext(ctx, "configured route", "prefix", r.Destination, "gateway", nh, "interface", tunIfIndex)
			}
			return nil
		},
		deleteTunnel: func(r plannedRoute) {
			nh := tunnelRouteNextHop(r)
			if err := tunLUID.DeleteRoute(r.Destination, nh); err != nil {
				log.Warn("delete tunnel route failed", "prefix", r.Destination, "gateway", nh, "interface", tunIfIndex, "err", err)
			} else {
				log.Info("removed tunnel route", "prefix", r.Destination, "gateway", nh, "interface", tunIfIndex)
			}
		},
		addBypass: func(r plannedRoute) error {
			gw := gatewayFor(r)
			if err := gw.luid.AddRoute(r.Destination, r.NextHop, r.Metric); err != nil {
				return fmt.Errorf("add bypass route %s via %s: %w", r.Destination, r.NextHop, err)
			}
			log.InfoContext(ctx, "configured route", "prefix", r.Destination, "gateway", r.NextHop, "interface", gw.ifIndex)
			return nil
		},
		deleteBypass: func(r plannedRoute) {
			gw := gatewayFor(r)
			if err := gw.luid.DeleteRoute(r.Destination, r.NextHop); err != nil {
				log.Warn("delete bypass route failed", "prefix", r.Destination, "gateway", r.NextHop, "interface", gw.ifIndex, "err", err)
			} else {
				log.Info("removed bypass route", "prefix", r.Destination, "gateway", r.NextHop, "interface", gw.ifIndex)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	rb.push(undoRoutes)

	// The DNS policy rule is set once the tunnel routes exist, so the tunnel
	// resolvers are reachable as soon as every name is sent to them.
	if len(tunnelDNS) > 0 {
		if groupPolicyNRPTActive() {
			log.WarnContext(ctx, "group policy defines DNS policy rules, which override the local catch-all rule: without the kill switch, DNS may also reach the physical interfaces' resolvers")
		}
		rb.push(func() {
			if rerr := removeNRPTRule(); rerr != nil {
				log.Warn("remove DNS policy rule failed", "err", rerr)
			}
		})
		if err := setNRPTRule(tunnelDNS); err != nil {
			return nil, fmt.Errorf("set DNS policy rule: %w", err)
		}
		log.InfoContext(ctx, "DNS policy rule set: every name resolves through the tunnel resolvers", "servers", len(tunnelDNS))
	}

	if c.KillSwitch {
		opts := wfp.Options{
			TunLUID:    uint64(tunLUID),
			DNSServers: tunnelDNS,
			Bypass:     bypassIPs,
		}
		if err := wfp.Enable(opts); err != nil {
			return nil, fmt.Errorf("kill switch: %w", err)
		}
		log.InfoContext(ctx, "kill switch on: traffic outside the tunnel is blocked", "allowed", len(bypassIPs))
		rb.push(func() {
			wfp.Disable()
			log.Info("kill switch off")
		})
	}

	return rb.run, nil
}

// setNRPTRule installs the catch-all DNS policy rule: the namespace "."
// matches every name and the generic DNS servers are the tunnel resolvers.
func setNRPTRule(servers []netip.Addr) (err error) {
	if len(servers) == 0 {
		return errors.New("no DNS servers for DNS policy rule")
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptRuleKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := k.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err = k.SetDWordValue("Version", nrptVersion); err != nil {
		return err
	}
	if err = k.SetDWordValue("ConfigOptions", nrptConfigGenericDNSServers); err != nil {
		return err
	}
	if err = k.SetStringValue("GenericDNSServers", formatNRPTServers(servers)); err != nil {
		return err
	}
	if err = k.SetStringValue("IPSECCARestriction", ""); err != nil {
		return err
	}
	// The namespace is written last, so the DNS client never sees a rule that
	// matches every name but has no servers.
	if err = k.SetStringsValue("Name", []string{"."}); err != nil {
		return err
	}
	flushResolverCache()
	return nil
}

// removeNRPTRule deletes the catch-all DNS policy rule. A missing rule is not
// an error.
func removeNRPTRule() error {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptRuleKey); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove DNS policy rule: %w", err)
	}
	flushResolverCache()
	return nil
}

// groupPolicyNRPTActive reports whether group policy defines DNS policy rules;
// the DNS client then ignores the local rules, including the catch-all rule.
func groupPolicyNRPTActive() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptGroupPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() {
		_ = k.Close() // read-only registry key; close error is not actionable
	}()
	info, err := k.Stat()
	return err == nil && info.SubKeyCount > 0
}

// flushResolverCache drops answers cached from the physical interfaces'
// resolvers, so a DNS policy change applies at once. Best effort.
func flushResolverCache() {
	proc := windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
	if proc.Find() != nil {
		return
	}
	_, _, _ = proc.Call() // best-effort resolver cache flush
}

func cleanupKillSwitchPlatform(context.Context) error {
	wfp.Disable()
	// A DNS policy rule left by a daemon that did not stop cleanly would send
	// every query to the unreachable tunnel resolvers.
	return removeNRPTRule()
}
