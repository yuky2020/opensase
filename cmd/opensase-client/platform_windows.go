//go:build windows

package main

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
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	defaultTUNName  = "OpenSASE"
	defaultHostname = "windows-client"
)

func gatewaySupported() bool {
	return false
}

func checkTUNPrerequisites() error {
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

func printRouteInstructions(_ netConfig) {
	fmt.Fprintln(os.Stderr, "# Routes are not configured (no -routes). Run with -routes to configure Wintun adapter routes and DNS.")
}

type gatewayConfig struct {
	name          string
	gwCIDRs       []netip.Prefix
	gnvCIDRs      []netip.Prefix
	dns           []string
	geneveListen  string
	gatewayRouted bool
}

func setupGatewayPlatform(_ context.Context, _ gatewayConfig, _ *slog.Logger) (func(), error) {
	return nil, errors.New("gateway mode (-gateway, -geneve-listen, -gateway-routed) is only supported on Linux")
}

func parseIPAddress(s string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func findPhysicalDefaultGateway(tunLUID winipcfg.LUID) (winipcfg.LUID, uint32, netip.Addr, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, 0, netip.Addr{}, fmt.Errorf("get IP forward table: %w", err)
	}
	var (
		found        bool
		bestLUID     winipcfg.LUID
		bestIfIndex  uint32
		bestGW       netip.Addr
		lowestMetric = ^uint32(0)
	)
	for _, row := range rows {
		if row.InterfaceLUID == tunLUID {
			continue
		}
		dst, nh := row.DestinationPrefix.Prefix(), row.NextHop.Addr()
		if dst.Bits() == 0 && dst.Addr().Is4() {
			if nh.IsValid() && !nh.IsUnspecified() {
				if !found || row.Metric < lowestMetric {
					found = true
					bestLUID = row.InterfaceLUID
					bestIfIndex = row.InterfaceIndex
					bestGW = nh
					lowestMetric = row.Metric
				}
			}
		}
	}
	if !found {
		return 0, 0, netip.Addr{}, errors.New("no IPv4 default route found on physical interface")
	}
	return bestLUID, bestIfIndex, bestGW, nil
}

func configureNetwork(ctx context.Context, dev tun.Device, c netConfig) (undo func(), err error) {
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

	physicalLUID, physicalIfIndex, physicalGW, err := findPhysicalDefaultGateway(tunLUID)
	if err != nil {
		return nil, err
	}

	if ipif, err := tunLUID.IPInterface(windows.AF_INET); err == nil {
		ipif.NLMTU = uint32(c.MTU)
		ipif.Metric = 1
		ipif.UseAutomaticMetric = false
		if err := ipif.Set(); err != nil {
			return nil, fmt.Errorf("set IPv4 interface MTU/metric: %w", err)
		}
	} else {
		return nil, fmt.Errorf("get IPv4 interface: %w", err)
	}

	if c.IPv6 != "" {
		if ipif6, err := tunLUID.IPInterface(windows.AF_INET6); err == nil {
			ipif6.NLMTU = uint32(c.MTU)
			ipif6.Metric = 1
			ipif6.UseAutomaticMetric = false
			_ = ipif6.Set()
		}
	}

	ip4Addr, err := parseIPAddress(c.IPv4)
	if err != nil {
		return nil, fmt.Errorf("parse tunnel IPv4 %q: %w", c.IPv4, err)
	}
	ip4Prefix := netip.PrefixFrom(ip4Addr, 32)
	if err := tunLUID.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{ip4Prefix}); err != nil {
		return nil, fmt.Errorf("set tunnel IPv4 address %s: %w", ip4Prefix, err)
	}

	if c.IPv6 != "" {
		if ip6Addr, err := parseIPAddress(c.IPv6); err == nil {
			ip6Prefix := netip.PrefixFrom(ip6Addr, 128)
			if err := tunLUID.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{ip6Prefix}); err != nil {
				slog.WarnContext(ctx, "set tunnel IPv6 address failed", "prefix", ip6Prefix, "err", err)
			}
		}
	}

	var dns4 []netip.Addr
	var dns6 []netip.Addr
	for _, d := range c.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			if a.Is4() {
				dns4 = append(dns4, a)
			} else if a.Is6() {
				dns6 = append(dns6, a)
			}
		}
	}
	if len(dns4) > 0 {
		if err := tunLUID.SetDNS(windows.AF_INET, dns4, nil); err != nil {
			return nil, fmt.Errorf("set tunnel IPv4 DNS: %w", err)
		}
	}
	if len(dns6) > 0 {
		if err := tunLUID.SetDNS(windows.AF_INET6, dns6, nil); err != nil {
			slog.WarnContext(ctx, "set tunnel IPv6 DNS failed", "err", err)
		}
	}

	var bypassIPs []netip.Addr
	for _, h := range c.Bypass {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
		if err != nil {
			slog.WarnContext(ctx, "bypass host does not resolve; no bypass route", "host", h, "err", err)
			continue
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				bypassIPs = append(bypassIPs, addr.Unmap())
			}
		}
	}

	routes := windowsRoutePlan(c, bypassIPs, physicalGW)

	var installedBypass []plannedRoute
	for _, r := range routes {
		if r.Tunnel {
			nh := r.NextHop
			if !nh.IsValid() {
				if r.Destination.Addr().Is4() {
					nh = netip.IPv4Unspecified()
				} else {
					nh = netip.IPv6Unspecified()
				}
			}
			if err := tunLUID.AddRoute(r.Destination, nh, r.Metric); err != nil {
				return nil, fmt.Errorf("add tunnel route %s: %w", r.Destination, err)
			}
			slog.Info("configured route", "prefix", r.Destination, "gateway", nh, "interface", tunIfIndex)
		} else {
			if err := physicalLUID.AddRoute(r.Destination, r.NextHop, r.Metric); err != nil {
				return nil, fmt.Errorf("add bypass route %s via %s: %w", r.Destination, r.NextHop, err)
			}
			installedBypass = append(installedBypass, r)
			slog.Info("configured route", "prefix", r.Destination, "gateway", r.NextHop, "interface", physicalIfIndex)
		}
	}

	undo = func() {
		for _, r := range installedBypass {
			if err := physicalLUID.DeleteRoute(r.Destination, r.NextHop); err != nil {
				slog.Warn("delete bypass route failed", "prefix", r.Destination, "gateway", r.NextHop, "interface", physicalIfIndex, "err", err)
			} else {
				slog.Info("removed bypass route", "prefix", r.Destination, "gateway", r.NextHop, "interface", physicalIfIndex)
			}
		}
		_ = tunLUID.FlushRoutes(windows.AF_INET)
		_ = tunLUID.FlushRoutes(windows.AF_INET6)
		_ = tunLUID.FlushDNS(windows.AF_INET)
		_ = tunLUID.FlushDNS(windows.AF_INET6)
	}

	return undo, nil
}
