package clientnet

import (
	"net/netip"
	"strings"
)

// plannedRoute represents a routing table entry to be installed.
type plannedRoute struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Tunnel      bool
	Blackhole   bool // IPv6 sink route into the tunnel when the session has no tunnel IPv6
	Metric      uint32
}

// windowsRoutePlan computes the list of routes needed on Windows: host routes
// for the bypass IPs via the physical gateway of their address family (/32 via
// gw4, /128 via gw6), followed by split default routes (0.0.0.0/1 and
// 128.0.0.0/1, plus ::/1 and 8000::/1) into the tunnel.
//
// A zero gw4 or gw6 means the host has no physical default route for that
// family, so bypass IPs of that family get no host route. Duplicate bypass IPs
// are deduplicated, zones are stripped, and IPv4-mapped IPv6 addresses are
// treated as IPv4.
//
// When c.IPv6 is empty and IPv6 is active on the host (ipv6Enabled or a valid
// gw6), ::/1 and 8000::/1 are still emitted into the tunnel with Blackhole set
// so IPv6 traffic cannot leak around the tunnel via the physical interface
// while /128 bypass routes remain reachable.
func windowsRoutePlan(c Config, bypassIPs []netip.Addr, gw4, gw6 netip.Addr, ipv6Enabled bool) []plannedRoute {
	var routes []plannedRoute
	seen := make(map[netip.Addr]bool)

	if gw4.IsValid() {
		gw4 = gw4.Unmap().WithZone("")
		if !gw4.Is4() {
			gw4 = netip.Addr{}
		}
	}
	if gw6.IsValid() {
		gw6 = gw6.Unmap().WithZone("")
		if !gw6.Is6() {
			gw6 = netip.Addr{}
		}
	}

	for _, ip := range bypassIPs {
		ip = ip.Unmap().WithZone("")
		if !ip.IsValid() {
			continue
		}
		var gw netip.Addr
		switch {
		case ip.Is4():
			gw = gw4
		case ip.Is6():
			gw = gw6
		}
		if !gw.IsValid() || seen[ip] {
			continue
		}
		seen[ip] = true
		routes = append(routes, plannedRoute{
			Destination: netip.PrefixFrom(ip, ip.BitLen()),
			NextHop:     gw,
			Tunnel:      false,
			Metric:      1,
		})
	}

	routes = append(routes,
		plannedRoute{
			Destination: netip.MustParsePrefix("0.0.0.0/1"),
			NextHop:     netip.Addr{},
			Tunnel:      true,
			Metric:      1,
		},
		plannedRoute{
			Destination: netip.MustParsePrefix("128.0.0.0/1"),
			NextHop:     netip.Addr{},
			Tunnel:      true,
			Metric:      1,
		},
	)

	if c.IPv6 != "" || ipv6Enabled || gw6.IsValid() {
		blackhole := c.IPv6 == ""
		routes = append(routes,
			plannedRoute{
				Destination: netip.MustParsePrefix("::/1"),
				NextHop:     netip.Addr{},
				Tunnel:      true,
				Blackhole:   blackhole,
				Metric:      1,
			},
			plannedRoute{
				Destination: netip.MustParsePrefix("8000::/1"),
				NextHop:     netip.Addr{},
				Tunnel:      true,
				Blackhole:   blackhole,
				Metric:      1,
			},
		)
	}

	return routes
}

// tunnelRouteNextHop returns the next-hop address to pass for a tunnel route:
// the route's NextHop if set, otherwise the unspecified address of the
// destination's address family (0.0.0.0 or ::).
func tunnelRouteNextHop(r plannedRoute) netip.Addr {
	if r.NextHop.IsValid() {
		return r.NextHop
	}
	if r.Destination.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// windowsRouteOps performs the routing table mutations for applyWindowsRoutes.
// Using callbacks keeps route installation and LIFO rollback order testable on
// non-Windows hosts.
type windowsRouteOps struct {
	addTunnel    func(plannedRoute) error
	deleteTunnel func(plannedRoute)
	addBypass    func(plannedRoute) error
	deleteBypass func(plannedRoute)
}

// applyWindowsRoutes installs routes in plan order and returns an undo
// function that removes every installed route in reverse (LIFO) order, so
// tunnel split routes are always removed before physical bypass routes. If any
// route fails to install, already-installed routes are rolled back in reverse
// order before returning the error.
func applyWindowsRoutes(routes []plannedRoute, ops windowsRouteOps) (func(), error) {
	installed := make([]plannedRoute, 0, len(routes))
	rollback := func() {
		for i := len(installed) - 1; i >= 0; i-- {
			r := installed[i]
			if r.Tunnel {
				if ops.deleteTunnel != nil {
					ops.deleteTunnel(r)
				}
			} else if ops.deleteBypass != nil {
				ops.deleteBypass(r)
			}
		}
		installed = nil
	}
	for _, r := range routes {
		var err error
		if r.Tunnel {
			err = ops.addTunnel(r)
		} else {
			err = ops.addBypass(r)
		}
		if err != nil {
			rollback()
			return nil, err
		}
		installed = append(installed, r)
	}
	return rollback, nil
}

// rollbackStack collects teardown callbacks and executes them in reverse
// (LIFO) order on setup failure or disconnect. Calling run more than once is a
// no-op.
type rollbackStack struct {
	steps []func()
}

func (s *rollbackStack) push(fn func()) {
	if fn != nil {
		s.steps = append(s.steps, fn)
	}
}

func (s *rollbackStack) run() {
	for i := len(s.steps) - 1; i >= 0; i-- {
		s.steps[i]()
	}
	s.steps = nil
}

// splitTunnelDNS parses, normalizes, and deduplicates DNS server addresses for
// the tunnel adapter and the catch-all DNS policy rule. When includeV6 is
// false (the session has no tunnel IPv6 address), IPv6 resolvers are omitted
// so queries are not sent to an unreachable blackholed IPv6 address.
func splitTunnelDNS(servers []string, includeV6 bool) (dns4, dns6, all []netip.Addr) {
	seen := make(map[netip.Addr]bool, len(servers))
	for _, s := range servers {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			dns4 = append(dns4, a)
		} else if includeV6 {
			dns6 = append(dns6, a)
		}
	}
	all = make([]netip.Addr, 0, len(dns4)+len(dns6))
	all = append(all, dns4...)
	all = append(all, dns6...)
	return dns4, dns6, all
}

// formatNRPTServers formats resolver addresses for the NRPT GenericDNSServers
// registry value (semicolon-separated IP literals).
func formatNRPTServers(servers []netip.Addr) string {
	list := make([]string, 0, len(servers))
	for _, s := range servers {
		list = append(list, s.String())
	}
	return strings.Join(list, ";")
}

// defaultRouteCandidate is a routing-table row reduced to the fields that
// decide which physical default gateway the bypass routes use.
type defaultRouteCandidate struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Metric      uint32
	Tunnel      bool // the row leaves through the tunnel adapter
}

// pickDefaultGateway returns the index of the lowest-metric default route of
// one address family (IPv6 when v6 is set, IPv4 otherwise) that leaves through
// a physical interface via a real next hop, or -1 when there is none. On equal
// metrics the first row wins.
func pickDefaultGateway(rows []defaultRouteCandidate, v6 bool) int {
	best := -1
	for i, r := range rows {
		if r.Tunnel || !r.Destination.IsValid() || r.Destination.Bits() != 0 {
			continue
		}
		if r.Destination.Addr().Is6() != v6 {
			continue
		}
		if !r.NextHop.IsValid() || r.NextHop.IsUnspecified() || r.NextHop.Is6() != v6 {
			continue
		}
		if best < 0 || r.Metric < rows[best].Metric {
			best = i
		}
	}
	return best
}
