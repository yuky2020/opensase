package clientnet

import (
	"net/netip"
)

// plannedRoute represents a routing table entry to be installed.
type plannedRoute struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Tunnel      bool
	Metric      uint32
}

// windowsRoutePlan computes the list of routes needed on Windows:
// host routes (/32) for bypass IPs via the physical gateway, and split
// default routes (0.0.0.0/1 and 128.0.0.0/1, plus ::/1 and 8000::/1 if IPv6 is set)
// into the tunnel. Duplicate bypass IPs are deduplicated.
func windowsRoutePlan(c Config, bypassIPs []netip.Addr, gw netip.Addr) []plannedRoute {
	var routes []plannedRoute
	seen := make(map[netip.Addr]bool)

	for _, ip := range bypassIPs {
		ip = ip.Unmap()
		if !ip.Is4() {
			continue
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		routes = append(routes, plannedRoute{
			Destination: netip.PrefixFrom(ip, 32),
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

	if c.IPv6 != "" {
		routes = append(routes,
			plannedRoute{
				Destination: netip.MustParsePrefix("::/1"),
				NextHop:     netip.Addr{},
				Tunnel:      true,
				Metric:      1,
			},
			plannedRoute{
				Destination: netip.MustParsePrefix("8000::/1"),
				NextHop:     netip.Addr{},
				Tunnel:      true,
				Metric:      1,
			},
		)
	}

	return routes
}
