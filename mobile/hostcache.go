package mobile

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// cacheLookupTimeout bounds a lookup for a host that already has a cached answer.
const cacheLookupTimeout = 3 * time.Second

// hostCache remembers the last successful IP resolution of external host names
// (Control Plane and Edge) and redirects DNS queries when tunnel DNS is down.
//
// When the tunnel goes down (e.g. Edge restarts), /etc/resolv.conf may still point
// to the tunnel resolver (100.64.0.1, inside the 100.64.0.0/10 range), which is
// unreachable while the tunnel is down. Issue #29 addresses two failure modes:
//  1. Resolution failure during reconnect: hostCache remembers previously resolved
//     addresses and returns cached entries if a fresh lookup fails, bounding the
//     lookup to 3 seconds when a cached entry exists.
//  2. Endpoint address changes across restarts: if the Control Plane or Edge host
//     has a new IP address while the tunnel is down, cached addresses are stale
//     and dialing the tunnel resolver fails. To recover, hostCache captures the
//     system nameservers (bootDNS) outside the tunnel range at creation time.
//     When dialing a resolver inside 100.64.0.0/10, it dials bootDNS servers in
//     order instead, allowing fresh lookups to succeed.
type hostCache struct {
	mu      sync.Mutex
	cache   map[string][]netip.Addr
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
	bootDNS []string
}

// readNameservers parses nameserver IP addresses from a resolv.conf format file at path.
// It skips addresses inside the 100.64.0.0/10 tunnel range. Each kept address is formatted
// as host:port with port 53. If the file is missing, unreadable, or contains no valid
// external nameservers, it returns nil.
func readNameservers(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // fixed system path (or a test file), read only
	if err != nil {
		return nil
	}
	tunnel := netip.MustParsePrefix("100.64.0.0/10")
	var servers []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip, err := netip.ParseAddr(fields[1])
			if err != nil {
				continue
			}
			if tunnel.Contains(ip) {
				continue
			}
			servers = append(servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return servers
}

// dnsTargets returns boot when address has a host in the 100.64.0.0/10 tunnel
// range and boot is non-empty; otherwise it returns []string{address}.
func dnsTargets(address string, boot []string) []string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.Trim(host, "[]")
	ip, err := netip.ParseAddr(host)
	if err == nil {
		tunnel := netip.MustParsePrefix("100.64.0.0/10")
		if tunnel.Contains(ip) && len(boot) > 0 {
			return boot
		}
	}
	return []string{address}
}

// newHostCache constructs a hostCache with a default lookup that dials via protect.
func newHostCache(protect protectFunc) *hostCache {
	bootDNS := readNameservers("/etc/resolv.conf")
	d := dialer(protect)
	r := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			targets := dnsTargets(address, bootDNS)
			var lastErr error
			for _, target := range targets {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				conn, err := d.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	return &hostCache{
		cache: make(map[string][]netip.Addr),
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return r.LookupNetIP(ctx, "ip", host)
		},
		bootDNS: bootDNS,
	}
}

// resolve returns the IP addresses for host. If host is an IP literal, it is returned
// directly. Otherwise lookup is called; on success the result is cached and returned;
// on error the cached addresses are returned if present, or the error if not.
func (c *hostCache) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	if c == nil {
		r := &net.Resolver{}
		return r.LookupNetIP(ctx, "ip", host)
	}
	c.mu.Lock()
	_, known := c.cache[host]
	c.mu.Unlock()
	lctx := ctx
	if known {
		// A cached answer exists: do not wait the resolver's full timeout for a tunnel DNS
		// that may be down.
		var cancel context.CancelFunc
		lctx, cancel = context.WithTimeout(ctx, cacheLookupTimeout)
		defer cancel()
	}
	ips, err := c.lookup(lctx, host)
	if err == nil {
		if len(ips) == 0 {
			err = fmt.Errorf("mobile: no addresses found for %s", host)
		} else {
			c.mu.Lock()
			if c.cache == nil {
				c.cache = make(map[string][]netip.Addr)
			}
			c.cache[host] = ips
			c.mu.Unlock()
			return ips, nil
		}
	}
	c.mu.Lock()
	cached, ok := c.cache[host]
	c.mu.Unlock()
	if ok && len(cached) > 0 {
		return cached, nil
	}
	return nil, err
}

// dialContext returns a dial function that resolves addr's host via the cache and attempts
// connecting to each resolved address in order using d.DialContext, returning the first
// success or the last error.
func (c *hostCache) dialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	if c == nil {
		return d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := c.resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("mobile: no addresses for %s", host)
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
