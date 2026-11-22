package mobile

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// cacheLookupTimeout bounds a lookup for a host that already has a cached answer.
const cacheLookupTimeout = 3 * time.Second

// hostCache remembers the last successful IP resolution of external host names
// (Control Plane and Edge). When the tunnel goes down (e.g. Edge restarts),
// DNS configured via the tunnel (100.64.0.1) becomes unreachable, which would
// otherwise prevent the client from resolving the endpoints needed to reconnect.
// See issue #29: host names must keep working while the tunnel DNS is down.
type hostCache struct {
	mu     sync.Mutex
	cache  map[string][]netip.Addr
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// newHostCache constructs a hostCache with a default lookup that dials via protect.
func newHostCache(protect protectFunc) *hostCache {
	r := &net.Resolver{
		Dial: dialer(protect).DialContext,
	}
	return &hostCache{
		cache: make(map[string][]netip.Addr),
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return r.LookupNetIP(ctx, "ip", host)
		},
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
