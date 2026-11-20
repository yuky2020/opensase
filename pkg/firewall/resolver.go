package firewall

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

// UIDResolver finds the app owning a connection. On Android it is backed by
// mobile.Platform (ConnectivityManager.getConnectionOwnerUid and PackageManager).
type UIDResolver interface {
	// ConnectionOwnerUID returns the owning Linux UID or -1. proto is 6 or 17.
	ConnectionOwnerUID(proto uint8, src, dst netip.AddrPort) int
	// PackagesForUID returns comma-separated package names, or "".
	PackagesForUID(uid int) string
}

// Decider asks the Control Plane for a verdict on an "ask" flow (POST /v1/decide).
// The returned Action must be allow or block; ttl is how long the verdict may be cached.
type Decider interface {
	Decide(ctx context.Context, f policy.Flow) (d policy.Decision, ttl time.Duration, err error)
}

// CachingResolver caches UID lookups per connection and package names per UID. Platform
// lookups are binder calls on Android and cost about a millisecond.
type CachingResolver struct {
	inner UIDResolver
	ttl   time.Duration
	max   int
	now   func() time.Time
	mu    sync.Mutex
	conns map[packet.FlowKey]cachedUID
	pkgs  map[int]cachedPkgs
}

type cachedUID struct {
	uid     int
	expires time.Time
}

type cachedPkgs struct {
	pkgs    string
	expires time.Time
}

// NewCachingResolver wraps inner. ttl bounds staleness (package lists change on app
// install/uninstall); limit bounds the per-connection cache.
func NewCachingResolver(inner UIDResolver, ttl time.Duration, limit int) *CachingResolver {
	if ttl <= 0 {
		ttl = time.Minute
	}
	if limit <= 0 {
		limit = 4096
	}
	return &CachingResolver{
		inner: inner, ttl: ttl, max: limit, now: time.Now,
		conns: make(map[packet.FlowKey]cachedUID), pkgs: make(map[int]cachedPkgs),
	}
}

// ConnectionOwnerUID implements UIDResolver.
func (r *CachingResolver) ConnectionOwnerUID(proto uint8, src, dst netip.AddrPort) int {
	k := packet.FlowKey{Proto: proto, Src: src.Addr(), Dst: dst.Addr(), SrcPort: src.Port(), DstPort: dst.Port()}
	now := r.now()
	r.mu.Lock()
	if c, ok := r.conns[k]; ok && now.Before(c.expires) {
		r.mu.Unlock()
		return c.uid
	}
	r.mu.Unlock()
	uid := r.inner.ConnectionOwnerUID(proto, src, dst)
	if uid < 0 {
		return uid // do not cache misses: the socket may not be visible yet
	}
	r.mu.Lock()
	if len(r.conns) >= r.max {
		clear(r.conns)
	}
	r.conns[k] = cachedUID{uid: uid, expires: now.Add(r.ttl)}
	r.mu.Unlock()
	return uid
}

// PackagesForUID implements UIDResolver.
func (r *CachingResolver) PackagesForUID(uid int) string {
	now := r.now()
	r.mu.Lock()
	if c, ok := r.pkgs[uid]; ok && now.Before(c.expires) {
		r.mu.Unlock()
		return c.pkgs
	}
	r.mu.Unlock()
	p := r.inner.PackagesForUID(uid)
	r.mu.Lock()
	if len(r.pkgs) >= r.max {
		clear(r.pkgs)
	}
	r.pkgs[uid] = cachedPkgs{pkgs: p, expires: now.Add(r.ttl)}
	r.mu.Unlock()
	return p
}

// firstPackage returns the first entry of a comma-separated package list.
func firstPackage(pkgs string) string {
	if i := strings.IndexByte(pkgs, ','); i >= 0 {
		pkgs = pkgs[:i]
	}
	return strings.TrimSpace(pkgs)
}
