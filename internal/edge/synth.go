package edge

import (
	"container/list"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/policy"
)

// SyntheticPrefix is the pool of synthetic IPv4 addresses the Edge resolver hands out for
// PrivateApp names (ADR-0013). It lies inside TunnelPrefix4 (100.64.0.0/10) but outside the
// addresses the registry allocates to devices.
var SyntheticPrefix = netip.MustParsePrefix(policy.SyntheticPrefix)

const (
	synthTTL     = 30             // seconds, DNS TTL of synthetic answers
	synthIdle    = 24 * time.Hour // a mapping unused for this long is dropped
	maxSynthEnts = 1 << 18
)

type synthKey struct{ tenant, name string }

type synthEntry struct {
	key  synthKey
	ip   netip.Addr
	last time.Time
}

// synthMap is the sticky, bidirectional (tenant, name) <-> synthetic IPv4 mapping. Entries
// idle out after idle without use (DNS answer or brokered connection) and the map is bounded
// to max entries, evicting the least recently used. Addresses are allocated next-fit, so a
// freed address is reused as late as possible. Safe for concurrent use.
type synthMap struct {
	mu    sync.Mutex
	byKey map[synthKey]*list.Element
	byIP  map[netip.Addr]*list.Element
	lru   *list.List // front = most recently used; values are *synthEntry
	base  uint32     // first address of the pool
	size  uint32     // number of addresses in the pool
	next  uint32     // next offset to try
	max   int
	idle  time.Duration
}

func newSynthMap(prefix netip.Prefix, max int, idle time.Duration) *synthMap {
	prefix = prefix.Masked()
	b := prefix.Addr().As4()
	return &synthMap{
		byKey: map[synthKey]*list.Element{},
		byIP:  map[netip.Addr]*list.Element{},
		lru:   list.New(),
		base:  uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
		size:  uint32(1) << (32 - prefix.Bits()),
		next:  1,
		max:   max,
		idle:  idle,
	}
}

func (m *synthMap) addrAt(off uint32) netip.Addr {
	v := m.base + off
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

var errSynthExhausted = errors.New("edge: synthetic address pool exhausted")

// assign returns the synthetic address of (tenant, name), allocating one if needed, and
// marks the mapping as used. name must be normalized.
func (m *synthMap) assign(tenant, name string, now time.Time) (netip.Addr, error) {
	k := synthKey{tenant, name}
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.byKey[k]; ok {
		e := el.Value.(*synthEntry)
		if now.Sub(e.last) <= m.idle {
			e.last = now
			m.lru.MoveToFront(el)
			return e.ip, nil
		}
		m.removeLocked(el)
	}
	for m.lru.Len() >= m.max {
		m.removeLocked(m.lru.Back())
	}
	// Offsets 0 (network) and size-1 (broadcast) are never used.
	usable := m.size - 2
	for range usable {
		off := m.next
		if m.next++; m.next >= m.size-1 {
			m.next = 1
		}
		ip := m.addrAt(off)
		if _, used := m.byIP[ip]; used {
			continue
		}
		e := &synthEntry{key: k, ip: ip, last: now}
		el := m.lru.PushFront(e)
		m.byKey[k], m.byIP[ip] = el, el
		return ip, nil
	}
	return netip.Addr{}, errSynthExhausted
}

// lookup returns the (tenant, name) of a synthetic address and marks it as used.
func (m *synthMap) lookup(ip netip.Addr, now time.Time) (tenant, name string, ok bool) {
	ip = ip.Unmap()
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.byIP[ip]
	if !ok {
		return "", "", false
	}
	e := el.Value.(*synthEntry)
	if now.Sub(e.last) > m.idle {
		m.removeLocked(el)
		return "", "", false
	}
	e.last = now
	m.lru.MoveToFront(el)
	return e.key.tenant, e.key.name, true
}

// sweep drops mappings idle for longer than the idle timeout.
func (m *synthMap) sweep(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for el := m.lru.Back(); el != nil; {
		e := el.Value.(*synthEntry)
		if now.Sub(e.last) <= m.idle {
			return // the rest is more recent
		}
		prev := el.Prev()
		m.removeLocked(el)
		el = prev
	}
}

func (m *synthMap) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lru.Len()
}

func (m *synthMap) removeLocked(el *list.Element) {
	e := el.Value.(*synthEntry)
	m.lru.Remove(el)
	delete(m.byKey, e.key)
	delete(m.byIP, e.ip)
}
