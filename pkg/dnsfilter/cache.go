package dnsfilter

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// domainCache maps resolved IP addresses back to the name the app asked for. It is bounded
// (LRU eviction) and every entry expires with the record TTL (clamped to [minTTL, maxTTL]).
type domainCache struct {
	mu      sync.Mutex
	max     int
	entries map[netip.Addr]*list.Element
	lru     *list.List // front = most recently used; values are *cacheEntry
}

type cacheEntry struct {
	ip      netip.Addr
	name    string
	expires time.Time
}

func newDomainCache(limit int) *domainCache {
	return &domainCache{max: limit, entries: make(map[netip.Addr]*list.Element, limit), lru: list.New()}
}

func (c *domainCache) put(ip netip.Addr, name string, expires time.Time) {
	ip = ip.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[ip]; ok {
		e := el.Value.(*cacheEntry)
		e.name, e.expires = name, expires
		c.lru.MoveToFront(el)
		return
	}
	c.entries[ip] = c.lru.PushFront(&cacheEntry{ip: ip, name: name, expires: expires})
	for c.lru.Len() > c.max {
		oldest := c.lru.Back()
		delete(c.entries, oldest.Value.(*cacheEntry).ip)
		c.lru.Remove(oldest)
	}
}

func (c *domainCache) get(ip netip.Addr, now time.Time) (string, bool) {
	ip = ip.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[ip]
	if !ok {
		return "", false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		delete(c.entries, ip)
		c.lru.Remove(el)
		return "", false
	}
	c.lru.MoveToFront(el)
	return e.name, true
}

func (c *domainCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
