package firewall

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// ring is a bounded FIFO that drops the oldest element when full.
type ring[T any] struct {
	buf     []T
	head, n int // head = index of oldest
}

func newRing[T any](size int) ring[T] { return ring[T]{buf: make([]T, size)} }

// push appends v and reports whether an old element was overwritten.
func (r *ring[T]) push(v T) bool {
	if len(r.buf) == 0 {
		return true
	}
	if r.n < len(r.buf) {
		r.buf[(r.head+r.n)%len(r.buf)] = v
		r.n++
		return false
	}
	r.buf[r.head] = v
	r.head = (r.head + 1) % len(r.buf)
	return true
}

// drain returns all elements oldest first and empties the ring.
func (r *ring[T]) drain() []T {
	out := make([]T, r.n)
	for i := range r.n {
		out[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	clear(r.buf)
	r.head, r.n = 0, 0
	return out
}

// newest returns up to limit elements, newest first.
func (r *ring[T]) newest(limit int) []T {
	if limit <= 0 || limit > r.n {
		limit = r.n
	}
	out := make([]T, limit)
	for i := range limit {
		out[i] = r.buf[(r.head+r.n-1-i)%len(r.buf)]
	}
	return out
}

// flowLog keeps two rings: one drained by the uploader, one for the UI (RecentFlows).
type flowLog struct {
	mu      sync.Mutex
	upload  ring[api.FlowRecord]
	recent  ring[api.FlowRecord]
	dropped uint64
}

func newFlowLog(size int) *flowLog {
	return &flowLog{upload: newRing[api.FlowRecord](size), recent: newRing[api.FlowRecord](size)}
}

func (l *flowLog) add(r api.FlowRecord) {
	l.mu.Lock()
	if l.upload.push(r) {
		l.dropped++
	}
	l.recent.push(r)
	l.mu.Unlock()
}

// appCounters are per-app totals, updated with atomics from the packet path.
type appCounters struct {
	bytesIn, bytesOut atomic.Uint64
	allowed, blocked  atomic.Uint64 // flows
}

// AppStat is the per-app traffic summary (mobile Engine.AppStats JSON).
type AppStat struct {
	App      string `json:"app"`
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
	Allowed  uint64 `json:"allowed"`
	Blocked  uint64 `json:"blocked"`
}

type appStats struct {
	mu   sync.Mutex
	apps map[string]*appCounters
}

func (s *appStats) get(app string) *appCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.apps[app]
	if !ok {
		c = &appCounters{}
		s.apps[app] = c
	}
	return c
}

func (s *appStats) snapshot() []AppStat {
	s.mu.Lock()
	out := make([]AppStat, 0, len(s.apps))
	for app, c := range s.apps {
		out = append(out, AppStat{
			App: app, BytesIn: c.bytesIn.Load(), BytesOut: c.bytesOut.Load(),
			Allowed: c.allowed.Load(), Blocked: c.blocked.Load(),
		})
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].BytesIn+out[i].BytesOut, out[j].BytesIn+out[j].BytesOut
		if ti != tj {
			return ti > tj
		}
		return out[i].App < out[j].App
	})
	return out
}

// tokenBucket rate-limits flow events. Not safe for concurrent use; guard with a mutex.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = b.burst
	} else {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// decisionCache caches cloud verdicts for "ask" flows.
type decisionCache struct {
	mu  sync.Mutex
	max int
	m   map[policy.Flow]cachedDecision
}

type cachedDecision struct {
	dec     policy.Decision
	expires time.Time
}

func (c *decisionCache) get(f policy.Flow, now time.Time) (policy.Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.m[f]
	if !ok {
		return policy.Decision{}, false
	}
	if !now.Before(d.expires) {
		delete(c.m, f)
		return policy.Decision{}, false
	}
	return d.dec, true
}

func (c *decisionCache) put(f policy.Flow, d policy.Decision, expires time.Time, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for k, v := range c.m {
			if !now.Before(v.expires) {
				delete(c.m, k)
			}
		}
		for k := range c.m { // still full: drop arbitrary entries
			if len(c.m) < c.max {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[f] = cachedDecision{dec: d, expires: expires}
}

func (c *decisionCache) reset() {
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}
