package firewall

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Conntrack timeouts (idle).
const (
	TimeoutTCPSyn         = 30 * time.Second
	TimeoutTCPEstablished = 2 * time.Hour
	TimeoutTCPClosing     = 10 * time.Second
	TimeoutUDP            = 60 * time.Second
	TimeoutICMP           = 30 * time.Second
	TimeoutOther          = 60 * time.Second
)

const numShards = 32

// TCP states (approximate: we only need timeouts, not a full state machine).
const (
	stNew uint32 = iota
	stEstablished
	stClosing
)

// verdict is the immutable decision attached to a flow, together with the policy state it
// was computed with. When the active policy pointer differs, the flow is re-evaluated.
type verdict struct {
	dec policy.Decision
	ps  *policyState
}

// entry is one conntrack flow. key is in the outbound (app -> network) orientation.
// Fields other than the atomics are immutable after insertion.
type entry struct {
	key   packet.FlowKey
	flow  policy.Flow
	start time.Time
	app   *appCounters
	dns   bool // UDP to port 53: every query goes through dnsfilter

	v        atomic.Pointer[verdict]
	state    atomic.Uint32
	lastSeen atomic.Int64 // unix nanos (coarse clock)
	bytesOut atomic.Uint64
	bytesIn  atomic.Uint64
	done     atomic.Bool // recorded in the flow log
}

func (e *entry) timeout() time.Duration {
	switch e.key.Proto {
	case packet.ProtoTCP:
		switch e.state.Load() {
		case stEstablished:
			return TimeoutTCPEstablished
		case stClosing:
			return TimeoutTCPClosing
		}
		return TimeoutTCPSyn
	case packet.ProtoUDP:
		return TimeoutUDP
	case packet.ProtoICMP, packet.ProtoICMPv6:
		return TimeoutICMP
	}
	return TimeoutOther
}

func (e *entry) expired(now int64) bool {
	return now-e.lastSeen.Load() > int64(e.timeout())
}

type shard struct {
	mu sync.RWMutex
	m  map[packet.FlowKey]*entry
}

// conntrack is a bounded, sharded flow table. Lookups take a shard read lock only.
type conntrack struct {
	shards   [numShards]shard
	perShard int
	count    atomic.Int64
}

func newConntrack(max int) *conntrack {
	ct := &conntrack{perShard: max/numShards + 1}
	for i := range ct.shards {
		ct.shards[i].m = make(map[packet.FlowKey]*entry)
	}
	return ct
}

// shardFor is symmetric in the two directions of a flow.
func (ct *conntrack) shardFor(k packet.FlowKey) *shard {
	return &ct.shards[(k.SrcPort^k.DstPort^uint16(k.Proto))%numShards]
}

func (ct *conntrack) get(k packet.FlowKey) *entry {
	s := ct.shardFor(k)
	s.mu.RLock()
	e := s.m[k]
	s.mu.RUnlock()
	return e
}

// insert adds e unless the key exists, returning the entry now in the table. When the
// shard is full, expired entries are reaped first, then the least recently seen entry is
// evicted. evicted entries are returned so the caller can log them.
func (ct *conntrack) insert(e *entry, now int64) (cur *entry, evicted []*entry) {
	s := ct.shardFor(e.key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.m[e.key]; ok {
		return old, nil
	}
	if len(s.m) >= ct.perShard {
		var lru *entry
		for k, x := range s.m {
			if x.expired(now) {
				delete(s.m, k)
				evicted = append(evicted, x)
				continue
			}
			if lru == nil || x.lastSeen.Load() < lru.lastSeen.Load() {
				lru = x
			}
		}
		if len(s.m) >= ct.perShard && lru != nil {
			delete(s.m, lru.key)
			evicted = append(evicted, lru)
		}
		ct.count.Add(-int64(len(evicted)))
	}
	s.m[e.key] = e
	ct.count.Add(1)
	return e, evicted
}

func (ct *conntrack) remove(e *entry) {
	s := ct.shardFor(e.key)
	s.mu.Lock()
	if s.m[e.key] == e {
		delete(s.m, e.key)
		ct.count.Add(-1)
	}
	s.mu.Unlock()
}

// gc removes expired entries (all entries if all is set) and returns them.
func (ct *conntrack) gc(now int64, all bool) []*entry {
	var out []*entry
	for i := range ct.shards {
		s := &ct.shards[i]
		s.mu.Lock()
		for k, e := range s.m {
			if all || e.expired(now) {
				delete(s.m, k)
				out = append(out, e)
			}
		}
		s.mu.Unlock()
	}
	ct.count.Add(-int64(len(out)))
	return out
}

func (ct *conntrack) len() int { return int(ct.count.Load()) }
