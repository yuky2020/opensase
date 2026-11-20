package edge

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// decider resolves "ask" verdicts through the Control Plane decision API, asynchronously,
// with a TTL cache. Failures fail closed for a short time.
type decider struct {
	ctx context.Context
	cp  controlPlane
	log *slog.Logger

	mu      sync.Mutex
	cache   map[decideKey]decideEntry
	pending map[decideKey]bool
	sem     chan struct{}
}

type decideKey struct {
	device, proto, ip, domain string
	port                      uint16
}

type decideEntry struct {
	d   policy.Decision
	exp time.Time
}

const (
	maxDecideInFlight = 32
	decideFailHold    = 5 * time.Second
	maxDecideCache    = 100000
)

func newDecider(ctx context.Context, cp controlPlane, log *slog.Logger) *decider {
	return &decider{ctx: ctx, cp: cp, log: log, cache: map[decideKey]decideEntry{}, pending: map[decideKey]bool{}, sem: make(chan struct{}, maxDecideInFlight)}
}

func keyOf(device string, f policy.Flow) decideKey {
	return decideKey{device: device, proto: f.Protocol, ip: f.DstIP, domain: f.Domain, port: f.DstPort}
}

func (d *decider) lookup(device string, f policy.Flow, now time.Time) (policy.Decision, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.cache[keyOf(device, f)]
	if !ok || now.After(e.exp) {
		return policy.Decision{}, false
	}
	return e.d, true
}

// request starts a decision in the background unless one is pending or too many are in flight.
func (d *decider) request(device string, f policy.Flow) {
	k := keyOf(device, f)
	d.mu.Lock()
	if d.pending[k] {
		d.mu.Unlock()
		return
	}
	select {
	case d.sem <- struct{}{}:
	default:
		d.mu.Unlock()
		return
	}
	d.pending[k] = true
	d.mu.Unlock()
	go func() {
		defer func() { <-d.sem }()
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		defer cancel()
		resp, err := d.cp.Decide(ctx, device, f)
		e := decideEntry{d: resp.Decision, exp: time.Now().Add(time.Duration(resp.TTL) * time.Second)}
		if err != nil || (resp.Decision.Action != policy.ActionAllow && resp.Decision.Action != policy.ActionBlock) {
			if err != nil {
				d.log.Warn("cloud decision failed; blocking", "device", device, "err", err)
			}
			e = decideEntry{d: policy.Decision{Action: policy.ActionBlock, RuleID: "decide:unavailable", Layer: policy.LayerCloud, Log: true}, exp: time.Now().Add(decideFailHold)}
		}
		d.mu.Lock()
		delete(d.pending, k)
		if len(d.cache) < maxDecideCache {
			d.cache[k] = e
		}
		d.mu.Unlock()
	}()
}

func (d *decider) sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, e := range d.cache {
		if now.After(e.exp) {
			delete(d.cache, k)
		}
	}
}

// snoop maps (device tunnel IP, resolved IP) to the domain the device looked up, learned from
// Edge DNS answers, so that domain rules can match flows.
type snoop struct {
	mu sync.RWMutex
	m  map[snoopKey]snoopEntry
}

type snoopKey struct{ client, ip netip.Addr }

type snoopEntry struct {
	domain string
	exp    time.Time
}

const (
	maxSnoop    = 200000
	snoopMinTTL = 60 * time.Second
	snoopMaxTTL = time.Hour
)

func newSnoop() *snoop { return &snoop{m: map[snoopKey]snoopEntry{}} }

func (s *snoop) add(client, ip netip.Addr, domain string, ttl time.Duration, now time.Time) {
	ttl = min(max(ttl, snoopMinTTL), snoopMaxTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := snoopKey{client.Unmap(), ip.Unmap()}
	if _, ok := s.m[k]; !ok && len(s.m) >= maxSnoop {
		return
	}
	s.m[k] = snoopEntry{domain: domain, exp: now.Add(ttl)}
}

func (s *snoop) lookup(client, ip netip.Addr) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[snoopKey{client, ip}]
	if !ok || time.Now().After(e.exp) {
		return ""
	}
	return e.domain
}

func (s *snoop) sweep(now time.Time, alive func(netip.Addr) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.m {
		if now.After(e.exp) || !alive(k.client) {
			delete(s.m, k)
		}
	}
}

// flowLog buffers Edge flow records for upload to the Control Plane.
type flowLog struct {
	mu    sync.Mutex
	recs  []api.FlowRecord
	local *localFlowLog // optional local JSONL copy (Config.FlowLogPath, ADR-0014)
}

const (
	maxFlowBuffer = 20000
	flowBatch     = 1000
)

func (l *flowLog) add(recs ...api.FlowRecord) {
	l.local.add(recs)
	l.mu.Lock()
	defer l.mu.Unlock()
	room := maxFlowBuffer - len(l.recs)
	if room <= 0 {
		return
	}
	l.recs = append(l.recs, recs[:min(len(recs), room)]...)
}

// flush posts buffered records; on failure they are kept (up to the buffer limit).
func (l *flowLog) flush(ctx context.Context, cp controlPlane) error {
	for {
		l.mu.Lock()
		n := min(len(l.recs), flowBatch)
		batch := append([]api.FlowRecord(nil), l.recs[:n]...)
		l.mu.Unlock()
		if n == 0 {
			return nil
		}
		if err := cp.PostFlows(ctx, batch); err != nil {
			return err
		}
		l.mu.Lock()
		l.recs = append(l.recs[:0], l.recs[n:]...)
		l.mu.Unlock()
	}
}

func (l *flowLog) pending() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recs)
}
