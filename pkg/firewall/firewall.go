// Package firewall is the Client's on-device L3 firewall (ADR-0012). FilteringTUN
// wraps the platform TUN device under wireguard-go: packets from apps are classified per
// flow and evaluated against the Policy Snapshot before WireGuard encrypts them, and
// packets from the tunnel are delivered only if they belong to an allowed flow.
package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/dnsfilter"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Defaults for Config.
const (
	DefaultMaxFlows      = 16384
	DefaultFlowLogSize   = 2048
	DefaultDecideTimeout = 5 * time.Second
	DefaultFailTTL       = 10 * time.Second
	DefaultMaxInflight   = 32
	DefaultGCInterval    = 5 * time.Second

	// injectHeadroom is the offset used when writing synthesised packets to the inner TUN;
	// Linux TUNs with virtio headers need at least 10 bytes in front of the packet.
	injectHeadroom = 32
	injectBufSize  = injectHeadroom + packet.MaxICMPUnreachableLen
)

// RuleID values used for decisions that do not come from the snapshot.
const (
	RuleNoSnapshot       = "no-snapshot"
	RuleCloudUnreachable = "cloud-unreachable"
	// LayerDNS marks flow records of DNS queries blocked by the DNS policy; RuleID is
	// "dns:<listId>".
	LayerDNS = "dns"
)

// Config configures a FilteringTUN.
type Config struct {
	Inner    tun.Device
	Resolver UIDResolver            // nil: UID -1 / app "" for every flow
	Decider  Decider                // nil: "ask" flows get the fallback verdict
	DNS      *dnsfilter.Interceptor // nil: no DNS filtering or snooping
	// DNSServers are the session resolvers. Queries to them are filtered and their
	// responses snooped (IP -> domain) when they match an outstanding query. If empty,
	// queries to any UDP port 53 are still filtered, but nothing is snooped: without a
	// known resolver a response cannot be authenticated by its source.
	DNSServers []netip.Addr
	// FallbackToDefault: when the cloud cannot decide, use the snapshot DefaultAction (if it
	// is allow or block). Otherwise, and by default, block (fail-closed).
	FallbackToDefault bool
	DeviceID          string
	OnEvent           func(kind, payload string) // "flow" events; must not block
	Logger            *slog.Logger
	MaxFlows          int
	FlowLogSize       int
	DecideTimeout     time.Duration
	FailTTL           time.Duration // cache lifetime of fallback verdicts
	MaxInflight       int           // concurrent cloud decisions
	GCInterval        time.Duration // 0 = default; <0 = no background loop (tests)
	EventRate         float64       // flow events per second (default 20, burst 50)
	Now               func() time.Time
}

// policyState is one active snapshot. It is replaced as a whole.
type policyState struct {
	c             *policy.Compiled
	defaultAction policy.Action
}

// FilteringTUN implements tun.Device. Read and Write may be called concurrently.
type FilteringTUN struct {
	cfg   Config
	inner tun.Device
	log   *slog.Logger

	policy  atomic.Pointer[policyState]
	network atomic.Pointer[policy.NetworkType]
	clock   atomic.Int64 // coarse unix nanos, refreshed by slow paths and the GC loop

	ct        *conntrack
	decisions *decisionCache
	sf        singleflight.Group
	inflight  atomic.Int32
	flows     *flowLog
	stats     appStats
	events    tokenBucket
	injPool   sync.Pool

	// Counters.
	dropsParse, dropsInbound, dropsFragment, dropsPending, dropsLocal, injected atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool
}

var _ tun.Device = (*FilteringTUN)(nil)

// New wraps cfg.Inner. Until SetPolicy is called every flow is blocked (fail-closed).
func New(cfg Config) (*FilteringTUN, error) {
	if cfg.Inner == nil {
		return nil, errors.New("firewall: Inner tun.Device is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = DefaultMaxFlows
	}
	if cfg.FlowLogSize <= 0 {
		cfg.FlowLogSize = DefaultFlowLogSize
	}
	if cfg.DecideTimeout <= 0 {
		cfg.DecideTimeout = DefaultDecideTimeout
	}
	if cfg.FailTTL <= 0 {
		cfg.FailTTL = DefaultFailTTL
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	}
	if cfg.GCInterval == 0 {
		cfg.GCInterval = DefaultGCInterval
	}
	if cfg.EventRate <= 0 {
		cfg.EventRate = 20
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &FilteringTUN{
		cfg:       cfg,
		inner:     cfg.Inner,
		log:       cfg.Logger,
		ct:        newConntrack(cfg.MaxFlows),
		decisions: &decisionCache{max: cfg.MaxFlows, m: make(map[policy.Flow]cachedDecision)},
		flows:     newFlowLog(cfg.FlowLogSize),
		stats:     appStats{apps: make(map[string]*appCounters)},
		events:    tokenBucket{rate: cfg.EventRate, burst: 50},
		ctx:       ctx,
		cancel:    cancel,
	}
	f.injPool.New = func() any { b := make([]byte, injectBufSize); return &b }
	nt := policy.NetworkUnknown
	f.network.Store(&nt)
	f.refreshClock()
	if cfg.GCInterval > 0 {
		f.wg.Add(1)
		go f.loop(cfg.GCInterval)
	}
	return f, nil
}

// SetPolicy atomically installs a compiled snapshot. defaultAction is the snapshot's
// Firewall.DefaultAction (used for the cloud-unreachable fallback). Existing flows are
// re-evaluated lazily on their next packet.
func (f *FilteringTUN) SetPolicy(c *policy.Compiled, defaultAction policy.Action) {
	if c == nil {
		f.policy.Store(nil)
		return
	}
	f.policy.Store(&policyState{c: c, defaultAction: defaultAction})
}

// Policy returns the active compiled snapshot, or nil.
func (f *FilteringTUN) Policy() *policy.Compiled {
	if ps := f.policy.Load(); ps != nil {
		return ps.c
	}
	return nil
}

// SetNetwork sets the network type used for new flows (and re-evaluated ones).
func (f *FilteringTUN) SetNetwork(n policy.NetworkType) {
	if n == "" {
		n = policy.NetworkUnknown
	}
	if *f.network.Load() == n {
		return
	}
	f.network.Store(&n)
	// Per-network app policies: force lazy re-evaluation of every flow by installing a
	// copy of the current policy state (new pointer, same content).
	if ps := f.policy.Load(); ps != nil {
		cp := *ps
		f.policy.CompareAndSwap(ps, &cp)
	}
}

func (f *FilteringTUN) refreshClock() int64 {
	n := f.cfg.Now().UnixNano()
	f.clock.Store(n)
	return n
}

func (f *FilteringTUN) loop(interval time.Duration) {
	defer f.wg.Done()
	clk := time.NewTicker(250 * time.Millisecond)
	defer clk.Stop()
	gc := time.NewTicker(interval)
	defer gc.Stop()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-clk.C:
			f.refreshClock()
		case <-gc.C:
			f.GC()
		}
	}
}

// GC expires idle flows and records them in the flow log.
func (f *FilteringTUN) GC() {
	now := f.refreshClock()
	for _, e := range f.ct.gc(now, false) {
		f.finish(e, now)
	}
}

// Flush ends every tracked flow and records it (call before a final Drain on shutdown).
func (f *FilteringTUN) Flush() {
	now := f.refreshClock()
	for _, e := range f.ct.gc(now, true) {
		f.finish(e, now)
	}
}

// Drain returns and clears the flow records waiting for upload (oldest first).
func (f *FilteringTUN) Drain() []api.FlowRecord {
	f.flows.mu.Lock()
	defer f.flows.mu.Unlock()
	return f.flows.upload.drain()
}

// RecentFlows returns up to limit recent flow records, newest first.
func (f *FilteringTUN) RecentFlows(limit int) []api.FlowRecord {
	f.flows.mu.Lock()
	defer f.flows.mu.Unlock()
	return f.flows.recent.newest(limit)
}

// AppStats returns per-app counters, busiest first.
func (f *FilteringTUN) AppStats() []AppStat { return f.stats.snapshot() }

// Counters is a debugging snapshot of internal counters.
type Counters struct {
	Flows         int    `json:"flows"`
	DropsParse    uint64 `json:"dropsParse"`
	DropsInbound  uint64 `json:"dropsInbound"`
	DropsFragment uint64 `json:"dropsFragment"`
	DropsPending  uint64 `json:"dropsPending"`
	DropsLocal    uint64 `json:"dropsLocal"` // link-local ICMPv6 (ND, RS, MLD), dropped silently
	Injected      uint64 `json:"injected"`
	FlowLogLost   uint64 `json:"flowLogLost"`
}

// Counters returns internal counters.
func (f *FilteringTUN) Counters() Counters {
	f.flows.mu.Lock()
	lost := f.flows.dropped
	f.flows.mu.Unlock()
	return Counters{
		Flows: f.ct.len(), DropsParse: f.dropsParse.Load(), DropsInbound: f.dropsInbound.Load(),
		DropsFragment: f.dropsFragment.Load(), DropsPending: f.dropsPending.Load(), DropsLocal: f.dropsLocal.Load(),
		Injected: f.injected.Load(), FlowLogLost: lost,
	}
}

// --- tun.Device ---

// File returns the inner device's file.
func (f *FilteringTUN) File() *os.File { return f.inner.File() }

// MTU returns the inner device's MTU.
func (f *FilteringTUN) MTU() (int, error) { return f.inner.MTU() }

// Name returns the inner device's interface name.
func (f *FilteringTUN) Name() (string, error) { return f.inner.Name() }

// Events returns the inner device's event channel.
func (f *FilteringTUN) Events() <-chan tun.Event { return f.inner.Events() }

// BatchSize returns the inner device's batch size.
func (f *FilteringTUN) BatchSize() int { return f.inner.BatchSize() }

// Close stops background work and closes the inner device.
func (f *FilteringTUN) Close() error {
	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}
	f.cancel()
	err := f.inner.Close()
	f.wg.Wait()
	return err
}

// Read is the app -> network path, called by wireguard-go. Dropped packets are removed
// from the batch; it only returns once at least one packet passes or the inner read fails.
func (f *FilteringTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := f.inner.Read(bufs, sizes, offset)
		out := 0
		for i := range n {
			pkt := bufs[i][offset : offset+sizes[i]] //nolint:gosec // G602: tun.Device.Read returns n <= len(bufs), len(sizes)
			if !f.outbound(pkt) {
				continue
			}
			if out != i {
				copy(bufs[out][offset:], pkt)
				sizes[out] = sizes[i] //nolint:gosec // G602: out < i < n <= len(sizes)
			}
			out++
		}
		if out > 0 || err != nil || n == 0 {
			return out, err
		}
	}
}

// Write is the network -> app path, called by wireguard-go with decrypted packets.
// Packets that do not belong to an allowed flow are dropped. It reports all packets as
// consumed so wireguard-go does not treat drops as errors.
func (f *FilteringTUN) Write(bufs [][]byte, offset int) (int, error) {
	keep := bufs[:0:0]
	allKept := true
	for i, b := range bufs {
		if f.inbound(b[offset:]) {
			if !allKept {
				keep = append(keep, b)
			}
			continue
		}
		if allKept {
			allKept = false
			keep = make([][]byte, 0, len(bufs))
			keep = append(keep, bufs[:i]...)
		}
	}
	if allKept {
		keep = bufs
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	if _, err := f.inner.Write(keep, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

// --- outbound ---

func (f *FilteringTUN) outbound(pkt []byte) bool {
	var p packet.Packet
	if err := packet.Parse(pkt, &p); err != nil {
		f.dropsParse.Add(1)
		return false
	}
	if p.FragmentOffset > 0 {
		// Non-first fragments carry no ports and cannot be attributed to a flow.
		f.dropsFragment.Add(1)
		return false
	}
	if linkLocalICMPv6(&p) {
		// Neighbour discovery, router solicitation and MLD only make sense on the local
		// link; the tunnel has none. Drop without a flow entry, log record or reply.
		f.dropsLocal.Add(1)
		return false
	}
	key := p.FlowKey()
	ps := f.policy.Load()
	if e := f.ct.get(key); e != nil && !e.dns {
		if v := e.v.Load(); v.ps == ps && ps != nil {
			if v.dec.Action == policy.ActionAllow {
				f.touchOut(e, &p, len(pkt), f.clock.Load())
				return true
			}
			f.reject(&p, pkt)
			return false
		}
		return f.slowOutbound(&p, pkt, key, e, ps)
	}
	return f.slowOutbound(&p, pkt, key, f.ct.get(key), ps)
}

// linkLocalICMPv6 reports whether p is ICMPv6 that is scoped to the local link: any
// neighbour discovery / router discovery / MLD message (types 130-137, 143), or any ICMPv6
// sent to a multicast or link-local address (e.g. router solicitation to ff02::2).
func linkLocalICMPv6(p *packet.Packet) bool {
	if p.Version != 6 || p.Protocol != packet.ProtoICMPv6 {
		return false
	}
	if (p.ICMPType >= 130 && p.ICMPType <= 137) || p.ICMPType == 143 {
		return true
	}
	return p.Dst.IsMulticast() || p.Dst.IsLinkLocalUnicast()
}

func (f *FilteringTUN) touchOut(e *entry, p *packet.Packet, n int, now int64) {
	e.lastSeen.Store(now)
	e.bytesOut.Add(uint64(n))
	e.app.bytesOut.Add(uint64(n))
	if p.Protocol == packet.ProtoTCP {
		switch {
		case p.RST() || p.FIN():
			e.state.Store(stClosing)
		case e.state.Load() == stNew && p.ACK() && !p.SYN():
			// Our ACK after the peer's SYN-ACK, or a mid-stream flow: established.
			e.state.CompareAndSwap(stNew, stEstablished)
		}
	}
}

func (f *FilteringTUN) touchIn(e *entry, p *packet.Packet, n int, now int64) {
	e.lastSeen.Store(now)
	e.bytesIn.Add(uint64(n))
	e.app.bytesIn.Add(uint64(n))
	if p.Protocol == packet.ProtoTCP {
		switch {
		case p.RST() || p.FIN():
			e.state.Store(stClosing)
		case p.SYN() && p.ACK():
			e.state.CompareAndSwap(stNew, stEstablished)
		}
	}
}

func (f *FilteringTUN) slowOutbound(p *packet.Packet, pkt []byte, key packet.FlowKey, e *entry, ps *policyState) bool {
	now := f.refreshClock()
	if e == nil {
		fl := f.buildFlow(p)
		dec, ok := f.evaluate(fl, ps, nil)
		if !ok {
			f.dropsPending.Add(1)
			return false
		}
		ne := &entry{
			key:   key,
			flow:  fl,
			start: time.Unix(0, now),
			app:   f.stats.get(fl.App),
			dns:   f.isDNS(p),
		}
		ne.lastSeen.Store(now)
		if p.Protocol == packet.ProtoTCP && !p.SYN() {
			ne.state.Store(stEstablished) // mid-stream (e.g. after a restart)
		}
		ne.v.Store(&verdict{dec: dec, ps: ps})
		var evicted []*entry
		e, evicted = f.ct.insert(ne, now)
		for _, x := range evicted {
			f.finish(x, now)
		}
		if e == ne {
			f.started(e, dec, now)
		}
	} else if v := e.v.Load(); v.ps != ps {
		if !f.reevaluate(e, ps, now) {
			f.dropsPending.Add(1)
			return false
		}
	}
	v := e.v.Load()
	if v.dec.Action != policy.ActionAllow {
		f.reject(p, pkt)
		return false
	}
	if e.dns && !f.handleDNS(e, p, v.ps) {
		return false
	}
	f.touchOut(e, p, len(pkt), now)
	return true
}

// reevaluate recomputes e's verdict for ps. It returns false if the verdict is pending a
// cloud decision (the packet must be dropped, the flow is kept).
func (f *FilteringTUN) reevaluate(e *entry, ps *policyState, now int64) bool {
	old := e.v.Load()
	fl := e.flow
	fl.Network = *f.network.Load() // the network may have changed since the flow started
	dec, ok := f.evaluate(fl, ps, old)
	if !ok {
		return false
	}
	if e.v.CompareAndSwap(old, &verdict{dec: dec, ps: ps}) &&
		old.dec.Action == policy.ActionAllow && dec.Action != policy.ActionAllow {
		e.app.blocked.Add(1)
		f.record(e, dec, now, true)
	}
	return true
}

// evaluate returns the verdict for fl. ok=false means an "ask" decision is pending.
func (f *FilteringTUN) evaluate(fl policy.Flow, ps *policyState, prev *verdict) (policy.Decision, bool) {
	if ps == nil {
		return policy.Decision{Action: policy.ActionBlock, RuleID: RuleNoSnapshot, Layer: policy.LayerDefault}, true
	}
	d := ps.c.Evaluate(fl, false)
	if d.Action != policy.ActionAsk {
		return d, true
	}
	now := time.Unix(0, f.clock.Load())
	if cd, ok := f.decisions.get(fl, now); ok {
		cd.Log = cd.Log || d.Log
		return cd, true
	}
	if f.cfg.Decider == nil {
		return f.fallback(ps), true
	}
	f.askAsync(fl, ps)
	if prev != nil && prev.dec.Layer == policy.LayerCloud {
		return prev.dec, true // keep an established cloud verdict while refreshing it
	}
	return policy.Decision{}, false
}

func (f *FilteringTUN) fallback(ps *policyState) policy.Decision {
	a := policy.ActionBlock
	if f.cfg.FallbackToDefault && ps != nil &&
		(ps.defaultAction == policy.ActionAllow || ps.defaultAction == policy.ActionBlock) {
		a = ps.defaultAction
	}
	return policy.Decision{Action: a, RuleID: RuleCloudUnreachable, Layer: policy.LayerCloud}
}

// askAsync starts one cloud decision per distinct flow; duplicates join the in-flight call.
func (f *FilteringTUN) askAsync(fl policy.Flow, ps *policyState) {
	if f.closed.Load() || int(f.inflight.Load()) >= f.cfg.MaxInflight {
		return
	}
	f.sf.DoChan(decisionKey(fl), func() (any, error) {
		// Not tracked by f.wg: the call ends when f.ctx is cancelled by Close.
		f.inflight.Add(1)
		defer f.inflight.Add(-1)
		ctx, cancel := context.WithTimeout(f.ctx, f.cfg.DecideTimeout)
		defer cancel()
		d, ttl, err := f.cfg.Decider.Decide(ctx, fl)
		now := f.cfg.Now()
		if err != nil || (d.Action != policy.ActionAllow && d.Action != policy.ActionBlock) {
			if err == nil {
				err = errors.New("invalid action " + strconv.Quote(string(d.Action)))
			}
			f.log.Warn("cloud decision failed, using fallback", "err", err, "proto", fl.Protocol, "dstPort", fl.DstPort)
			d, ttl = f.fallback(ps), f.cfg.FailTTL
		} else {
			d.Layer = policy.LayerCloud
			if ttl <= 0 {
				ttl = time.Minute
			}
		}
		f.decisions.put(fl, d, now.Add(ttl), now)
		return nil, nil
	})
}

func decisionKey(fl policy.Flow) string {
	b := make([]byte, 0, 96)
	b = append(b, fl.App...)
	b = append(b, 0)
	b = strconv.AppendInt(b, int64(fl.UID), 10)
	b = append(b, 0)
	b = append(b, fl.Network...)
	b = append(b, 0)
	b = append(b, fl.Protocol...)
	b = append(b, 0)
	b = append(b, fl.DstIP...)
	b = append(b, 0)
	b = strconv.AppendUint(b, uint64(fl.DstPort), 10)
	b = append(b, 0)
	b = append(b, fl.Domain...)
	return string(b)
}

func (f *FilteringTUN) buildFlow(p *packet.Packet) policy.Flow {
	fl := policy.Flow{
		UID:     -1,
		Network: *f.network.Load(),
		DstIP:   p.Dst.Unmap().String(),
	}
	switch p.Protocol {
	case packet.ProtoTCP:
		fl.Protocol = "tcp"
	case packet.ProtoUDP:
		fl.Protocol = "udp"
	case packet.ProtoICMP:
		fl.Protocol = "icmp"
	case packet.ProtoICMPv6:
		fl.Protocol = "icmpv6"
	default:
		fl.Protocol = strconv.Itoa(int(p.Protocol))
	}
	if p.Protocol == packet.ProtoTCP || p.Protocol == packet.ProtoUDP {
		fl.DstPort = p.DstPort
		if r := f.cfg.Resolver; r != nil {
			src := netip.AddrPortFrom(p.Src, p.SrcPort)
			dst := netip.AddrPortFrom(p.Dst, p.DstPort)
			if uid := r.ConnectionOwnerUID(p.Protocol, src, dst); uid >= 0 {
				fl.UID = uid
				fl.App = firstPackage(r.PackagesForUID(uid))
			}
		}
	}
	if f.cfg.DNS != nil {
		fl.Domain = f.cfg.DNS.Domain(p.Dst)
	}
	return fl
}

func (f *FilteringTUN) isDNS(p *packet.Packet) bool {
	if f.cfg.DNS == nil || p.Protocol != packet.ProtoUDP || p.DstPort != 53 {
		return false
	}
	if len(f.cfg.DNSServers) == 0 {
		return true
	}
	dst := p.Dst.Unmap()
	for _, s := range f.cfg.DNSServers {
		if s.Unmap() == dst {
			return true
		}
	}
	return false
}

// handleDNS runs one DNS query through dnsfilter. It returns true if the query may go on
// to the resolver; for a blocked name, the synthesised answer is injected instead.
func (f *FilteringTUN) handleDNS(e *entry, p *packet.Packet, ps *policyState) bool {
	var c *policy.Compiled
	if ps != nil {
		c = ps.c
	}
	src := netip.AddrPortFrom(p.Src, p.SrcPort)
	dst := netip.AddrPortFrom(p.Dst, p.DstPort)
	res, err := f.cfg.DNS.HandleQuery(c, e.flow.App, src, dst, p.Payload)
	if err != nil {
		f.dropsParse.Add(1)
		return false
	}
	if !res.Blocked {
		return true
	}
	f.inject(res.Response)
	rec := api.FlowRecord{
		Start: time.Unix(0, f.clock.Load()), Flow: e.flow, Where: "device", DeviceID: f.cfg.DeviceID,
		Decision: policy.Decision{Action: policy.ActionBlock, RuleID: "dns:" + res.ListID, Layer: LayerDNS},
	}
	rec.Flow.Domain = res.Name
	f.flows.add(rec)
	f.emitIfAllowed(rec)
	return false
}

// reject drops a blocked packet and answers it so the app fails fast.
func (f *FilteringTUN) reject(p *packet.Packet, pkt []byte) {
	bp := f.injPool.Get().(*[]byte)
	defer f.injPool.Put(bp)
	buf := *bp
	var n int
	var err error
	if p.Protocol == packet.ProtoTCP {
		if p.RST() {
			return
		}
		n, err = packet.BuildTCPReset(p, pkt, buf[injectHeadroom:])
	} else {
		n, err = packet.BuildICMPUnreachable(pkt, buf[injectHeadroom:])
	}
	if err != nil {
		return
	}
	f.write(buf[:injectHeadroom+n])
}

// inject writes a synthesised packet (starting at the IP header) to the inner TUN.
func (f *FilteringTUN) inject(pkt []byte) {
	buf := make([]byte, injectHeadroom+len(pkt))
	copy(buf[injectHeadroom:], pkt)
	f.write(buf)
}

func (f *FilteringTUN) write(buf []byte) {
	if _, err := f.inner.Write([][]byte{buf}, injectHeadroom); err != nil {
		f.log.Debug("inject failed", "err", err)
		return
	}
	f.injected.Add(1)
}

// --- inbound ---

func (f *FilteringTUN) inbound(pkt []byte) bool {
	var p packet.Packet
	if err := packet.Parse(pkt, &p); err != nil {
		f.dropsParse.Add(1)
		return false
	}
	if p.FragmentOffset > 0 {
		f.dropsFragment.Add(1)
		return false
	}
	var key packet.FlowKey
	if q, ok := quotedFlowKey(&p); ok {
		key = q // ICMP error about one of our flows (e.g. PMTU "packet too big")
	} else {
		key = p.FlowKey().Reverse()
	}
	e := f.ct.get(key)
	if e == nil {
		f.dropsInbound.Add(1)
		return false
	}
	ps := f.policy.Load()
	v := e.v.Load()
	if v.ps != ps {
		if !f.reevaluate(e, ps, f.refreshClock()) {
			f.dropsPending.Add(1)
			return false
		}
		v = e.v.Load()
	}
	if v.dec.Action != policy.ActionAllow {
		f.dropsInbound.Add(1)
		return false
	}
	f.touchIn(e, &p, len(pkt), f.clock.Load())
	// e.dns implies the query went to one of DNSServers (isDNS); dnsfilter additionally
	// matches the response to the outstanding query (txid, qname, client port, server).
	if e.dns && len(f.cfg.DNSServers) > 0 && p.Protocol == packet.ProtoUDP && p.SrcPort == 53 {
		f.cfg.DNS.SnoopResponse(netip.AddrPortFrom(p.Src, p.SrcPort), netip.AddrPortFrom(p.Dst, p.DstPort), p.Payload)
	}
	return true
}

// quotedFlowKey extracts the outbound flow key from the datagram quoted in an inbound
// ICMP/ICMPv6 error. The quote is truncated, so packet.Parse cannot be used.
func quotedFlowKey(p *packet.Packet) (packet.FlowKey, bool) {
	isErr := (p.Protocol == packet.ProtoICMP && p.Version == 4 && (p.ICMPType == 3 || p.ICMPType == 11 || p.ICMPType == 12)) ||
		(p.Protocol == packet.ProtoICMPv6 && p.Version == 6 && p.ICMPType < 128)
	if !isErr || p.TransportLen == 0 {
		return packet.FlowKey{}, false
	}
	q := p.Payload
	var k packet.FlowKey
	var l4 []byte
	switch {
	case len(q) >= 20 && q[0]>>4 == 4:
		ihl := int(q[0]&0x0f) * 4
		if ihl < 20 || len(q) < ihl+4 {
			return k, false
		}
		k.Proto = q[9]
		k.Src = netip.AddrFrom4([4]byte(q[12:16]))
		k.Dst = netip.AddrFrom4([4]byte(q[16:20]))
		l4 = q[ihl:]
	case len(q) >= 44 && q[0]>>4 == 6:
		k.Proto = q[6] // extension headers in quotes are not followed
		k.Src = netip.AddrFrom16([16]byte(q[8:24]))
		k.Dst = netip.AddrFrom16([16]byte(q[24:40]))
		l4 = q[40:]
	default:
		return k, false
	}
	switch k.Proto {
	case packet.ProtoTCP, packet.ProtoUDP:
		k.SrcPort = uint16(l4[0])<<8 | uint16(l4[1])
		k.DstPort = uint16(l4[2])<<8 | uint16(l4[3])
	default:
		return k, false
	}
	// The quoted packet was sent by us: its source must be the error's destination.
	if k.Src != p.Dst {
		return k, false
	}
	return k, true
}

// --- flow log ---

// started accounts a new flow and emits/records it if needed.
func (f *FilteringTUN) started(e *entry, dec policy.Decision, now int64) {
	if dec.Action == policy.ActionAllow {
		e.app.allowed.Add(1)
		if dec.Log {
			f.emitIfAllowed(f.recordFor(e, dec, 0))
		}
		return
	}
	e.app.blocked.Add(1)
	f.record(e, dec, now, true)
}

// record logs e immediately (blocks); emit sends a rate-limited "flow" event.
func (f *FilteringTUN) record(e *entry, dec policy.Decision, now int64, emit bool) {
	rec := f.recordFor(e, dec, now)
	f.flows.add(rec)
	if emit {
		f.emitIfAllowed(rec)
	}
}

func (f *FilteringTUN) recordFor(e *entry, dec policy.Decision, end int64) api.FlowRecord {
	rec := api.FlowRecord{
		Start: e.start, Flow: e.flow, Decision: dec,
		BytesOut: e.bytesOut.Load(), BytesIn: e.bytesIn.Load(),
		Where: "device", DeviceID: f.cfg.DeviceID,
	}
	if end != 0 {
		rec.End = time.Unix(0, end)
	}
	return rec
}

// finish records an allowed flow when it leaves the table.
func (f *FilteringTUN) finish(e *entry, now int64) {
	if !e.done.CompareAndSwap(false, true) {
		return
	}
	v := e.v.Load()
	if v.dec.Action != policy.ActionAllow {
		return // blocks were recorded when they happened
	}
	end := e.lastSeen.Load()
	if end == 0 {
		end = now
	}
	f.record(e, v.dec, end, v.dec.Log)
}

func (f *FilteringTUN) emitIfAllowed(rec api.FlowRecord) {
	if f.cfg.OnEvent == nil || !f.events.allow(time.Unix(0, f.clock.Load())) {
		return
	}
	f.emit(rec)
}

func (f *FilteringTUN) emit(rec api.FlowRecord) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f.cfg.OnEvent("flow", string(b))
}
