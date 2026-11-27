package edge

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

const (
	pumpOffset   = 16    // headroom for the Linux TUN virtio header
	maxPacket    = 65535 // largest IP packet
	injectQueue  = 256
	maxConns     = 1 << 18
	blockedHold  = 10 * time.Second
	closedHold   = 10 * time.Second
	tcpIdle      = 5 * time.Minute
	tcpSynIdle   = 30 * time.Second
	udpIdle      = 60 * time.Second
	localUDPIdle = 15 * time.Second
	icmpIdle     = 30 * time.Second
)

// Filter wraps the WireGuard TUN and enforces each device's Policy Snapshot in edge mode.
//
// Direction naming follows the device: Write carries packets decrypted from WireGuard peers
// toward the kernel ("outbound", device -> internet); Read carries packets from the kernel
// toward peers ("inbound", internet -> device). New flows are only accepted outbound;
// inbound packets must belong to an existing flow (stateful). Blocked flows are dropped and
// answered with a TCP RST or ICMP unreachable injected back into the tunnel.
type Filter struct {
	tun.Device
	e  *Edge
	ct *conntrack

	inject chan []byte
	pumpCh chan *readBatch
	ack    chan struct{}
	closed chan struct{}
	once   sync.Once
}

type readBatch struct {
	bufs  [][]byte
	sizes []int
	n     int
	err   error
}

func newFilter(inner tun.Device, e *Edge) *Filter {
	f := &Filter{
		Device: inner,
		e:      e,
		ct:     e.ct,
		inject: make(chan []byte, injectQueue),
		pumpCh: make(chan *readBatch),
		ack:    make(chan struct{}),
		closed: make(chan struct{}),
	}
	go f.pump()
	return f
}

// pump reads the kernel TUN so that Read can also deliver injected packets promptly.
func (f *Filter) pump() {
	bs := f.BatchSize()
	b := &readBatch{bufs: make([][]byte, bs), sizes: make([]int, bs)}
	for i := range b.bufs {
		b.bufs[i] = make([]byte, pumpOffset+maxPacket)
	}
	for {
		b.n, b.err = f.Device.Read(b.bufs, b.sizes, pumpOffset)
		select {
		case f.pumpCh <- b:
		case <-f.closed:
			return
		}
		select {
		case <-f.ack:
		case <-f.closed:
			return
		}
		if errors.Is(b.err, os.ErrClosed) {
			return
		}
	}
}

// Read implements tun.Device.
func (f *Filter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case pkt := <-f.inject:
			n := 0
			for {
				sizes[n] = copy(bufs[n][offset:], pkt)
				n++
				if n == len(bufs) {
					return n, nil
				}
				select {
				case pkt = <-f.inject:
				default:
					return n, nil
				}
			}
		case b := <-f.pumpCh:
			n := 0
			for i := 0; i < b.n && n < len(bufs); i++ {
				pkt := b.bufs[i][pumpOffset : pumpOffset+b.sizes[i]]
				if f.inbound(pkt) {
					sizes[n] = copy(bufs[n][offset:], pkt)
					n++
				}
			}
			err := b.err
			f.ack <- struct{}{}
			if n > 0 || err != nil {
				return n, err
			}
		case <-f.closed:
			return 0, os.ErrClosed
		}
	}
}

// Write implements tun.Device. It is called concurrently by WireGuard receive routines.
func (f *Filter) Write(bufs [][]byte, offset int) (int, error) {
	out := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if f.outbound(b[offset:]) {
			out = append(out, b)
		}
	}
	if len(out) > 0 {
		if _, err := f.Device.Write(out, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// Close implements tun.Device.
func (f *Filter) Close() error {
	f.once.Do(func() { close(f.closed) })
	return f.Device.Close()
}

func protoName(p uint8) string {
	switch p {
	case packet.ProtoTCP:
		return "tcp"
	case packet.ProtoUDP:
		return "udp"
	case packet.ProtoICMP:
		return "icmp"
	case packet.ProtoICMPv6:
		return "icmpv6"
	}
	return ""
}

func isICMP(proto string) bool {
	return proto == "icmp" || proto == "icmpv6"
}

func isEchoRequest(p *packet.Packet) bool {
	return (p.Protocol == packet.ProtoICMP && p.ICMPType == 8) || (p.Protocol == packet.ProtoICMPv6 && p.ICMPType == 128)
}

func isICMPError(p *packet.Packet) bool {
	switch p.Protocol {
	case packet.ProtoICMP:
		return p.ICMPType == 3 || p.ICMPType == 11 || p.ICMPType == 12
	case packet.ProtoICMPv6:
		return p.ICMPType >= 1 && p.ICMPType <= 4
	}
	return false
}

// outbound decides a packet from a device. It returns true to forward it.
func (f *Filter) outbound(pkt []byte) bool {
	var p packet.Packet
	if packet.Parse(pkt, &p) != nil {
		return false
	}
	// WireGuard's cryptokey routing guarantees the source address belongs to the peer.
	d := f.e.reg.byTunnelIP(p.Src)
	if d == nil {
		return false
	}
	c := d.compiled.Load()
	if c == nil {
		return false
	}
	dst := p.Dst.Unmap()
	if p.FragmentOffset > 0 {
		return false // non-first fragments carry no ports; the client MTU avoids fragmentation
	}
	local := dst == EdgeIPv4 || dst == EdgeIPv6
	synthetic := dst.Is4() && SyntheticPrefix.Contains(dst)
	key := p.FlowKey()
	now := time.Now()
	if !local && !synthetic && (TunnelPrefix4.Contains(dst) || TunnelPrefix6.Contains(dst)) {
		return f.meshOutbound(&p, pkt, d, key, dst, now) // device to device (ADR-0034)
	}
	if cn := f.ct.get(key); cn != nil && cn.deviceID == d.id {
		if cn.blocked.Load() {
			f.reject(&p, pkt)
			return false
		}
		// Web control (ADR-0017): the first bytes of an allowed TCP flow name its host.
		if cn.peek != nil && len(p.Payload) > 0 && !f.inspect(cn, c, &p, pkt, dst, now) {
			return false
		}
		cn.touch(now, len(pkt), true, &p)
		return true
	}
	proto := protoName(p.Protocol)
	switch {
	case proto == "":
		return false
	case p.Protocol == packet.ProtoTCP && (!p.SYN() || p.ACK()):
		return false // mid-stream segment without state
	case isICMP(proto) && !isEchoRequest(&p):
		return false
	}
	if synthetic {
		return f.ztnaOutbound(&p, pkt, d, key, dst, now)
	}
	if local {
		// The Edge only serves DNS and answers pings on its tunnel address.
		if !isICMP(proto) && p.DstPort != 53 {
			f.reject(&p, pkt)
			return false
		}
		return f.ct.add(key, &conn{deviceID: d.id, proto: p.Protocol, local: true, start: now}, now, len(pkt), &p)
	}
	flow := policy.Flow{Protocol: proto, SrcIP: p.Src.Unmap().String(), DstIP: dst.String(), DstPort: p.DstPort, Domain: f.e.snoop.lookup(d.id, dst)}
	if isICMP(proto) {
		flow.DstPort = 0
	}
	// Built-in Edge rules (metadata, internal networks, DNS bypass) come before any policy.
	dec, builtin := f.e.guard.check(dst, flow)
	if builtin && dec.RuleID == RuleDNSBypass && flow.DstPort == dnsPort && (dst.Is4() || f.e.ipv6) && c.RedirectDNS() {
		// Forced DNS (issue #63): the kernel DNATs it to the Edge resolver (redirectDNS).
		dec = policy.Decision{Action: policy.ActionAllow, RuleID: RuleDNSRedirect, Layer: LayerEdge, Log: true}
	}
	if !builtin {
		dec = c.Evaluate(flow, true)
	}
	if dec.Action == policy.ActionAsk {
		cached, ok := f.e.dec.lookup(d.id, flow, now)
		if !ok {
			// First packet of an undecided flow is dropped; the retransmission finds the verdict.
			f.e.dec.request(d.id, flow)
			return false
		}
		dec = cached
	}
	// Inspection (ADR-0018): web flows that would escape the inspection path are refused,
	// so the browser falls back to TCP over IPv4.
	if dec.Action == policy.ActionAllow && f.e.insp != nil {
		if rule := webBlockRule(c, p.Protocol, dst, p.DstPort); rule != "" {
			dec = policy.Decision{Action: policy.ActionBlock, RuleID: rule, Layer: LayerWeb, Log: true}
		}
	}
	cn := &conn{deviceID: d.id, proto: p.Protocol, flow: flow, decision: dec, start: now}
	if dec.Action != policy.ActionAllow {
		cn.blocked.Store(true)
		if f.ct.add(key, cn, now, len(pkt), &p) {
			f.e.flows.add(cn.record(now))
		}
		f.reject(&p, pkt)
		return false
	}
	if p.Protocol == packet.ProtoTCP {
		cn.peek = newHostPeek(&p)
	}
	return f.ct.add(key, cn, now, len(pkt), &p)
}

// ztnaOutbound decides the first packet of a flow to a synthetic PrivateApp address
// (ADR-0013). It is the only exemption from the built-in deny of 100.64.0.0/10: TCP to an
// address that maps to a name entitled in this device's snapshot is handed to the kernel,
// where the REDIRECT rule sends it to the broker listener, which re-checks the name, port
// and tenant and records the flow. Everything else is rejected here.
func (f *Filter) ztnaOutbound(p *packet.Packet, pkt []byte, d *device, key packet.FlowKey, dst netip.Addr, now time.Time) bool {
	flow := policy.Flow{Protocol: protoName(p.Protocol), SrcIP: p.Src.Unmap().String(), DstIP: dst.String(), DstPort: p.DstPort}
	if isICMP(flow.Protocol) {
		flow.DstPort = 0
	}
	rule := "ztna:tcp-only"
	if p.Protocol == packet.ProtoTCP {
		rule = "ztna:unknown-address"
		if name, ok := f.e.ztnaName(d, dst, now); ok {
			// Reported by the broker, with the real byte counts of the brokered stream.
			return f.ct.add(key, &conn{deviceID: d.id, proto: p.Protocol, local: true, start: now}, now, len(pkt), p)
		} else if name != "" {
			flow.Domain = name
		}
	}
	cn := &conn{deviceID: d.id, proto: p.Protocol, flow: flow, start: now,
		decision: policy.Decision{Action: policy.ActionBlock, RuleID: rule, Layer: LayerZTNA, Log: true}}
	cn.blocked.Store(true)
	if f.ct.add(key, cn, now, len(pkt), p) {
		f.e.flows.add(cn.record(now))
	}
	f.reject(p, pkt)
	return false
}

// inbound decides a packet toward a device. It returns true to forward it.
func (f *Filter) inbound(pkt []byte) bool {
	var p packet.Packet
	if packet.Parse(pkt, &p) != nil {
		return false
	}
	if f.e.reg.byTunnelIP(p.Dst) == nil {
		return false
	}
	if isICMPError(&p) {
		return true // PMTU and unreachable signals for known devices
	}
	cn := f.ct.get(p.FlowKey().Reverse())
	if cn == nil {
		// A mesh packet from another device comes back from the kernel in the direction of
		// the tracked flow (ADR-0034).
		if m := f.ct.get(p.FlowKey()); m != nil && m.mesh && !m.blocked.Load() {
			return true
		}
		return false
	}
	if cn.blocked.Load() {
		return false
	}
	cn.touch(time.Now(), len(pkt), false, &p)
	return true
}

// meshOutbound decides a packet from device d to another device's tunnel address
// (ADR-0034): replies of tracked mesh flows pass; a new flow passes if both devices are in
// one tenant, the target has a session here and its snapshot grants the source.
func (f *Filter) meshOutbound(p *packet.Packet, pkt []byte, d *device, key packet.FlowKey, dst netip.Addr, now time.Time) bool {
	if cn := f.ct.get(key.Reverse()); cn != nil && cn.mesh {
		if cn.blocked.Load() {
			return false
		}
		cn.touch(now, len(pkt), false, p)
		return true
	}
	if cn := f.ct.get(key); cn != nil && cn.mesh && cn.deviceID == d.id {
		if cn.blocked.Load() {
			return false
		}
		cn.touch(now, len(pkt), true, p)
		return true
	}
	proto := protoName(p.Protocol)
	if proto == "" || (p.Protocol == packet.ProtoTCP && (!p.SYN() || p.ACK())) || (isICMP(proto) && !isEchoRequest(p)) {
		return false
	}
	flow := policy.Flow{Protocol: proto, SrcIP: p.Src.Unmap().String(), DstIP: dst.String(), DstPort: p.DstPort}
	if isICMP(proto) {
		flow.DstPort = 0
	}
	dec := policy.Decision{Action: policy.ActionBlock, RuleID: RuleMeshDenied, Layer: LayerEdge, Log: true}
	if target := f.e.reg.byTunnelIP(dst); target != nil && target.tenantID == d.tenantID && target.id != d.id {
		f.e.reg.mu.Lock()
		live := target.hasPeer
		f.e.reg.mu.Unlock()
		src := d.compiled.Load()
		if tc := target.compiled.Load(); live && tc != nil && src != nil {
			if rule, ok := tc.MeshAllows(src.UserID(), d.id, proto, flow.DstPort); ok {
				dec = policy.Decision{Action: policy.ActionAllow, RuleID: rule, Layer: LayerEdge, Log: true}
			}
		}
	}
	cn := &conn{deviceID: d.id, proto: p.Protocol, flow: flow, decision: dec, start: now, mesh: true}
	if dec.Action != policy.ActionAllow {
		cn.blocked.Store(true)
		if f.ct.add(key, cn, now, len(pkt), p) {
			f.e.flows.add(cn.record(now))
		}
		f.reject(p, pkt)
		return false
	}
	return f.ct.add(key, cn, now, len(pkt), p)
}

// reject sends a TCP RST or ICMP unreachable for pkt back into the tunnel.
func (f *Filter) reject(p *packet.Packet, pkt []byte) {
	out := make([]byte, packet.MaxICMPUnreachableLen)
	var n int
	var err error
	if p.Protocol == packet.ProtoTCP {
		n, err = packet.BuildTCPReset(p, pkt, out)
	} else {
		n, err = packet.BuildICMPUnreachable(pkt, out)
	}
	if err != nil || n == 0 {
		return
	}
	select {
	case f.inject <- out[:n]:
	default: // queue full: drop silently
	}
}

// conn is one tracked flow.
type conn struct {
	deviceID string
	proto    uint8
	start    time.Time
	local    bool      // to the Edge itself (DNS, ping): not reported
	mesh     bool      // device to device (ADR-0034)
	peek     *hostPeek // allowed TCP flows until their host is known (ADR-0017); nil otherwise

	mu       sync.Mutex // guards flow and decision, which web control may update
	flow     policy.Flow
	decision policy.Decision

	blocked atomic.Bool

	lastSeen atomic.Int64 // unix nanoseconds
	bytesOut atomic.Uint64
	bytesIn  atomic.Uint64
	state    atomic.Uint32 // tcp flag bits below
}

const (
	stEstablished = 1 << iota
	stFinOut
	stFinIn
	stRST
)

func (c *conn) touch(now time.Time, n int, out bool, p *packet.Packet) {
	c.lastSeen.Store(now.UnixNano())
	if out {
		c.bytesOut.Add(uint64(n))
	} else {
		c.bytesIn.Add(uint64(n))
	}
	if p.Protocol != packet.ProtoTCP {
		return
	}
	var bits uint32
	switch {
	case p.RST():
		bits = stRST
	case p.FIN() && out:
		bits = stFinOut
	case p.FIN():
		bits = stFinIn
	case !out && p.SYN() && p.ACK():
		bits = stEstablished
	}
	if bits != 0 {
		for {
			old := c.state.Load()
			if c.state.CompareAndSwap(old, old|bits) {
				break
			}
		}
	}
}

func (c *conn) record(end time.Time) api.FlowRecord {
	c.mu.Lock()
	flow, dec := c.flow, c.decision
	c.mu.Unlock()
	return api.FlowRecord{
		Start:    c.start,
		End:      end,
		Flow:     flow,
		Decision: dec,
		BytesOut: c.bytesOut.Load(),
		BytesIn:  c.bytesIn.Load(),
		Where:    "edge",
		DeviceID: c.deviceID,
	}
}

// expired reports whether c has been idle past its timeout.
func (c *conn) expired(now time.Time) bool {
	idle := now.Sub(time.Unix(0, c.lastSeen.Load()))
	if c.blocked.Load() {
		return idle > blockedHold
	}
	switch c.proto {
	case packet.ProtoTCP:
		st := c.state.Load()
		switch {
		case st&stRST != 0, st&stFinOut != 0 && st&stFinIn != 0:
			return idle > closedHold
		case st&stEstablished == 0:
			return idle > tcpSynIdle
		}
		return idle > tcpIdle
	case packet.ProtoUDP:
		if c.local {
			return idle > localUDPIdle
		}
		return idle > udpIdle
	}
	return idle > icmpIdle
}

// conntrack is the flow table.
type conntrack struct {
	mu sync.RWMutex
	m  map[packet.FlowKey]*conn
}

func newConntrack() *conntrack { return &conntrack{m: map[packet.FlowKey]*conn{}} }

func (t *conntrack) get(k packet.FlowKey) *conn {
	t.mu.RLock()
	c := t.m[k]
	t.mu.RUnlock()
	return c
}

// add inserts c unless the table is full or another goroutine won the race; it returns
// false when c was not inserted (the caller then drops the packet, except blocked entries
// which are only for de-duplicating reports).
func (t *conntrack) add(k packet.FlowKey, c *conn, now time.Time, n int, p *packet.Packet) bool {
	t.mu.Lock()
	if old, ok := t.m[k]; ok {
		t.mu.Unlock()
		if old.blocked.Load() || old.deviceID != c.deviceID {
			return false
		}
		old.touch(now, n, true, p)
		return true
	}
	if len(t.m) >= maxConns {
		t.mu.Unlock()
		return false
	}
	c.touch(now, n, true, p)
	t.m[k] = c
	t.mu.Unlock()
	return true
}

// sweep removes expired flows and flows of devices that no longer own their address, and
// returns the records of reportable flows that ended.
func (t *conntrack) sweep(now time.Time, owner func(packet.FlowKey) string) []api.FlowRecord {
	var out []api.FlowRecord
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, c := range t.m {
		gone := owner(k) != c.deviceID
		if !gone && !c.expired(now) {
			continue
		}
		delete(t.m, k)
		if !c.local && !c.blocked.Load() {
			out = append(out, c.record(time.Unix(0, c.lastSeen.Load())))
		}
	}
	return out
}
