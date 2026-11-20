package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/dnsfilter"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

// memTUN is an in-memory tun.Device. Packets queued with push are returned by Read;
// packets written are captured in written.
type memTUN struct {
	in      chan []byte
	mu      sync.Mutex
	written [][]byte
	closed  chan struct{}
	once    sync.Once
	events  chan tun.Event
	batch   int
}

func newMemTUN() *memTUN {
	return &memTUN{in: make(chan []byte, 64), closed: make(chan struct{}), events: make(chan tun.Event), batch: 4}
}

func (m *memTUN) File() *os.File { return nil }
func (m *memTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-m.closed:
		return 0, os.ErrClosed
	case p := <-m.in:
		n := 0
		for {
			sizes[n] = copy(bufs[n][offset:], p)
			n++
			if n == len(bufs) {
				return n, nil
			}
			select {
			case p = <-m.in:
			default:
				return n, nil
			}
		}
	}
}
func (m *memTUN) Write(bufs [][]byte, offset int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range bufs {
		m.written = append(m.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}
func (m *memTUN) take() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.written
	m.written = nil
	return w
}
func (m *memTUN) MTU() (int, error)        { return 1280, nil }
func (m *memTUN) Name() (string, error)    { return "mem0", nil }
func (m *memTUN) Events() <-chan tun.Event { return m.events }
func (m *memTUN) BatchSize() int           { return m.batch }
func (m *memTUN) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

// fakeResolver maps destination ports to UIDs, and UIDs to packages.
type fakeResolver struct {
	byPort map[uint16]int
	pkgs   map[int]string
	calls  atomic.Int32
}

func (r *fakeResolver) ConnectionOwnerUID(proto uint8, src, dst netip.AddrPort) int {
	r.calls.Add(1)
	if uid, ok := r.byPort[dst.Port()]; ok {
		return uid
	}
	return -1
}
func (r *fakeResolver) PackagesForUID(uid int) string { return r.pkgs[uid] }

// fakeDecider returns a fixed verdict; if gate is non-nil, each call waits on it.
type fakeDecider struct {
	action policy.Action
	err    error
	gate   chan struct{}
	calls  atomic.Int32
	done   chan struct{}
}

func (d *fakeDecider) Decide(ctx context.Context, f policy.Flow) (policy.Decision, time.Duration, error) {
	d.calls.Add(1)
	defer func() {
		if d.done != nil {
			d.done <- struct{}{}
		}
	}()
	if d.gate != nil {
		select {
		case <-d.gate:
		case <-ctx.Done():
			return policy.Decision{}, 0, ctx.Err()
		}
	}
	if d.err != nil {
		return policy.Decision{}, 0, d.err
	}
	return policy.Decision{Action: d.action, RuleID: "cloud-rule"}, time.Minute, nil
}

var errCloudDown = errors.New("cloud down")

// fakeClock is a settable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var (
	devIP  = netip.MustParseAddr("100.64.0.7")
	dnsIP  = netip.MustParseAddr("100.64.0.1")
	webIP  = netip.MustParseAddr("203.0.113.10")
	evilIP = netip.MustParseAddr("198.51.100.66")
)

type env struct {
	t     testing.TB
	inner *memTUN
	fw    *FilteringTUN
	res   *fakeResolver
	dec   *fakeDecider
	clock *fakeClock
	dns   *dnsfilter.Interceptor
}

type envOpt func(*Config)

func newEnv(t testing.TB, snap *policy.Snapshot, opts ...envOpt) *env {
	t.Helper()
	e := &env{
		t:     t,
		inner: newMemTUN(),
		res: &fakeResolver{
			byPort: map[uint16]int{443: 10100, 80: 10200, 53: 10100, 8443: 10300},
			pkgs:   map[int]string{10100: "com.browser,com.browser.helper", 10200: "com.game", 10300: "com.chat"},
		},
		clock: &fakeClock{t: time.Unix(1_700_000_000, 0)},
	}
	e.dns = dnsfilter.New(dnsfilter.Config{Now: e.clock.now})
	cfg := Config{
		Inner: e.inner, Resolver: e.res, DNS: e.dns, DNSServers: []netip.Addr{dnsIP}, DeviceID: "dev1",
		GCInterval: -1, Now: e.clock.now, EventRate: 1000,
	}
	for _, o := range opts {
		o(&cfg)
	}
	if d, ok := cfg.Decider.(*fakeDecider); ok {
		e.dec = d
	}
	fw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fw.Close() })
	e.fw = fw
	if snap != nil {
		e.setPolicy(snap)
	}
	return e
}

func (e *env) setPolicy(s *policy.Snapshot) {
	e.t.Helper()
	c, err := policy.Compile(s)
	if err != nil {
		e.t.Fatalf("Compile: %v", err)
	}
	e.fw.SetPolicy(c, s.Firewall.DefaultAction)
}

func snapshot(def policy.Action, rules ...policy.Rule) *policy.Snapshot {
	for i := range rules {
		if rules[i].Source == "" {
			rules[i].Source = policy.SourceTenant
		}
		if rules[i].Priority == 0 {
			rules[i].Priority = i + 1
		}
	}
	return &policy.Snapshot{
		SchemaVersion: 1, Version: 1, TenantID: "t1", DeviceID: "dev1",
		IssuedAt: time.Unix(1_700_000_000, 0), ExpiresAt: time.Unix(1_800_000_000, 0),
		Firewall: policy.FirewallPolicy{DefaultAction: def, Rules: rules},
		DNS: policy.DNSPolicy{
			BlockResponse: "nxdomain",
			BlockDomains:  []string{"blocked.example"},
		},
	}
}

// --- packet builders (IPv4 only; checksums are filled in) ---

func csum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

func fold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return ^uint16(acc)
}

func ipv4(proto uint8, src, dst netip.Addr, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:], s[:])
	copy(pkt[16:], d[:])
	binary.BigEndian.PutUint16(pkt[10:], fold(csum(pkt[:20], 0)))
	copy(pkt[20:], l4)
	if proto == packet.ProtoTCP || proto == packet.ProtoUDP {
		acc := csum(s[:], 0)
		acc = csum(d[:], acc)
		acc += uint32(proto) + uint32(len(l4))
		off := 16
		if proto == packet.ProtoUDP {
			off = 6
		}
		binary.BigEndian.PutUint16(pkt[20+off:], fold(csum(pkt[20:], acc)))
	} else {
		binary.BigEndian.PutUint16(pkt[22:], fold(csum(pkt[20:], 0)))
	}
	return pkt
}

func tcp(src netip.AddrPort, dst netip.AddrPort, flags uint8, payload []byte) []byte {
	l4 := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(l4[0:], src.Port())
	binary.BigEndian.PutUint16(l4[2:], dst.Port())
	binary.BigEndian.PutUint32(l4[4:], 1000)
	if flags&packet.FlagACK != 0 {
		binary.BigEndian.PutUint32(l4[8:], 5000)
	}
	l4[12] = 5 << 4
	l4[13] = flags
	binary.BigEndian.PutUint16(l4[14:], 65535)
	copy(l4[20:], payload)
	return ipv4(packet.ProtoTCP, src.Addr(), dst.Addr(), l4)
}

func udp(src, dst netip.AddrPort, payload []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(l4[0:], src.Port())
	binary.BigEndian.PutUint16(l4[2:], dst.Port())
	binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	copy(l4[8:], payload)
	return ipv4(packet.ProtoUDP, src.Addr(), dst.Addr(), l4)
}

func icmpUnreachable(from, to netip.Addr, quoted []byte, code uint8) []byte {
	q := quoted
	if len(q) > 28 {
		q = q[:28]
	}
	l4 := make([]byte, 8+len(q))
	l4[0], l4[1] = 3, code
	copy(l4[8:], q)
	return ipv4(packet.ProtoICMP, from, to, l4)
}

func dnsQuery(t testing.TB, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = testDNSID
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dnsAnswer(t testing.TB, name string, ip netip.Addr) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = testDNSID
	m.Response = true
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   ip.AsSlice(),
	}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testDNSID is the transaction ID of dnsQuery and dnsAnswer, so answers match queries.
const testDNSID = 0x4242

// icmpv6 builds an IPv6 ICMPv6 packet with a valid checksum.
func icmpv6(src, dst netip.Addr, typ, code uint8, body []byte) []byte {
	l4 := make([]byte, 4+len(body))
	l4[0], l4[1] = typ, code
	copy(l4[4:], body)
	pkt := make([]byte, 40+len(l4))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(l4)))
	pkt[6], pkt[7] = packet.ProtoICMPv6, 255
	s, d := src.As16(), dst.As16()
	copy(pkt[8:], s[:])
	copy(pkt[24:], d[:])
	copy(pkt[40:], l4)
	acc := csum(s[:], 0)
	acc = csum(d[:], acc)
	acc += uint32(len(l4)) + uint32(packet.ProtoICMPv6)
	binary.BigEndian.PutUint16(pkt[42:], fold(csum(pkt[40:], acc)))
	return pkt
}

func ap(a netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(a, port) }

func mustParse(t testing.TB, b []byte) packet.Packet {
	t.Helper()
	var p packet.Packet
	if err := packet.Parse(b, &p); err != nil {
		t.Fatalf("parse injected packet: %v", err)
	}
	return p
}

func keyOf(t testing.TB, b []byte) packet.FlowKey {
	t.Helper()
	p := mustParse(t, b)
	return p.FlowKey()
}

func isRST(t testing.TB, b []byte) bool {
	t.Helper()
	p := mustParse(t, b)
	return p.Protocol == packet.ProtoTCP && p.RST()
}
