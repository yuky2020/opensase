package firewall

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestOutboundVerdicts(t *testing.T) {
	blockGame := policy.Rule{ID: "no-games", Action: policy.ActionBlock, Match: policy.Match{Apps: []string{"com.game"}}}
	blockEvil := policy.Rule{ID: "evil", Action: policy.ActionBlock, Log: true, Match: policy.Match{CIDRs: []string{"198.51.100.0/24"}}}
	tests := []struct {
		name     string
		snap     *policy.Snapshot
		pkt      []byte
		wantPass bool
		wantInj  uint8 // 0 none, else protocol of the injected packet
		wantRule string
		wantApp  string
	}{
		{"default allow", snapshot(policy.ActionAllow), tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagSYN, nil), true, 0, "", "com.browser"},
		{"default block tcp sends RST", snapshot(policy.ActionBlock), tcp(ap(devIP, 40001), ap(webIP, 443), packet.FlagSYN, nil), false, packet.ProtoTCP, "", "com.browser"},
		{"app rule", snapshot(policy.ActionAllow, blockGame), tcp(ap(devIP, 40002), ap(webIP, 80), packet.FlagSYN, nil), false, packet.ProtoTCP, "no-games", "com.game"},
		{"cidr rule udp sends ICMP", snapshot(policy.ActionAllow, blockEvil), udp(ap(devIP, 40003), ap(evilIP, 9999), []byte("x")), false, packet.ProtoICMP, "evil", ""},
		{"no snapshot fails closed", nil, tcp(ap(devIP, 40004), ap(webIP, 443), packet.FlagSYN, nil), false, packet.ProtoTCP, RuleNoSnapshot, "com.browser"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.snap)
			if got := e.fw.outbound(tt.pkt); got != tt.wantPass {
				t.Fatalf("outbound=%v, want %v", got, tt.wantPass)
			}
			inj := e.inner.take()
			if tt.wantInj == 0 {
				if len(inj) != 0 {
					t.Fatalf("unexpected injection")
				}
			} else {
				if len(inj) != 1 {
					t.Fatalf("injected %d packets, want 1", len(inj))
				}
				p := mustParse(t, inj[0])
				orig := mustParse(t, tt.pkt)
				if p.Protocol != tt.wantInj || p.Dst != orig.Src || p.Src != orig.Dst {
					t.Fatalf("injected proto=%d %v->%v", p.Protocol, p.Src, p.Dst)
				}
				if p.Protocol == packet.ProtoTCP && (!p.RST() || p.DstPort != orig.SrcPort) {
					t.Fatalf("not an RST to the app: flags=%#x port=%d", p.TCPFlags, p.DstPort)
				}
			}
			recs := e.fw.RecentFlows(10)
			if !tt.wantPass {
				if len(recs) != 1 || recs[0].Decision.RuleID != tt.wantRule || recs[0].Flow.App != tt.wantApp {
					t.Fatalf("flow log %+v", recs)
				}
			}
			// A retransmission hits the conntrack entry, not the resolver.
			calls := e.res.calls.Load()
			if got := e.fw.outbound(tt.pkt); got != tt.wantPass {
				t.Fatalf("retransmit outbound=%v", got)
			}
			if e.res.calls.Load() != calls {
				t.Fatal("resolver called again for a tracked flow")
			}
		})
	}
}

func TestStatefulInbound(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow))
	// Unsolicited inbound packet: dropped.
	if e.fw.inbound(tcp(ap(webIP, 443), ap(devIP, 40000), packet.FlagSYN, nil)) {
		t.Fatal("unsolicited inbound passed")
	}
	if !e.fw.outbound(tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagSYN, nil)) {
		t.Fatal("SYN dropped")
	}
	synack := tcp(ap(webIP, 443), ap(devIP, 40000), packet.FlagSYN|packet.FlagACK, nil)
	if !e.fw.inbound(synack) {
		t.Fatal("SYN-ACK dropped")
	}
	// Same remote, other local port: no flow.
	if e.fw.inbound(tcp(ap(webIP, 443), ap(devIP, 40001), packet.FlagACK, nil)) {
		t.Fatal("inbound for unknown port passed")
	}
	ent := e.fw.ct.get(keyOf(t, tcp(ap(devIP, 40000), ap(webIP, 443), 0, nil)))
	if ent.state.Load() != stEstablished {
		t.Fatal("not established after SYN-ACK")
	}
	if ent.bytesIn.Load() != uint64(len(synack)) {
		t.Fatalf("bytesIn=%d", ent.bytesIn.Load())
	}
	// ICMP error quoting our flow is related and passes; one quoting another flow does not.
	ours := tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagACK, []byte("data"))
	if !e.fw.inbound(icmpUnreachable(webIP, devIP, ours, 4)) {
		t.Fatal("related ICMP error dropped")
	}
	other := tcp(ap(devIP, 41000), ap(webIP, 443), packet.FlagACK, nil)
	if e.fw.inbound(icmpUnreachable(webIP, devIP, other, 4)) {
		t.Fatal("unrelated ICMP error passed")
	}
}

func TestAskPath(t *testing.T) {
	ask := policy.Rule{ID: "ask-chat", Action: policy.ActionAsk, Match: policy.Match{Apps: []string{"com.chat"}}}
	syn := tcp(ap(devIP, 40000), ap(webIP, 8443), packet.FlagSYN, nil)

	t.Run("allow after decision, deduped", func(t *testing.T) {
		d := &fakeDecider{action: policy.ActionAllow, gate: make(chan struct{}), done: make(chan struct{}, 10)}
		e := newEnv(t, snapshot(policy.ActionAllow, ask), func(c *Config) { c.Decider = d })
		for range 5 { // first packet + retransmissions while the decision is in flight
			if e.fw.outbound(syn) {
				t.Fatal("undecided flow passed")
			}
		}
		close(d.gate)
		<-d.done
		waitFor(t, func() bool { return e.fw.inflight.Load() == 0 })
		if n := d.calls.Load(); n != 1 {
			t.Fatalf("Decide called %d times, want 1", n)
		}
		if !e.fw.outbound(syn) {
			t.Fatal("retransmission after allow verdict dropped")
		}
		v := e.fw.ct.get(keyOf(t, syn)).v.Load()
		if v.dec.Layer != policy.LayerCloud || v.dec.RuleID != "cloud-rule" {
			t.Fatalf("decision %+v", v.dec)
		}
		// A second flow with the same attributes (other source port) uses the cache.
		if !e.fw.outbound(tcp(ap(devIP, 40001), ap(webIP, 8443), packet.FlagSYN, nil)) {
			t.Fatal("cached verdict not used")
		}
		if d.calls.Load() != 1 {
			t.Fatal("decision cache missed")
		}
	})

	t.Run("cloud blocks", func(t *testing.T) {
		d := &fakeDecider{action: policy.ActionBlock, done: make(chan struct{}, 10)}
		e := newEnv(t, snapshot(policy.ActionAllow, ask), func(c *Config) { c.Decider = d })
		e.fw.outbound(syn)
		<-d.done
		waitFor(t, func() bool { return e.fw.inflight.Load() == 0 })
		if e.fw.outbound(syn) {
			t.Fatal("blocked by cloud but passed")
		}
		if inj := e.inner.take(); len(inj) != 1 || !isRST(t, inj[0]) {
			t.Fatal("no RST after cloud block")
		}
	})

	fallbacks := []struct {
		name      string
		def       policy.Action
		toDefault bool
		decider   bool
		want      bool
	}{
		{"cloud down fails closed", policy.ActionAllow, false, true, false},
		{"cloud down falls back to default allow", policy.ActionAllow, true, true, true},
		{"fallback ignores ask default", policy.ActionAsk, true, true, false},
		{"no decider fails closed", policy.ActionAllow, false, false, false},
	}
	for _, tt := range fallbacks {
		t.Run(tt.name, func(t *testing.T) {
			d := &fakeDecider{err: errCloudDown, done: make(chan struct{}, 10)}
			e := newEnv(t, snapshot(tt.def, ask), func(c *Config) {
				if tt.decider {
					c.Decider = d
				}
				c.FallbackToDefault = tt.toDefault
			})
			first := e.fw.outbound(syn)
			if tt.decider {
				if first {
					t.Fatal("first packet passed before decision")
				}
				<-d.done
				waitFor(t, func() bool { return e.fw.inflight.Load() == 0 })
				first = e.fw.outbound(syn)
			}
			if first != tt.want {
				t.Fatalf("pass=%v, want %v", first, tt.want)
			}
			v := e.fw.ct.get(keyOf(t, syn)).v.Load()
			if v.dec.RuleID != RuleCloudUnreachable {
				t.Fatalf("rule %q", v.dec.RuleID)
			}
		})
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDNSBlock(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow), func(c *Config) { c.DNSServers = nil })
	q := udp(ap(devIP, 50000), ap(dnsIP, 53), dnsQuery(t, "Blocked.Example"))
	if e.fw.outbound(q) {
		t.Fatal("blocked query forwarded")
	}
	inj := e.inner.take()
	if len(inj) != 1 {
		t.Fatalf("injected %d", len(inj))
	}
	p := mustParse(t, inj[0])
	if p.Src != dnsIP || p.Dst != devIP || p.SrcPort != 53 || p.DstPort != 50000 {
		t.Fatalf("response addressing %v:%d -> %v:%d", p.Src, p.SrcPort, p.Dst, p.DstPort)
	}
	var m dns.Msg
	if err := m.Unpack(p.Payload); err != nil || m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode %d err %v", m.Rcode, err)
	}
	// An allowed query on the same flow is forwarded.
	if !e.fw.outbound(udp(ap(devIP, 50000), ap(dnsIP, 53), dnsQuery(t, "fine.example"))) {
		t.Fatal("allowed query dropped")
	}
	st := e.dns.Stats()
	if len(st) != 1 || st[0].App != "com.browser" || st[0].Queries != 2 || st[0].Blocked != 1 {
		t.Fatalf("dns stats %+v", st)
	}
	if recs := e.fw.RecentFlows(1); len(recs) != 1 || recs[0].Decision.Layer != LayerDNS || recs[0].Flow.Domain != "blocked.example" {
		t.Fatalf("flow log %+v", recs)
	}
}

func TestDomainRuleViaSnoop(t *testing.T) {
	rule := policy.Rule{ID: "no-social", Action: policy.ActionBlock, Match: policy.Match{Domains: []string{"*.social.example"}}}
	e := newEnv(t, snapshot(policy.ActionAllow, rule))
	// Before DNS: no domain known, allowed.
	if !e.fw.outbound(tcp(ap(devIP, 40000), ap(evilIP, 443), packet.FlagSYN, nil)) {
		t.Fatal("flow without known domain blocked")
	}
	// DNS query + response teach the cache that evilIP is www.social.example.
	if !e.fw.outbound(udp(ap(devIP, 50001), ap(dnsIP, 53), dnsQuery(t, "www.social.example"))) {
		t.Fatal("query dropped")
	}
	if !e.fw.inbound(udp(ap(dnsIP, 53), ap(devIP, 50001), dnsAnswer(t, "www.social.example", evilIP))) {
		t.Fatal("response dropped")
	}
	if got := e.dns.Domain(evilIP); got != "www.social.example" {
		t.Fatalf("snooped %q", got)
	}
	// New flow to that IP is blocked by the domain rule.
	if e.fw.outbound(tcp(ap(devIP, 40001), ap(evilIP, 443), packet.FlagSYN, nil)) {
		t.Fatal("domain rule not applied")
	}
	recs := e.fw.RecentFlows(1)
	if recs[0].Decision.RuleID != "no-social" || recs[0].Flow.Domain != "www.social.example" {
		t.Fatalf("record %+v", recs[0])
	}
	// Responses not matching a flow are not snooped.
	e.fw.inbound(udp(ap(dnsIP, 53), ap(devIP, 59999), dnsAnswer(t, "spoof.example", webIP)))
	if e.dns.Domain(webIP) != "" {
		t.Fatal("snooped an unsolicited response")
	}
}

// TestDNSSnoopRequiresMatchAndServer is the regression test for review #11.
func TestDNSSnoopRequiresMatchAndServer(t *testing.T) {
	spoof := func(e *env, port uint16) {
		// Response from the resolver to the query's flow, but for a name never asked.
		e.fw.inbound(udp(ap(dnsIP, 53), ap(devIP, port), dnsAnswer(t, "spoof.example", webIP)))
	}
	t.Run("answer for another name on the query flow", func(t *testing.T) {
		e := newEnv(t, snapshot(policy.ActionAllow))
		if !e.fw.outbound(udp(ap(devIP, 50010), ap(dnsIP, 53), dnsQuery(t, "asked.example"))) {
			t.Fatal("query dropped")
		}
		spoof(e, 50010)
		if e.dns.Domain(webIP) != "" {
			t.Fatal("snooped a response that does not match the query")
		}
	})
	t.Run("second response after the first is ignored", func(t *testing.T) {
		e := newEnv(t, snapshot(policy.ActionAllow))
		e.fw.outbound(udp(ap(devIP, 50011), ap(dnsIP, 53), dnsQuery(t, "a.example")))
		e.fw.inbound(udp(ap(dnsIP, 53), ap(devIP, 50011), dnsAnswer(t, "a.example", evilIP)))
		e.fw.inbound(udp(ap(dnsIP, 53), ap(devIP, 50011), dnsAnswer(t, "a.example", webIP)))
		if e.dns.Domain(evilIP) != "a.example" || e.dns.Domain(webIP) != "" {
			t.Fatalf("evil=%q web=%q", e.dns.Domain(evilIP), e.dns.Domain(webIP))
		}
	})
	t.Run("no DNSServers: filter but never snoop", func(t *testing.T) {
		e := newEnv(t, snapshot(policy.ActionAllow), func(c *Config) { c.DNSServers = nil })
		if !e.fw.outbound(udp(ap(devIP, 50012), ap(dnsIP, 53), dnsQuery(t, "a.example"))) {
			t.Fatal("query dropped")
		}
		e.fw.inbound(udp(ap(dnsIP, 53), ap(devIP, 50012), dnsAnswer(t, "a.example", webIP)))
		if e.dns.Domain(webIP) != "" {
			t.Fatal("snooped without a session DNS server")
		}
	})
	t.Run("third-party resolver is not snooped", func(t *testing.T) {
		other := netip.MustParseAddr("8.8.8.8")
		e := newEnv(t, snapshot(policy.ActionAllow))
		e.fw.outbound(udp(ap(devIP, 50013), ap(other, 53), dnsQuery(t, "a.example")))
		e.fw.inbound(udp(ap(other, 53), ap(devIP, 50013), dnsAnswer(t, "a.example", webIP)))
		if e.dns.Domain(webIP) != "" {
			t.Fatal("snooped a non-session resolver")
		}
	})
}

// TestLinkLocalICMPv6DroppedSilently: router solicitation to ff02::2 and other link-scoped
// ICMPv6 must be dropped without a flow record, event or injected reply.
func TestLinkLocalICMPv6DroppedSilently(t *testing.T) {
	dev6 := netip.MustParseAddr("fd7a:5a5e::7")
	ll := netip.MustParseAddr("fe80::1")
	tests := []struct {
		name string
		pkt  []byte
		drop bool
	}{
		{"router solicitation to ff02::2", icmpv6(dev6, netip.MustParseAddr("ff02::2"), 133, 0, make([]byte, 4)), true},
		{"router solicitation from link-local", icmpv6(ll, netip.MustParseAddr("ff02::2"), 133, 0, make([]byte, 4)), true},
		{"neighbour solicitation to solicited-node", icmpv6(dev6, netip.MustParseAddr("ff02::1:ff00:1"), 135, 0, make([]byte, 20)), true},
		{"neighbour advertisement unicast", icmpv6(dev6, netip.MustParseAddr("2001:db8::1"), 136, 0, make([]byte, 20)), true},
		{"MLDv2 report", icmpv6(dev6, netip.MustParseAddr("ff02::16"), 143, 0, make([]byte, 4)), true},
		{"echo to link-local", icmpv6(dev6, ll, 128, 0, make([]byte, 4)), true},
		{"echo to global is a normal flow", icmpv6(dev6, netip.MustParseAddr("2001:db8::1"), 128, 0, make([]byte, 4)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var events atomic.Int32
			e := newEnv(t, nil, func(c *Config) { c.OnEvent = func(string, string) { events.Add(1) } })
			pass := e.fw.outbound(tt.pkt)
			if !tt.drop {
				// No snapshot: a normal flow is blocked fail-closed and logged as no-snapshot.
				if pass || len(e.fw.RecentFlows(1)) != 1 || e.fw.RecentFlows(1)[0].Decision.RuleID != RuleNoSnapshot {
					t.Fatalf("pass=%v flows=%+v", pass, e.fw.RecentFlows(1))
				}
				return
			}
			if pass {
				t.Fatal("link-local ICMPv6 forwarded")
			}
			if n := len(e.fw.RecentFlows(10)); n != 0 || events.Load() != 0 || len(e.inner.take()) != 0 || e.fw.Counters().Flows != 0 {
				t.Fatalf("not silent: flows=%d events=%d", n, events.Load())
			}
			if e.fw.Counters().DropsLocal != 1 {
				t.Fatalf("dropsLocal=%d", e.fw.Counters().DropsLocal)
			}
		})
	}
}

func TestSnapshotHotSwap(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow))
	syn := tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagSYN, nil)
	ack := tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagACK, []byte("hello"))
	if !e.fw.outbound(syn) || !e.fw.inbound(tcp(ap(webIP, 443), ap(devIP, 40000), packet.FlagSYN|packet.FlagACK, nil)) {
		t.Fatal("handshake dropped")
	}
	s := snapshot(policy.ActionAllow, policy.Rule{ID: "block-web", Action: policy.ActionBlock, Match: policy.Match{Ports: []policy.PortRange{{From: 443}}}})
	s.Version = 2
	e.setPolicy(s)
	if e.fw.inbound(tcp(ap(webIP, 443), ap(devIP, 40000), packet.FlagACK, []byte("x"))) {
		t.Fatal("inbound passed after policy now blocks the flow")
	}
	if e.fw.outbound(ack) {
		t.Fatal("outbound passed after policy now blocks the flow")
	}
	if inj := e.inner.take(); len(inj) != 1 || !isRST(t, inj[0]) {
		t.Fatal("no RST on re-evaluated flow")
	}
	st := e.fw.AppStats()
	if len(st) != 1 || st[0].Allowed != 1 || st[0].Blocked != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Changing the network forces re-evaluation of per-network app policy.
	s3 := snapshot(policy.ActionAllow)
	s3.Version = 3
	s3.Firewall.Apps = map[string]policy.AppPolicy{"com.game": {Cellular: policy.ActionBlock}}
	e.setPolicy(s3)
	e.fw.SetNetwork(policy.NetworkWiFi)
	game := tcp(ap(devIP, 40010), ap(webIP, 80), packet.FlagSYN, nil)
	if !e.fw.outbound(game) {
		t.Fatal("game blocked on wifi")
	}
	e.fw.SetNetwork(policy.NetworkCellular)
	if e.fw.outbound(tcp(ap(devIP, 40010), ap(webIP, 80), packet.FlagACK, nil)) {
		t.Fatal("game allowed on cellular")
	}
}

func TestConntrackTimeoutsAndFlowLog(t *testing.T) {
	var mu sync.Mutex
	var events []string
	e := newEnv(t, snapshot(policy.ActionAllow, policy.Rule{ID: "log-udp", Action: policy.ActionAllow, Log: true, Match: policy.Match{Protocols: []string{"udp"}}}),
		func(c *Config) {
			c.OnEvent = func(kind, payload string) {
				mu.Lock()
				events = append(events, kind+":"+payload)
				mu.Unlock()
			}
		})
	u := udp(ap(devIP, 50000), ap(webIP, 4000), []byte("ping"))
	e.fw.outbound(u)
	e.fw.inbound(udp(ap(webIP, 4000), ap(devIP, 50000), []byte("pong!")))
	tcpSyn := tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagSYN, nil)
	e.fw.outbound(tcpSyn)

	tests := []struct {
		advance   time.Duration
		wantFlows int
	}{
		{TimeoutTCPSyn - time.Second, 2},
		{2 * time.Second, 1}, // TCP SYN_SENT expired (30s)
		{TimeoutUDP, 0},      // UDP idle > 60s
	}
	for i, tt := range tests {
		e.clock.advance(tt.advance)
		e.fw.GC()
		if got := e.fw.ct.len(); got != tt.wantFlows {
			t.Fatalf("step %d: %d flows, want %d", i, got, tt.wantFlows)
		}
	}
	recs := e.fw.Drain()
	if len(recs) != 2 {
		t.Fatalf("drained %d records", len(recs))
	}
	var udpRec = recs[1]
	if udpRec.Flow.Protocol != "udp" || udpRec.BytesOut != uint64(len(u)) || udpRec.BytesIn == 0 || udpRec.End.IsZero() || udpRec.DeviceID != "dev1" {
		t.Fatalf("udp record %+v", udpRec)
	}
	if len(e.fw.Drain()) != 0 {
		t.Fatal("Drain did not clear")
	}
	if len(e.fw.RecentFlows(0)) != 2 {
		t.Fatal("RecentFlows cleared by Drain")
	}
	mu.Lock()
	defer mu.Unlock()
	// Log=true rule: one event at start, one at end.
	if len(events) != 2 {
		t.Fatalf("events %v", events)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(events[1][len("flow:"):]), &rec); err != nil {
		t.Fatal(err)
	}
}

func TestTCPClosingTimeout(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow))
	e.fw.outbound(tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagSYN, nil))
	e.fw.inbound(tcp(ap(webIP, 443), ap(devIP, 40000), packet.FlagSYN|packet.FlagACK, nil))
	e.clock.advance(time.Hour)
	e.fw.GC()
	if e.fw.ct.len() != 1 {
		t.Fatal("established flow expired after 1h")
	}
	e.fw.refreshClock()
	e.fw.outbound(tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagFIN|packet.FlagACK, nil))
	e.clock.advance(TimeoutTCPClosing + time.Second)
	e.fw.GC()
	if e.fw.ct.len() != 0 {
		t.Fatal("closing flow not expired")
	}
}

func TestConntrackBound(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow), func(c *Config) { c.MaxFlows = 64 })
	for i := range 1000 {
		e.fw.outbound(udp(ap(devIP, uint16(10000+i)), ap(webIP, 4000), nil))
	}
	if n := e.fw.ct.len(); n > 64+numShards {
		t.Fatalf("%d flows tracked, bound is ~64", n)
	}
	if len(e.fw.Drain()) == 0 {
		t.Fatal("evicted flows not logged")
	}
}

func TestReadWriteBatches(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow, policy.Rule{ID: "evil", Action: policy.ActionBlock, Match: policy.Match{CIDRs: []string{"198.51.100.0/24"}}}))
	a := udp(ap(devIP, 50000), ap(webIP, 4000), []byte("a"))
	b := udp(ap(devIP, 50001), ap(evilIP, 4000), []byte("bb"))
	c := udp(ap(devIP, 50002), ap(webIP, 4000), []byte("ccc"))
	for _, p := range [][]byte{a, b, c} {
		e.inner.in <- p
	}
	const off = 16
	bufs := make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, off+1500)
	}
	sizes := make([]int, 4)
	n, err := e.fw.Read(bufs, sizes, off)
	if err != nil || n != 2 {
		t.Fatalf("Read n=%d err=%v", n, err)
	}
	if string(bufs[0][off:off+sizes[0]]) != string(a) || string(bufs[1][off:off+sizes[1]]) != string(c) {
		t.Fatal("batch not compacted correctly")
	}
	e.inner.take() // ICMP for b

	// Write: only packets of known flows reach the app.
	in := [][]byte{
		append(make([]byte, off), udp(ap(webIP, 4000), ap(devIP, 50000), []byte("r1"))...),
		append(make([]byte, off), udp(ap(evilIP, 4000), ap(devIP, 50001), []byte("r2"))...),
		append(make([]byte, off), udp(ap(webIP, 4000), ap(devIP, 50002), []byte("r3"))...),
	}
	n, err = e.fw.Write(in, off)
	if err != nil || n != 3 {
		t.Fatalf("Write n=%d err=%v", n, err)
	}
	got := e.inner.take()
	if len(got) != 2 || string(mustParse(t, got[0]).Payload) != "r1" || string(mustParse(t, got[1]).Payload) != "r3" {
		t.Fatalf("delivered %d packets", len(got))
	}
	// Close unblocks Read.
	e.fw.Close()
	if _, err := e.fw.Read(bufs, sizes, off); err == nil {
		t.Fatal("Read after Close succeeded")
	}
}

func TestConcurrentTraffic(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow))
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			for i := range 500 {
				port := uint16(20000 + g*1000 + i%50)
				e.fw.outbound(tcp(ap(devIP, port), ap(webIP, 443), packet.FlagSYN, nil))
				e.fw.inbound(tcp(ap(webIP, 443), ap(devIP, port), packet.FlagSYN|packet.FlagACK, nil))
				if i%100 == 0 {
					e.setPolicy(snapshot(policy.ActionAllow))
					e.fw.GC()
				}
			}
		})
	}
	wg.Wait()
	_ = e.fw.AppStats()
	_ = e.fw.Counters()
}

func BenchmarkOutboundEstablished(b *testing.B) {
	e := newEnv(b, snapshot(policy.ActionAllow))
	pkt := tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagACK, make([]byte, 1200))
	if !e.fw.outbound(pkt) {
		b.Fatal("dropped")
	}
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		if !e.fw.outbound(pkt) {
			b.Fatal("dropped")
		}
	}
}

func BenchmarkInboundEstablished(b *testing.B) {
	e := newEnv(b, snapshot(policy.ActionAllow))
	e.fw.outbound(tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagSYN, nil))
	pkt := tcp(ap(webIP, 443), ap(devIP, 40000), packet.FlagACK, make([]byte, 1200))
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		if !e.fw.inbound(pkt) {
			b.Fatal("dropped")
		}
	}
}

func BenchmarkReadEstablished(b *testing.B) {
	e := newEnv(b, snapshot(policy.ActionAllow))
	pkt := tcp(ap(devIP, 40000), ap(webIP, 443), packet.FlagACK, make([]byte, 1200))
	e.fw.outbound(pkt)
	bufs := [][]byte{make([]byte, 16+1500)}
	sizes := []int{0}
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		e.inner.in <- pkt
		if n, _ := e.fw.Read(bufs, sizes, 16); n != 1 {
			b.Fatal("dropped")
		}
	}
}

// TestMeshInbound covers ADR-0034 on the device: with a mesh grant, a flow another device
// opens through the Edge (source in the tunnel prefix) is accepted and its replies pass;
// without a grant, or from outside the tunnel prefix, it is dropped.
func TestMeshInbound(t *testing.T) {
	peer := netip.MustParseAddr("100.64.0.9")
	syn := tcp(ap(peer, 50000), ap(devIP, 22), packet.FlagSYN, nil)
	synack := tcp(ap(devIP, 22), ap(peer, 50000), packet.FlagSYN|packet.FlagACK, nil)

	e := newEnv(t, snapshot(policy.ActionBlock))
	if e.fw.inbound(syn) {
		t.Fatal("mesh SYN passed without a grant")
	}

	s := snapshot(policy.ActionBlock)
	s.MeshInbound = []policy.MeshGrant{{RuleID: "ssh", FromAll: true, Protocol: "tcp", Ports: []policy.PortRange{{From: 22}}}}
	e = newEnv(t, s)
	if !e.fw.inbound(syn) {
		t.Fatal("mesh SYN from a tunnel address dropped")
	}
	if !e.fw.outbound(synack) {
		t.Fatal("reply to a mesh flow dropped by the default block")
	}
	if e.fw.inbound(tcp(ap(webIP, 50001), ap(devIP, 22), packet.FlagSYN, nil)) {
		t.Fatal("unsolicited SYN from outside the tunnel prefix passed")
	}
	if e.fw.inbound(tcp(ap(netip.MustParseAddr("100.64.0.1"), 50002), ap(devIP, 22), packet.FlagSYN, nil)) {
		t.Fatal("unsolicited SYN from the Edge address passed")
	}
}

var (
	devIP6  = netip.MustParseAddr("fd7a:5a5e::7")
	dnsIP6  = netip.MustParseAddr("fd7a:5a5e::1")
	webIP6  = netip.MustParseAddr("2001:db8:1::10")
	evilIP6 = netip.MustParseAddr("2001:db8:bad::66")
)

func ipv6Ext(firstNext, proto uint8, src, dst netip.Addr, ext, l4 []byte) []byte {
	pkt := make([]byte, 40+len(ext)+len(l4))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(ext)+len(l4)))
	pkt[6] = firstNext
	pkt[7] = 64
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	copy(pkt[40:], ext)
	l4Off := 40 + len(ext)
	copy(pkt[l4Off:], l4)
	acc := csum(s[:], 0)
	acc = csum(d[:], acc)
	acc += uint32(len(l4)) + uint32(proto)
	var off int
	switch proto {
	case packet.ProtoTCP:
		off = 16
	case packet.ProtoUDP:
		off = 6
	case packet.ProtoICMPv6:
		off = 2
	default:
		return pkt
	}
	cs := fold(csum(pkt[l4Off:], acc))
	if proto == packet.ProtoUDP && cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[l4Off+off:], cs)
	return pkt
}

func tcp6(src, dst netip.AddrPort, flags uint8, payload []byte) []byte {
	return tcp6Ext(src, dst, flags, payload, packet.ProtoTCP, nil)
}

func tcp6Ext(src, dst netip.AddrPort, flags uint8, payload []byte, firstNext uint8, ext []byte) []byte {
	l4 := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(l4[0:2], src.Port())
	binary.BigEndian.PutUint16(l4[2:4], dst.Port())
	binary.BigEndian.PutUint32(l4[4:8], 1000)
	if flags&packet.FlagACK != 0 {
		binary.BigEndian.PutUint32(l4[8:12], 5000)
	}
	l4[12] = 5 << 4
	l4[13] = flags
	binary.BigEndian.PutUint16(l4[14:16], 65535)
	copy(l4[20:], payload)
	return ipv6Ext(firstNext, packet.ProtoTCP, src.Addr(), dst.Addr(), ext, l4)
}

func udp6(src, dst netip.AddrPort, payload []byte) []byte {
	return udp6Ext(src, dst, payload, packet.ProtoUDP, nil)
}

func udp6Ext(src, dst netip.AddrPort, payload []byte, firstNext uint8, ext []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(l4[0:2], src.Port())
	binary.BigEndian.PutUint16(l4[2:4], dst.Port())
	binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	copy(l4[8:], payload)
	return ipv6Ext(firstNext, packet.ProtoUDP, src.Addr(), dst.Addr(), ext, l4)
}

func icmpv6Echo(src, dst netip.Addr, typ uint8, id, seq uint16, payload []byte) []byte {
	return icmpv6EchoExt(src, dst, typ, id, seq, payload, packet.ProtoICMPv6, nil)
}

func icmpv6EchoExt(src, dst netip.Addr, typ uint8, id, seq uint16, payload []byte, firstNext uint8, ext []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	l4[0] = typ
	binary.BigEndian.PutUint16(l4[4:6], id)
	binary.BigEndian.PutUint16(l4[6:8], seq)
	copy(l4[8:], payload)
	return ipv6Ext(firstNext, packet.ProtoICMPv6, src, dst, ext, l4)
}

func icmpv6Error(from, to netip.Addr, typ, code uint8, word uint32, quoted []byte) []byte {
	body := make([]byte, 4+len(quoted))
	binary.BigEndian.PutUint32(body[0:4], word)
	copy(body[4:], quoted)
	return icmpv6(from, to, typ, code, body)
}

func dnsQueryAAAA(t testing.TB, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	m.Id = testDNSID
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dnsAnswerAAAA(t testing.TB, name string, ip netip.Addr) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	m.Id = testDNSID
	m.Response = true
	m.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: ip.AsSlice(),
	}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOutboundVerdictsIPv6(t *testing.T) {
	blockGame := policy.Rule{ID: "no-games", Action: policy.ActionBlock, Match: policy.Match{Apps: []string{"com.game"}}}
	blockEvil6 := policy.Rule{ID: "evil6", Action: policy.ActionBlock, Log: true, Match: policy.Match{CIDRs: []string{"2001:db8:bad::/48"}}}
	blockICMPv6 := policy.Rule{ID: "no-icmpv6", Action: policy.ActionBlock, Match: policy.Match{Protocols: []string{"icmpv6"}}}
	tests := []struct {
		name      string
		snap      *policy.Snapshot
		pkt       []byte
		wantPass  bool
		wantInj   uint8 // 0 none, else protocol of the injected packet
		wantRule  string
		wantApp   string
		wantProto string
	}{
		{"default allow tcp", snapshot(policy.ActionAllow), tcp6(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagSYN, nil), true, 0, "", "com.browser", "tcp"},
		{"default block tcp sends RST", snapshot(policy.ActionBlock), tcp6(ap(devIP6, 40001), ap(webIP6, 443), packet.FlagSYN, nil), false, packet.ProtoTCP, "", "com.browser", "tcp"},
		{"app rule", snapshot(policy.ActionAllow, blockGame), tcp6(ap(devIP6, 40002), ap(webIP6, 80), packet.FlagSYN, nil), false, packet.ProtoTCP, "no-games", "com.game", "tcp"},
		{"cidr rule udp sends ICMPv6", snapshot(policy.ActionAllow, blockEvil6), udp6(ap(devIP6, 40003), ap(evilIP6, 9999), []byte("x")), false, packet.ProtoICMPv6, "evil6", "", "udp"},
		{"icmpv6 protocol rule blocks echo", snapshot(policy.ActionAllow, blockICMPv6), icmpv6Echo(devIP6, webIP6, 128, 0x0042, 1, []byte("ping")), false, packet.ProtoICMPv6, "no-icmpv6", "", "icmpv6"},
		{"default allow icmpv6 echo", snapshot(policy.ActionAllow), icmpv6Echo(devIP6, webIP6, 128, 0x0043, 1, []byte("ping")), true, 0, "", "", "icmpv6"},
		{"no snapshot fails closed", nil, tcp6(ap(devIP6, 40004), ap(webIP6, 443), packet.FlagSYN, nil), false, packet.ProtoTCP, RuleNoSnapshot, "com.browser", "tcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.snap)
			if got := e.fw.outbound(tt.pkt); got != tt.wantPass {
				t.Fatalf("outbound=%v, want %v", got, tt.wantPass)
			}
			inj := e.inner.take()
			if tt.wantInj == 0 {
				if len(inj) != 0 {
					t.Fatalf("unexpected injection")
				}
			} else {
				if len(inj) != 1 {
					t.Fatalf("injected %d packets, want 1", len(inj))
				}
				p := mustParse(t, inj[0])
				orig := mustParse(t, tt.pkt)
				if p.Version != 6 || p.Protocol != tt.wantInj || p.Dst != orig.Src || p.Src != orig.Dst {
					t.Fatalf("injected v%d proto=%d %v->%v", p.Version, p.Protocol, p.Src, p.Dst)
				}
				if p.Protocol == packet.ProtoTCP && (!p.RST() || p.DstPort != orig.SrcPort) {
					t.Fatalf("not an RST to the app: flags=%#x port=%d", p.TCPFlags, p.DstPort)
				}
				if p.Protocol == packet.ProtoICMPv6 && (p.ICMPType != 1 || p.ICMPCode != 1) {
					t.Fatalf("not ICMPv6 administratively prohibited: type=%d code=%d", p.ICMPType, p.ICMPCode)
				}
			}
			recs := e.fw.RecentFlows(10)
			if !tt.wantPass {
				if len(recs) != 1 || recs[0].Decision.RuleID != tt.wantRule || recs[0].Flow.App != tt.wantApp || recs[0].Flow.Protocol != tt.wantProto {
					t.Fatalf("flow log %+v", recs)
				}
			}
			// A retransmission hits the conntrack entry, not the resolver.
			calls := e.res.calls.Load()
			if got := e.fw.outbound(tt.pkt); got != tt.wantPass {
				t.Fatalf("retransmit outbound=%v", got)
			}
			if e.res.calls.Load() != calls {
				t.Fatal("resolver called again for a tracked flow")
			}
		})
	}
}

func TestStatefulInboundIPv6(t *testing.T) {
	e := newEnv(t, snapshot(policy.ActionAllow))
	// Unsolicited inbound packet: dropped.
	if e.fw.inbound(tcp6(ap(webIP6, 443), ap(devIP6, 40000), packet.FlagSYN, nil)) {
		t.Fatal("unsolicited inbound passed")
	}
	if !e.fw.outbound(tcp6(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagSYN, nil)) {
		t.Fatal("SYN dropped")
	}
	synack := tcp6(ap(webIP6, 443), ap(devIP6, 40000), packet.FlagSYN|packet.FlagACK, nil)
	if !e.fw.inbound(synack) {
		t.Fatal("SYN-ACK dropped")
	}
	// Same remote, other local port: no flow.
	if e.fw.inbound(tcp6(ap(webIP6, 443), ap(devIP6, 40001), packet.FlagACK, nil)) {
		t.Fatal("inbound for unknown port passed")
	}
	ent := e.fw.ct.get(keyOf(t, tcp6(ap(devIP6, 40000), ap(webIP6, 443), 0, nil)))
	if ent.state.Load() != stEstablished {
		t.Fatal("not established after SYN-ACK")
	}
	if ent.bytesIn.Load() != uint64(len(synack)) {
		t.Fatalf("bytesIn=%d", ent.bytesIn.Load())
	}

	// Open UDP and ICMPv6 echo flows for related-error tests below.
	if !e.fw.outbound(udp6(ap(devIP6, 50000), ap(webIP6, 5353), []byte("hi"))) {
		t.Fatal("outbound UDP dropped")
	}
	if !e.fw.inbound(udp6(ap(webIP6, 5353), ap(devIP6, 50000), []byte("ok"))) {
		t.Fatal("inbound UDP reply dropped")
	}
	if !e.fw.outbound(icmpv6Echo(devIP6, webIP6, 128, 0x1234, 1, []byte("ping"))) {
		t.Fatal("outbound ICMPv6 echo dropped")
	}
	if !e.fw.inbound(icmpv6Echo(webIP6, devIP6, 129, 0x1234, 1, []byte("ping"))) {
		t.Fatal("inbound ICMPv6 echo reply dropped")
	}
	if e.fw.inbound(icmpv6Echo(webIP6, devIP6, 129, 0x9999, 1, []byte("ping"))) {
		t.Fatal("unsolicited ICMPv6 echo reply passed")
	}

	routerIP6 := netip.MustParseAddr("2001:db8:ff::1")
	hbhToDst := []byte{ipv6DestOpts, 0, 1, 4, 0, 0, 0, 0}
	dstToTCP := []byte{packet.ProtoTCP, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	hbhDstExt := append(append([]byte(nil), hbhToDst...), dstToTCP...)
	routingToUDP := []byte{packet.ProtoUDP, 0, 0, 0, 0, 0, 0, 0}
	fragFirstTCP := []byte{packet.ProtoTCP, 0, 0x00, 0x01, 0, 0, 0, 7}    // offset 0, M=1
	fragNonFirstTCP := []byte{packet.ProtoTCP, 0, 0x00, 0xb8, 0, 0, 0, 7} // offset 184, M=0
	hbhToICMPv6 := []byte{packet.ProtoICMPv6, 0, 1, 4, 0, 0, 0, 0}

	var maxExt []byte
	for range 7 {
		maxExt = append(maxExt, ipv6DestOpts, 0, 1, 4, 0, 0, 0, 0)
	}
	maxExt = append(maxExt, packet.ProtoTCP, 0, 1, 4, 0, 0, 0, 0) // 8 ext headers total

	var tooManyExt []byte
	for range 8 {
		tooManyExt = append(tooManyExt, ipv6DestOpts, 0, 1, 4, 0, 0, 0, 0)
	}
	tooManyExt = append(tooManyExt, packet.ProtoTCP, 0, 1, 4, 0, 0, 0, 0) // 9 ext headers total

	tcpPlain := tcp6(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagACK, []byte("data"))
	tcpWithExt := tcp6Ext(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagACK, []byte("big payload"), ipv6HopByHop, hbhDstExt)
	udpWithRouting := udp6Ext(ap(devIP6, 50000), ap(webIP6, 5353), []byte("data"), ipv6Routing, routingToUDP)
	tcpFirstFrag := tcp6Ext(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagACK, []byte("data"), ipv6Fragment, fragFirstTCP)
	tcpNonFirstFrag := tcp6Ext(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagACK, nil, ipv6Fragment, fragNonFirstTCP)
	tcpMaxExt := tcp6Ext(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagACK, nil, ipv6DestOpts, maxExt)
	tcpTooManyExt := tcp6Ext(ap(devIP6, 40000), ap(webIP6, 443), packet.FlagACK, nil, ipv6DestOpts, tooManyExt)
	echoPlain := icmpv6Echo(devIP6, webIP6, 128, 0x1234, 1, []byte("ping"))
	echoWithExt := icmpv6EchoExt(devIP6, webIP6, 128, 0x1234, 2, []byte("big ping"), ipv6HopByHop, hbhToICMPv6)
	otherTCP := tcp6(ap(devIP6, 41000), ap(webIP6, 443), packet.FlagACK, nil)
	otherEcho := icmpv6Echo(devIP6, webIP6, 128, 0x9999, 1, nil)
	nonEchoICMP := icmpv6Error(devIP6, webIP6, 1, 0, 0, make([]byte, 8))
	spoofedSrc := tcp6(ap(evilIP6, 40000), ap(webIP6, 443), packet.FlagACK, nil)

	errTests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"PTB quoting truncated plain TCP", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpPlain[:48]), true},
		{"PTB quoting truncated TCP with hbh and dest opts", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpWithExt[:40+len(hbhDstExt)+8]), true},
		{"PTB quoting truncated UDP with routing header", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, udpWithRouting[:40+len(routingToUDP)+4]), true},
		{"PTB quoting TCP with first fragment header", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpFirstFrag[:40+len(fragFirstTCP)+8]), true},
		{"PTB quoting TCP with 8 extension headers", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpMaxExt[:40+len(maxExt)+8]), true},
		{"Time Exceeded quoting ICMPv6 echo", icmpv6Error(routerIP6, devIP6, 3, 0, 0, echoPlain[:48]), true},
		{"PTB quoting ICMPv6 echo with hbh header", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, echoWithExt[:40+len(hbhToICMPv6)+8]), true},
		{"PTB quoting unrelated TCP port", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, otherTCP), false},
		{"PTB quoting unrelated ICMPv6 echo id", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, otherEcho), false},
		{"PTB quoting non-first fragment", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpNonFirstFrag), false},
		{"PTB quoting truncated extension header", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpWithExt[:40+len(hbhToDst)+4]), false},
		{"PTB quoting truncated extension header body", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpWithExt[:40+len(hbhToDst)+10]), false},
		{"PTB quoting truncated L4 ports", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpWithExt[:40+len(hbhDstExt)+2]), false},
		{"PTB quoting truncated ICMPv6 echo header", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, echoPlain[:44]), false},
		{"PTB quoting too many extension headers", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, tcpTooManyExt), false},
		{"PTB quoting non-echo ICMPv6", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, nonEchoICMP), false},
		{"PTB quoting spoofed source", icmpv6Error(routerIP6, devIP6, 2, 0, 1280, spoofedSrc), false},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.fw.inbound(tt.pkt); got != tt.want {
				t.Fatalf("inbound=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSBlockIPv6(t *testing.T) {
	tests := []struct {
		name      string
		blockResp string
		wantRcode int
		wantZero  bool
	}{
		{"nxdomain", "nxdomain", dns.RcodeNameError, false},
		{"zero returns unspecified AAAA", "zero", dns.RcodeSuccess, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := snapshot(policy.ActionAllow)
			s.DNS.BlockResponse = tt.blockResp
			e := newEnv(t, s, func(c *Config) { c.DNSServers = []netip.Addr{dnsIP6} })
			q := udp6(ap(devIP6, 50000), ap(dnsIP6, 53), dnsQueryAAAA(t, "Blocked.Example"))
			if e.fw.outbound(q) {
				t.Fatal("blocked query forwarded")
			}
			inj := e.inner.take()
			if len(inj) != 1 {
				t.Fatalf("injected %d", len(inj))
			}
			p := mustParse(t, inj[0])
			if p.Version != 6 || p.Protocol != packet.ProtoUDP || p.Src != dnsIP6 || p.Dst != devIP6 || p.SrcPort != 53 || p.DstPort != 50000 {
				t.Fatalf("response addressing v%d proto=%d %v:%d -> %v:%d", p.Version, p.Protocol, p.Src, p.SrcPort, p.Dst, p.DstPort)
			}
			var m dns.Msg
			if err := m.Unpack(p.Payload); err != nil || m.Rcode != tt.wantRcode {
				t.Fatalf("rcode %d want %d err %v", m.Rcode, tt.wantRcode, err)
			}
			if tt.wantZero {
				if len(m.Answer) != 1 {
					t.Fatalf("answers %d, want 1", len(m.Answer))
				}
				rr, ok := m.Answer[0].(*dns.AAAA)
				if !ok {
					t.Fatalf("answer type %T, want *dns.AAAA", m.Answer[0])
				}
				ip, ok := netip.AddrFromSlice(rr.AAAA)
				if !ok || ip != netip.IPv6Unspecified() {
					t.Fatalf("zero AAAA = %v (ok=%v), want ::", ip, ok)
				}
			} else if len(m.Answer) != 0 {
				t.Fatalf("unexpected answers %+v", m.Answer)
			}
			// An allowed query on the same flow is forwarded.
			if !e.fw.outbound(udp6(ap(devIP6, 50000), ap(dnsIP6, 53), dnsQueryAAAA(t, "fine.example"))) {
				t.Fatal("allowed query dropped")
			}
			st := e.dns.Stats()
			if len(st) != 1 || st[0].App != "com.browser" || st[0].Queries != 2 || st[0].Blocked != 1 {
				t.Fatalf("dns stats %+v", st)
			}
			if recs := e.fw.RecentFlows(1); len(recs) != 1 || recs[0].Decision.Layer != LayerDNS || recs[0].Flow.Domain != "blocked.example" || recs[0].Flow.DstIP != dnsIP6.String() {
				t.Fatalf("flow log %+v", recs)
			}
		})
	}
}

func TestDomainRuleViaAAAASnoop(t *testing.T) {
	rule := policy.Rule{ID: "no-social", Action: policy.ActionBlock, Match: policy.Match{Domains: []string{"*.social.example"}}}
	tests := []struct {
		name            string
		queryPkt        []byte
		respPkt         []byte
		unsolicitedResp []byte
	}{
		{
			name:            "AAAA over IPv6 DNS",
			queryPkt:        udp6(ap(devIP6, 50001), ap(dnsIP6, 53), dnsQueryAAAA(t, "www.social.example")),
			respPkt:         udp6(ap(dnsIP6, 53), ap(devIP6, 50001), dnsAnswerAAAA(t, "www.social.example", evilIP6)),
			unsolicitedResp: udp6(ap(dnsIP6, 53), ap(devIP6, 59999), dnsAnswerAAAA(t, "spoof.example", webIP6)),
		},
		{
			name:            "AAAA over IPv4 DNS (cross-family)",
			queryPkt:        udp(ap(devIP, 50002), ap(dnsIP, 53), dnsQueryAAAA(t, "www.social.example")),
			respPkt:         udp(ap(dnsIP, 53), ap(devIP, 50002), dnsAnswerAAAA(t, "www.social.example", evilIP6)),
			unsolicitedResp: udp(ap(dnsIP, 53), ap(devIP, 59999), dnsAnswerAAAA(t, "spoof.example", webIP6)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, snapshot(policy.ActionAllow, rule), func(c *Config) {
				c.DNSServers = []netip.Addr{dnsIP, dnsIP6}
			})
			// Before DNS: no domain known, allowed.
			if !e.fw.outbound(tcp6(ap(devIP6, 40000), ap(evilIP6, 443), packet.FlagSYN, nil)) {
				t.Fatal("flow without known domain blocked")
			}
			// DNS AAAA query + response teach the cache that evilIP6 is www.social.example.
			if !e.fw.outbound(tt.queryPkt) {
				t.Fatal("query dropped")
			}
			if !e.fw.inbound(tt.respPkt) {
				t.Fatal("response dropped")
			}
			if got := e.dns.Domain(evilIP6); got != "www.social.example" {
				t.Fatalf("snooped %q", got)
			}
			// New IPv6 flow to that IP is blocked by the domain rule.
			if e.fw.outbound(tcp6(ap(devIP6, 40001), ap(evilIP6, 443), packet.FlagSYN, nil)) {
				t.Fatal("domain rule not applied")
			}
			if inj := e.inner.take(); len(inj) != 1 || !isRST(t, inj[0]) || mustParse(t, inj[0]).Version != 6 {
				t.Fatalf("expected IPv6 RST, got %d injected", len(inj))
			}
			recs := e.fw.RecentFlows(1)
			if len(recs) != 1 || recs[0].Decision.RuleID != "no-social" || recs[0].Flow.Domain != "www.social.example" || recs[0].Flow.DstIP != evilIP6.String() {
				t.Fatalf("record %+v", recs)
			}
			// Responses not matching a flow are not snooped.
			if e.fw.inbound(tt.unsolicitedResp) {
				t.Fatal("unsolicited DNS response passed")
			}
			if e.dns.Domain(webIP6) != "" {
				t.Fatal("snooped an unsolicited response")
			}
		})
	}
}

func TestMeshInboundIPv6(t *testing.T) {
	peer6 := netip.MustParseAddr("fd7a:5a5e::9")
	tcpSyn := tcp6(ap(peer6, 50000), ap(devIP6, 22), packet.FlagSYN, nil)
	tcpSynAck := tcp6(ap(devIP6, 22), ap(peer6, 50000), packet.FlagSYN|packet.FlagACK, nil)
	udpIn := udp6(ap(peer6, 50001), ap(devIP6, 51820), []byte("hi"))
	udpOut := udp6(ap(devIP6, 51820), ap(peer6, 50001), []byte("ok"))
	echoReq := icmpv6Echo(peer6, devIP6, 128, 0x0077, 1, []byte("ping"))
	echoRep := icmpv6Echo(devIP6, peer6, 129, 0x0077, 1, []byte("ping"))

	grants := []policy.MeshGrant{
		{RuleID: "ssh", FromAll: true, Protocol: "tcp", Ports: []policy.PortRange{{From: 22}}},
		{RuleID: "ping6", FromAll: true, Protocol: "icmpv6"},
	}
	tests := []struct {
		name     string
		grants   []policy.MeshGrant
		inPkt    []byte
		replyPkt []byte
		errPkt   []byte // optional inbound ICMPv6 error quoting replyPkt
		wantIn   bool
	}{
		{"TCP SYN without grant dropped", nil, tcpSyn, nil, nil, false},
		{"TCP SYN from peer allowed", grants, tcpSyn, tcpSynAck, nil, true},
		{"UDP from peer allowed", grants, udpIn, udpOut, nil, true},
		{"ICMPv6 echo from peer allowed", grants, echoReq, echoRep, icmpv6Error(peer6, devIP6, 2, 0, 1280, echoRep[:48]), true},
		{"TCP ACK without SYN from peer dropped", grants, tcp6(ap(peer6, 50002), ap(devIP6, 22), packet.FlagACK, nil), nil, nil, false},
		{"unsolicited ICMPv6 echo reply from peer dropped", grants, icmpv6Echo(peer6, devIP6, 129, 0x0078, 1, nil), nil, nil, false},
		{"TCP SYN from outside tunnel prefix dropped", grants, tcp6(ap(webIP6, 50003), ap(devIP6, 22), packet.FlagSYN, nil), nil, nil, false},
		{"TCP SYN from Edge IPv6 dropped", grants, tcp6(ap(dnsIP6, 50004), ap(devIP6, 22), packet.FlagSYN, nil), nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := snapshot(policy.ActionBlock)
			s.MeshInbound = tt.grants
			e := newEnv(t, s)
			if got := e.fw.inbound(tt.inPkt); got != tt.wantIn {
				t.Fatalf("inbound=%v, want %v", got, tt.wantIn)
			}
			if tt.replyPkt != nil && !e.fw.outbound(tt.replyPkt) {
				t.Fatal("reply to IPv6 mesh flow dropped by default block")
			}
			if tt.errPkt != nil && !e.fw.inbound(tt.errPkt) {
				t.Fatal("related ICMPv6 error quoting mesh echo reply dropped")
			}
		})
	}

	// Removing mesh grants via policy hot-swap blocks an existing IPv6 mesh flow.
	s1 := snapshot(policy.ActionBlock)
	s1.MeshInbound = grants
	e := newEnv(t, s1)
	if !e.fw.inbound(tcpSyn) || !e.fw.outbound(tcpSynAck) {
		t.Fatal("mesh TCP flow did not establish")
	}
	s2 := snapshot(policy.ActionBlock)
	s2.Version = 2
	e.setPolicy(s2)
	if e.fw.outbound(tcp6(ap(devIP6, 22), ap(peer6, 50000), packet.FlagACK, []byte("x"))) {
		t.Fatal("IPv6 mesh flow passed after grants were removed")
	}
}
