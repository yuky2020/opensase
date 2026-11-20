package edge

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestSynthMapStickyBidirectional(t *testing.T) {
	m := newSynthMap(SyntheticPrefix, 16, time.Hour)
	now := time.Now()
	a1, err := m.assign("acme", "intranet.acme.internal", now)
	if err != nil || !SyntheticPrefix.Contains(a1) || a1 == SyntheticPrefix.Addr() {
		t.Fatalf("assign: %v %v", a1, err)
	}
	if a, _ := m.assign("acme", "intranet.acme.internal", now.Add(time.Minute)); a != a1 {
		t.Fatalf("not sticky: %v != %v", a, a1)
	}
	// Same name in another tenant gets its own address (overlapping customer spaces).
	a2, _ := m.assign("globex", "intranet.acme.internal", now)
	if a2 == a1 {
		t.Fatal("tenants share an address")
	}
	if tn, name, ok := m.lookup(a1, now); !ok || tn != "acme" || name != "intranet.acme.internal" {
		t.Fatalf("reverse: %q %q %v", tn, name, ok)
	}
	if _, _, ok := m.lookup(netip.MustParseAddr("100.96.200.200"), now); ok {
		t.Fatal("unassigned address resolved")
	}
}

func TestSynthMapIdleAndBound(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, m *synthMap, now time.Time)
	}{
		{"idle expiry on lookup", func(t *testing.T, m *synthMap, now time.Time) {
			a, _ := m.assign("t", "a.example", now)
			if _, _, ok := m.lookup(a, now.Add(2*time.Hour)); ok {
				t.Fatal("idle mapping still resolves")
			}
		}},
		{"use keeps it alive", func(t *testing.T, m *synthMap, now time.Time) {
			a, _ := m.assign("t", "a.example", now)
			for i := 1; i <= 3; i++ {
				if _, _, ok := m.lookup(a, now.Add(time.Duration(i)*50*time.Minute)); !ok {
					t.Fatalf("used mapping expired at step %d", i)
				}
			}
		}},
		{"sweep", func(t *testing.T, m *synthMap, now time.Time) {
			m.assign("t", "old.example", now)
			m.assign("t", "new.example", now.Add(90*time.Minute))
			m.sweep(now.Add(100 * time.Minute))
			if m.len() != 1 {
				t.Fatalf("len after sweep %d", m.len())
			}
		}},
		{"lru bound", func(t *testing.T, m *synthMap, now time.Time) {
			first, _ := m.assign("t", "n0.example", now)
			for i := 1; i < 6; i++ {
				m.assign("t", "n"+string(rune('0'+i))+".example", now.Add(time.Duration(i)*time.Second))
			}
			if m.len() != 4 {
				t.Fatalf("len %d, want bound 4", m.len())
			}
			if _, _, ok := m.lookup(first, now.Add(10*time.Second)); ok {
				t.Fatal("least recently used entry not evicted")
			}
			// Next-fit: an evicted address is not handed out again right away.
			a, _ := m.assign("t", "n9.example", now.Add(11*time.Second))
			if a == first {
				t.Fatal("evicted address reused immediately")
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newSynthMap(SyntheticPrefix, 4, time.Hour), time.Now())
		})
	}
}

func TestSynthMapExhausted(t *testing.T) {
	m := newSynthMap(netip.MustParsePrefix("100.96.0.0/30"), 100, time.Hour) // 2 usable
	now := time.Now()
	for _, n := range []string{"a", "b"} {
		if _, err := m.assign("t", n, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.assign("t", "c", now); err != errSynthExhausted {
		t.Fatalf("err %v", err)
	}
}

func TestPrivateAppMatcher(t *testing.T) {
	c, err := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "acme", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow}, PrivateApps: []policy.PrivateApp{
		{ID: "intranet", Domains: []string{"Intranet.Acme.Internal."}, Ports: []policy.PortRange{{From: 80}, {From: 8000, To: 8010}}},
		{ID: "wiki", Domains: []string{"*.wiki.acme.internal"}, Ports: []policy.PortRange{{From: 443}}},
		{ID: "noports", Domains: []string{"closed.acme.internal"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	v := newZTNAView("acme", c)
	tests := []struct {
		name   string
		port   uint16
		app    string // name match
		access string // name + port
	}{
		{"intranet.acme.internal", 80, "intranet", "intranet"},
		{"INTRANET.acme.internal.", 8005, "intranet", "intranet"},
		{"intranet.acme.internal", 81, "intranet", ""},
		{"x.intranet.acme.internal", 80, "", ""},
		{"wiki.acme.internal", 443, "wiki", "wiki"},
		{"a.b.wiki.acme.internal", 443, "wiki", "wiki"},
		{"badwiki.acme.internal", 443, "", ""},
		{"closed.acme.internal", 80, "noports", ""},
		{"", 80, "", ""},
	}
	for _, tc := range tests {
		a, ok := v.app(tc.name)
		if got := map[bool]string{true: a.ID}[ok]; got != tc.app {
			t.Errorf("app(%q) = %q want %q", tc.name, got, tc.app)
		}
		a, ok = v.access(tc.name, tc.port)
		if got := map[bool]string{true: a.ID}[ok]; got != tc.access {
			t.Errorf("access(%q, %d) = %q want %q", tc.name, tc.port, got, tc.access)
		}
	}
	var nilView *ztnaView
	if _, ok := nilView.app("x"); ok {
		t.Fatal("nil view matched")
	}
}

func TestResolverSynthesizesPrivateApps(t *testing.T) {
	fx := newFixture(t)
	fx.apps = []policy.PrivateApp{{ID: "intranet", Name: "Intranet", Domains: []string{"intranet.acme.internal"}, Ports: []policy.PortRange{{From: 80}}, ConnectorGroup: "default"}}
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	r := fx.e.reg
	r.mu.Lock()
	d := r.devices["d1"]
	d.offset, d.ip4, d.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd7a:5a5e::2")
	r.reindexLocked()
	r.mu.Unlock()

	upstreamQueries := make(chan string, 16)
	upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		upstreamQueries <- req.Question[0].Name
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 7)})
		_ = w.WriteMsg(m)
	}))
	edgeDNS := startDNS(t, newResolver(fx.e, upstream))
	c := new(dns.Client)
	ask := func(name string, qt uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, qt)
		resp, _, err := c.Exchange(m, edgeDNS)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := ask("Intranet.Acme.Internal.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("A: %v", resp)
	}
	a := resp.Answer[0].(*dns.A)
	ip, _ := netip.AddrFromSlice(a.A.To4())
	if !SyntheticPrefix.Contains(ip) || a.Hdr.Ttl != synthTTL {
		t.Fatalf("answer %v ttl %d", ip, a.Hdr.Ttl)
	}
	if again := ask("intranet.acme.internal.", dns.TypeA).Answer[0].(*dns.A); !again.A.Equal(a.A) {
		t.Fatal("mapping not sticky")
	}
	if tn, name, ok := fx.e.synth.lookup(ip, time.Now()); !ok || tn != "acme" || name != "intranet.acme.internal" {
		t.Fatalf("reverse %q %q %v", tn, name, ok)
	}
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeMX, dns.TypeHTTPS} {
		if r := ask("intranet.acme.internal.", qt); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
			t.Fatalf("type %d: %v", qt, r)
		}
	}
	// Ordinary names still go upstream; private names never did.
	ask("example.com.", dns.TypeA)
	var seen []string
	for len(upstreamQueries) > 0 {
		seen = append(seen, <-upstreamQueries)
	}
	if len(seen) != 1 || seen[0] != "example.com." {
		t.Fatalf("upstream saw %v", seen)
	}
}

// TCP to a synthetic address that maps to an entitled name passes the filter despite the
// built-in deny of 100.64.0.0/10; anything else to the synthetic prefix is rejected.
func TestFilterSyntheticExemption(t *testing.T) {
	fx := newFixture(t)
	fx.apps = []policy.PrivateApp{{ID: "intranet", Domains: []string{"intranet.acme.internal"}, Ports: []policy.PortRange{{From: 80}}, ConnectorGroup: "default"}}
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()
	me := d.ip4.String()
	now := time.Now()
	known, _ := fx.e.synth.assign("acme", "intranet.acme.internal", now)
	other, _ := fx.e.synth.assign("globex", "intranet.globex.internal", now)
	stale, _ := fx.e.synth.assign("acme", "gone.acme.internal", now) // not in the snapshot

	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)
	tests := []struct {
		name string
		pkt  []byte
		pass bool
		rule string
	}{
		{"tcp to entitled name", ipv4(me, known.String(), packet.ProtoTCP, tcpSeg(42000, 80, packet.FlagSYN)), true, ""},
		// The port is checked by the broker (RST there), not by the filter.
		{"tcp other port to entitled name", ipv4(me, known.String(), packet.ProtoTCP, tcpSeg(42001, 81, packet.FlagSYN)), true, ""},
		{"udp to entitled name", ipv4(me, known.String(), packet.ProtoUDP, udpDgram(42002, 80)), false, "ztna:tcp-only"},
		{"other tenant's address", ipv4(me, other.String(), packet.ProtoTCP, tcpSeg(42003, 80, packet.FlagSYN)), false, "ztna:unknown-address"},
		{"name not entitled", ipv4(me, stale.String(), packet.ProtoTCP, tcpSeg(42004, 80, packet.FlagSYN)), false, "ztna:unknown-address"},
		{"unassigned address", ipv4(me, "100.96.9.9", packet.ProtoTCP, tcpSeg(42005, 80, packet.FlagSYN)), false, "ztna:unknown-address"},
		// The rest of the tunnel range stays unreachable (no device-to-device traffic).
		{"tunnel range outside the pool", ipv4(me, "100.120.1.1", packet.ProtoTCP, tcpSeg(42006, 80, packet.FlagSYN)), false, ""},
	}
	for _, tc := range tests {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{tc.pkt}, 0); err != nil {
			t.Fatal(err)
		}
		if got := ft.nWrites() > before; got != tc.pass {
			t.Errorf("%s: pass=%v", tc.name, got)
		}
		if tc.rule != "" {
			if _, ok := readOne(t, rd); !ok {
				t.Errorf("%s: no RST/ICMP unreachable", tc.name)
			}
		}
	}
	// The reply of the redirected connection (de-NATed to the synthetic source) reaches the device.
	ft.in <- ipv4(known.String(), me, packet.ProtoTCP, tcpSeg(80, 42000, packet.FlagSYN|packet.FlagACK))
	if _, ok := readOne(t, rd); !ok {
		t.Fatal("SYN-ACK from the synthetic address dropped")
	}
	rules := map[string]int{}
	fx.e.flows.mu.Lock()
	for _, r := range fx.e.flows.recs {
		if r.Decision.Layer == LayerZTNA {
			rules[r.Decision.RuleID]++
		}
	}
	fx.e.flows.mu.Unlock()
	if rules["ztna:tcp-only"] != 1 || rules["ztna:unknown-address"] != 3 {
		t.Fatalf("ztna block records %v", rules)
	}
}

func TestRegistrySkipsSyntheticPrefix(t *testing.T) {
	r := newRegistry()
	b4 := SyntheticPrefix.Addr().As4()
	t4 := TunnelPrefix4.Addr().As4()
	off := (uint32(b4[1])-uint32(t4[1]))<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	r.next = off - 1
	d1, d2 := &device{id: "a"}, &device{id: "b"}
	r.mu.Lock()
	_ = r.allocateLocked(d1)
	_ = r.allocateLocked(d2)
	r.mu.Unlock()
	if SyntheticPrefix.Contains(d1.ip4) || SyntheticPrefix.Contains(d2.ip4) {
		t.Fatalf("device got a synthetic address: %v %v", d1.ip4, d2.ip4)
	}
	if want := netip.MustParseAddr("100.112.0.0"); d2.ip4 != want {
		t.Fatalf("second allocation %v, want %v (first after the pool)", d2.ip4, want)
	}
}
