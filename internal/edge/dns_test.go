package edge

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/policy"
)

func startDNS(t *testing.T, h dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func startDNS6(t *testing.T, h dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func startDNSTCP6(t *testing.T, h dns.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{Listener: ln, Handler: h, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}

func TestResolver(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())

	// Pretend the device's tunnel address is 127.0.0.1 so the test client maps to it.
	r := fx.e.reg
	r.mu.Lock()
	d := r.devices["d1"]
	d.offset, d.ip4, d.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd7a:5a5e::2")
	r.reindexLocked()
	r.mu.Unlock()

	upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Name == "cloak.example." {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "x.doubleclick.net."})
		}
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 7)})
		_ = w.WriteMsg(m)
	}))
	edgeDNS := startDNS(t, newResolver(fx.e, upstream))

	tests := []struct {
		name  string
		rcode int
		snoop bool
	}{
		{"example.com.", dns.RcodeSuccess, true},
		{"ads.doubleclick.net.", dns.RcodeNameError, false},
		{"DoubleClick.NET.", dns.RcodeNameError, false},
		{"cloak.example.", dns.RcodeNameError, false},
	}
	c := new(dns.Client)
	for _, tc := range tests {
		m := new(dns.Msg)
		m.SetQuestion(tc.name, dns.TypeA)
		resp, _, err := c.Exchange(m, edgeDNS)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if resp.Rcode != tc.rcode {
			t.Errorf("%s: rcode %s", tc.name, dns.RcodeToString[resp.Rcode])
		}
		if tc.snoop {
			if got := fx.e.snoop.lookup(d.id, netip.MustParseAddr("192.0.2.7")); got != normalize(tc.name) {
				t.Errorf("%s: snooped %q", tc.name, got)
			}
		}
	}
	if fx.e.flows.pending() != 3 {
		t.Fatalf("dns block records: %d", fx.e.flows.pending())
	}

	// Unknown client: REFUSED.
	r.mu.Lock()
	delete(r.devices, "d1")
	r.reindexLocked()
	r.mu.Unlock()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if resp, _, err := c.Exchange(m, edgeDNS); err != nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("unknown client: %v %v", resp, err)
	}
}

// TestResolverInternalDNS covers issue #62: device names in the tenant zone, tenant records
// and conditional forwarding.
func TestResolverInternalDNS(t *testing.T) {
	fx := newFixture(t)
	forwarded := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(10, 9, 9, 9)})
		_ = w.WriteMsg(m)
	}))
	upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused) // never asked for internal names
		_ = w.WriteMsg(m)
	}))
	fx.dnsMod = func(d *policy.DNSPolicy) {
		d.Zone = "corp.internal"
		d.Records = []policy.DNSRecord{
			{Name: "nas.corp.internal", Type: "A", Value: "10.0.0.5"},
			{Name: "wiki.corp.internal", Type: "CNAME", Value: "nas.corp.internal"},
		}
		d.Forwarders = []policy.DNSForwarder{{Zone: "ad.example", Servers: []string{forwarded}}}
	}
	fx.setPeer("d1", 1)
	fx.setPeer("d2", 1)
	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		fx.cp.peers.Devices[i].DNSName = fx.cp.peers.Devices[i].DeviceID + ".alice"
	}
	fx.cp.mu.Unlock()
	_ = fx.e.syncPeers(context.Background())
	r := fx.e.reg
	r.mu.Lock()
	d1, d2 := r.devices["d1"], r.devices["d2"]
	d1.offset, d1.ip4 = 2, netip.MustParseAddr("127.0.0.1")
	d2.offset, d2.ip4 = 3, netip.MustParseAddr("100.64.0.3")
	r.reindexLocked()
	r.mu.Unlock()
	edgeDNS := startDNS(t, newResolver(fx.e, upstream))

	ask := func(name string, qt uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, qt)
		resp, _, err := new(dns.Client).Exchange(m, edgeDNS)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return resp
	}
	a := func(resp *dns.Msg) string {
		for _, rr := range resp.Answer {
			if v, ok := rr.(*dns.A); ok {
				return v.A.String()
			}
		}
		return ""
	}
	if got := a(ask("d2.alice.corp.internal.", dns.TypeA)); got != "100.64.0.3" {
		t.Fatalf("device name: %q", got)
	}
	if resp := ask("nobody.alice.corp.internal.", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown device name: %s", dns.RcodeToString[resp.Rcode])
	}
	if got := a(ask("nas.corp.internal.", dns.TypeA)); got != "10.0.0.5" {
		t.Fatalf("record: %q", got)
	}
	if resp := ask("wiki.corp.internal.", dns.TypeA); a(resp) != "10.0.0.5" || len(resp.Answer) != 2 {
		t.Fatalf("cname: %v", resp.Answer)
	}
	if got := a(ask("dc1.ad.example.", dns.TypeA)); got != "10.9.9.9" {
		t.Fatalf("forwarded: %q", got)
	}
	if resp := ask("public.example.", dns.TypeA); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("other names go upstream: %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestDNSLocal(t *testing.T) {
	tests := []struct {
		name      string
		addr      net.Addr
		wantDst   string
		wantProto string
	}{
		{"ipv4 udp", &net.UDPAddr{IP: net.ParseIP("100.64.0.1"), Port: 53}, "100.64.0.1", "udp"},
		{"ipv4 tcp", &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 53}, "100.64.0.1", "tcp"},
		{"ipv6 udp", &net.UDPAddr{IP: net.ParseIP("fd7a:5a5e::1"), Port: 53}, "fd7a:5a5e::1", "udp"},
		{"ipv6 tcp", &net.TCPAddr{IP: net.ParseIP("fd7a:5a5e::1"), Port: 53}, "fd7a:5a5e::1", "tcp"},
		{"nil fallback", nil, EdgeIPv4.String(), "udp"},
		{"unspecified ipv4 fallback", &net.UDPAddr{IP: net.IPv4zero, Port: 53}, EdgeIPv4.String(), "udp"},
		{"unspecified ipv6 tcp fallback", &net.TCPAddr{IP: net.IPv6zero, Port: 53}, EdgeIPv4.String(), "tcp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst, proto := dnsLocal(tc.addr)
			if dst != tc.wantDst || proto != tc.wantProto {
				t.Errorf("dnsLocal(%v) = (%q, %q), want (%q, %q)", tc.addr, dst, proto, tc.wantDst, tc.wantProto)
			}
		})
	}
}

func TestResolverIPv6(t *testing.T) {
	aaaa := func(resp *dns.Msg) string {
		for _, rr := range resp.Answer {
			if v, ok := rr.(*dns.AAAA); ok {
				return v.AAAA.String()
			}
		}
		return ""
	}

	t.Run("aaaa and flow logs", func(t *testing.T) {
		fx := newFixture(t)
		fx.dnsMod = func(d *policy.DNSPolicy) {
			d.LogQueries = true
		}
		fx.setPeer("d1", 1)
		_ = fx.e.syncPeers(context.Background())

		r := fx.e.reg
		r.mu.Lock()
		d := r.devices["d1"]
		d.offset, d.ip4, d.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
		r.reindexLocked()
		r.mu.Unlock()

		upstream := startDNS6(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			q := req.Question[0]
			switch q.Name {
			case "cloak.example.":
				m.Answer = append(m.Answer,
					&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "x.doubleclick.net."},
					&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::8")},
				)
			case "mapped.example.":
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.IP(netip.MustParseAddr("::ffff:192.0.2.44").AsSlice()),
				})
			default:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::7"),
				})
			}
			_ = w.WriteMsg(m)
		}))
		rs := newResolver(fx.e, upstream)
		edgeUDP6 := startDNS6(t, rs)
		edgeTCP6 := startDNSTCP6(t, rs)

		tests := []struct {
			name       string
			qname      string
			proto      string
			addr       string
			wantRcode  int
			wantAAAA   string
			wantSnoop  string
			wantAction policy.Action
			wantRule   string
		}{
			{"allowed AAAA over udp6", "example.com.", "udp", edgeUDP6, dns.RcodeSuccess, "2001:db8::7", "2001:db8::7", policy.ActionAllow, "dns:query"},
			{"allowed AAAA over tcp6", "example.com.", "tcp", edgeTCP6, dns.RcodeSuccess, "2001:db8::7", "2001:db8::7", policy.ActionAllow, "dns:query"},
			{"v4-mapped AAAA unmapped in snoop", "mapped.example.", "udp", edgeUDP6, dns.RcodeSuccess, "192.0.2.44", "192.0.2.44", policy.ActionAllow, "dns:query"},
			{"blocked AAAA nxdomain over udp6", "ads.doubleclick.net.", "udp", edgeUDP6, dns.RcodeNameError, "", "", policy.ActionBlock, "dns:ads"},
			{"cname-cloaked AAAA over tcp6", "cloak.example.", "tcp", edgeTCP6, dns.RcodeNameError, "", "", policy.ActionBlock, "dns:ads"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				fx.e.flows.mu.Lock()
				before := len(fx.e.flows.recs)
				fx.e.flows.mu.Unlock()

				m := new(dns.Msg)
				m.SetQuestion(tc.qname, dns.TypeAAAA)
				c := &dns.Client{Net: tc.proto}
				resp, _, err := c.Exchange(m, tc.addr)
				if err != nil {
					t.Fatalf("%s: %v", tc.qname, err)
				}
				if resp.Rcode != tc.wantRcode {
					t.Fatalf("rcode %s want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.wantRcode])
				}
				if tc.wantAAAA != "" && aaaa(resp) != tc.wantAAAA {
					t.Errorf("AAAA = %q want %q", aaaa(resp), tc.wantAAAA)
				}
				if tc.wantSnoop != "" {
					if got := fx.e.snoop.lookup(d.id, netip.MustParseAddr(tc.wantSnoop)); got != normalize(tc.qname) {
						t.Errorf("snoop(%s, %s) = %q want %q", d.id, tc.wantSnoop, got, normalize(tc.qname))
					}
				}
				fx.e.flows.mu.Lock()
				n := len(fx.e.flows.recs)
				if n != before+1 {
					fx.e.flows.mu.Unlock()
					t.Fatalf("flow records = %d want %d", n, before+1)
				}
				rec := fx.e.flows.recs[n-1]
				fx.e.flows.mu.Unlock()
				if rec.DeviceID != d.id || rec.Flow.Protocol != tc.proto || rec.Flow.SrcIP != "::1" || rec.Flow.DstIP != "::1" || rec.Flow.DstPort != 53 || rec.Flow.Domain != normalize(tc.qname) {
					t.Errorf("flow = %+v (device=%s), want proto=%s src=::1 dst=::1 port=53 domain=%s", rec.Flow, rec.DeviceID, tc.proto, normalize(tc.qname))
				}
				if rec.Decision.Action != tc.wantAction || rec.Decision.RuleID != tc.wantRule {
					t.Errorf("decision = %+v want %s/%s", rec.Decision, tc.wantAction, tc.wantRule)
				}
			})
		}
	})

	t.Run("zero block response", func(t *testing.T) {
		fx := newFixture(t)
		fx.dnsMod = func(d *policy.DNSPolicy) {
			d.BlockResponse = "zero"
		}
		fx.setPeer("d1", 1)
		_ = fx.e.syncPeers(context.Background())
		r := fx.e.reg
		r.mu.Lock()
		d := r.devices["d1"]
		d.offset, d.ip4, d.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
		r.reindexLocked()
		r.mu.Unlock()

		upstream := startDNS6(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
		}))
		edgeUDP6 := startDNS6(t, newResolver(fx.e, upstream))

		m := new(dns.Msg)
		m.SetQuestion("ads.doubleclick.net.", dns.TypeAAAA)
		resp, _, err := new(dns.Client).Exchange(m, edgeUDP6)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("zero AAAA response: rcode=%s answer=%v", dns.RcodeToString[resp.Rcode], resp.Answer)
		}
		rr, ok := resp.Answer[0].(*dns.AAAA)
		if !ok || !rr.AAAA.Equal(net.IPv6zero) {
			t.Fatalf("zero AAAA = %v, want ::", resp.Answer[0])
		}
		fx.e.flows.mu.Lock()
		n := len(fx.e.flows.recs)
		if n != 1 {
			fx.e.flows.mu.Unlock()
			t.Fatalf("block flow count = %d want 1", n)
		}
		rec := fx.e.flows.recs[0]
		fx.e.flows.mu.Unlock()
		if rec.Flow.Protocol != "udp" || rec.Flow.DstIP != "::1" || rec.Decision.Action != policy.ActionBlock || rec.Decision.RuleID != "dns:ads" {
			t.Errorf("zero block flow = %+v %+v", rec.Flow, rec.Decision)
		}
	})

	t.Run("internal dns aaaa", func(t *testing.T) {
		fx := newFixture(t)
		fx.e.ipv6 = true
		forwarded := startDNS6(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
				AAAA: net.ParseIP("fd00:9::9"),
			})
			_ = w.WriteMsg(m)
		}))
		upstream := startDNS6(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
		}))
		fx.dnsMod = func(d *policy.DNSPolicy) {
			d.Zone = "corp.internal"
			d.Records = []policy.DNSRecord{
				{Name: "nas.corp.internal", Type: "AAAA", Value: "fd00:1::5"},
				{Name: "wiki.corp.internal", Type: "CNAME", Value: "nas.corp.internal"},
			}
			d.Forwarders = []policy.DNSForwarder{{Zone: "ad.example", Servers: []string{forwarded}}}
		}
		fx.setPeer("d1", 1)
		fx.setPeer("d2", 1)
		fx.cp.mu.Lock()
		for i := range fx.cp.peers.Devices {
			fx.cp.peers.Devices[i].DNSName = fx.cp.peers.Devices[i].DeviceID + ".alice"
		}
		fx.cp.mu.Unlock()
		_ = fx.e.syncPeers(context.Background())
		r := fx.e.reg
		r.mu.Lock()
		d1, d2 := r.devices["d1"], r.devices["d2"]
		d1.offset, d1.ip4, d1.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
		d2.offset, d2.ip4, d2.ip6 = 3, netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("fd7a:5a5e::3")
		r.reindexLocked()
		r.mu.Unlock()
		edgeUDP6 := startDNS6(t, newResolver(fx.e, upstream))

		tests := []struct {
			name      string
			qname     string
			wantRcode int
			wantCount int
			wantAAAA  string
		}{
			{"device AAAA", "d2.alice.corp.internal.", dns.RcodeSuccess, 1, "fd7a:5a5e::3"},
			{"unknown device AAAA", "nobody.alice.corp.internal.", dns.RcodeNameError, 0, ""},
			{"static AAAA record", "nas.corp.internal.", dns.RcodeSuccess, 1, "fd00:1::5"},
			{"cname to AAAA record", "wiki.corp.internal.", dns.RcodeSuccess, 2, "fd00:1::5"},
			{"forwarded AAAA", "dc1.ad.example.", dns.RcodeSuccess, 1, "fd00:9::9"},
			{"external goes upstream", "public.example.", dns.RcodeRefused, 0, ""},
		}
		c := new(dns.Client)
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				m := new(dns.Msg)
				m.SetQuestion(tc.qname, dns.TypeAAAA)
				resp, _, err := c.Exchange(m, edgeUDP6)
				if err != nil {
					t.Fatalf("%s: %v", tc.qname, err)
				}
				if resp.Rcode != tc.wantRcode || len(resp.Answer) != tc.wantCount {
					t.Fatalf("rcode=%s answers=%v, want rcode=%s count=%d", dns.RcodeToString[resp.Rcode], resp.Answer, dns.RcodeToString[tc.wantRcode], tc.wantCount)
				}
				if tc.wantAAAA != "" && aaaa(resp) != tc.wantAAAA {
					t.Errorf("AAAA = %q want %q", aaaa(resp), tc.wantAAAA)
				}
			})
		}
	})

	t.Run("internal device aaaa omitted when ipv6 disabled", func(t *testing.T) {
		fx := newFixture(t)
		upstream := startDNS6(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
		}))
		fx.dnsMod = func(d *policy.DNSPolicy) { d.Zone = "corp.internal" }
		fx.setPeer("d1", 1)
		fx.setPeer("d2", 1)
		fx.cp.mu.Lock()
		for i := range fx.cp.peers.Devices {
			fx.cp.peers.Devices[i].DNSName = fx.cp.peers.Devices[i].DeviceID + ".alice"
		}
		fx.cp.mu.Unlock()
		_ = fx.e.syncPeers(context.Background())
		r := fx.e.reg
		r.mu.Lock()
		d1, d2 := r.devices["d1"], r.devices["d2"]
		d1.offset, d1.ip4, d1.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
		d2.offset, d2.ip4, d2.ip6 = 3, netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("fd7a:5a5e::3")
		r.reindexLocked()
		r.mu.Unlock()
		edgeUDP6 := startDNS6(t, newResolver(fx.e, upstream))

		m := new(dns.Msg)
		m.SetQuestion("d2.alice.corp.internal.", dns.TypeAAAA)
		resp, _, err := new(dns.Client).Exchange(m, edgeUDP6)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
			t.Fatalf("device AAAA with ipv6=false: rcode=%s answer=%v", dns.RcodeToString[resp.Rcode], resp.Answer)
		}
	})
}
