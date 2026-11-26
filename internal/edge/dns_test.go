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
			if got := fx.e.snoop.lookup(d.ip4, netip.MustParseAddr("192.0.2.7")); got != normalize(tc.name) {
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
