package edge

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/policy"
)

// TestSafeSearch checks ADR-0025 at the Edge: covered names resolve to the provider's safe
// hostname, HTTPS records carry no hints, and flows to covered hostnames must go to an address
// the Edge returned for a safe hostname.
func TestSafeSearch(t *testing.T) {
	fx := newFixture(t)
	fx.safe = true
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
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
		ip := net.IPv4(192, 0, 2, 7) // the normal address of everything
		if q.Name == "forcesafesearch.google.com." {
			ip = net.IPv4(216, 239, 38, 120)
		}
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: ip})
		}
		_ = w.WriteMsg(m)
	}))
	edgeDNS := startDNS(t, newResolver(fx.e, upstream))
	ask := func(name string, qt uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, qt)
		resp, err := dns.Exchange(m, edgeDNS)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := ask("WWW.Google.IT.", dns.TypeA)
	if len(resp.Answer) != 2 {
		t.Fatalf("answer %v", resp.Answer)
	}
	if cn, ok := resp.Answer[0].(*dns.CNAME); !ok || cn.Target != "forcesafesearch.google.com." {
		t.Fatalf("no CNAME to the safe name: %v", resp.Answer)
	}
	if a, ok := resp.Answer[1].(*dns.A); !ok || !a.A.Equal(net.IPv4(216, 239, 38, 120)) {
		t.Fatalf("not the safe address: %v", resp.Answer)
	}
	if resp := ask("www.google.com.", dns.TypeHTTPS); len(resp.Answer) != 1 {
		t.Fatalf("HTTPS record answer %v", resp.Answer)
	}
	if resp := ask("example.com.", dns.TypeA); len(resp.Answer) != 1 {
		t.Fatalf("uncovered name changed: %v", resp.Answer)
	}

	c := d.compiled.Load()
	f := &Filter{e: fx.e}
	flow := policy.Flow{Protocol: "tcp", DstPort: 443, Domain: "www.google.it"}
	if _, block := f.hostDecision(c, flow, netip.MustParseAddr("216.239.38.120")); block {
		t.Fatal("flow to the safe address blocked")
	}
	if dec, block := f.hostDecision(c, flow, netip.MustParseAddr("142.250.180.4")); !block || dec.RuleID != "safesearch:bypass" {
		t.Fatalf("hard-coded address not blocked: %+v %v", dec, block)
	}
	// Without SafeSearch nothing changes.
	off, _ := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "acme", DeviceID: "d1", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow}})
	if _, block := f.hostDecision(off, flow, netip.MustParseAddr("142.250.180.4")); block {
		t.Fatal("blocked without SafeSearch")
	}
}
