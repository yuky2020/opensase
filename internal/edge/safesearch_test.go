package edge

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

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

func TestSafeSearchAAAA(t *testing.T) {
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

	safeTarget := dns.Fqdn(safeTargets[0])
	safeV6 := netip.MustParseAddr("2001:db8:1::120")
	mappedV6 := netip.MustParseAddr("::ffff:198.51.100.120")
	unmappedV4 := netip.MustParseAddr("198.51.100.120")
	otherV6 := netip.MustParseAddr("2001:db8:2::4")

	upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Qtype == dns.TypeAAAA {
			if q.Name == safeTarget {
				m.Answer = append(m.Answer,
					&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.IP(safeV6.AsSlice())},
					&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.IP(mappedV6.AsSlice())},
				)
			} else {
				m.Answer = append(m.Answer,
					&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8:9::7")},
				)
			}
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

	resp := ask("WWW.Google.IT.", dns.TypeAAAA)
	if len(resp.Answer) != 3 {
		t.Fatalf("answer %v", resp.Answer)
	}
	if cn, ok := resp.Answer[0].(*dns.CNAME); !ok || cn.Target != safeTarget {
		t.Fatalf("no CNAME to safe target: %v", resp.Answer)
	}
	if a6, ok := resp.Answer[1].(*dns.AAAA); !ok || !a6.AAAA.Equal(net.IP(safeV6.AsSlice())) {
		t.Fatalf("not the safe IPv6 address: %v", resp.Answer[1])
	}
	if a6, ok := resp.Answer[2].(*dns.AAAA); !ok || !a6.AAAA.Equal(net.IP(mappedV6.AsSlice())) {
		t.Fatalf("not the v4-mapped AAAA address: %v", resp.Answer[2])
	}
	if resp := ask("example.com.", dns.TypeAAAA); len(resp.Answer) != 1 {
		t.Fatalf("uncovered AAAA changed: %v", resp.Answer)
	}

	// Both the IPv6 address and the unmapped IPv4-in-IPv6 address are recorded in safeIPs
	// and snooped under the device ID (independent of the IPv4 query transport).
	now := time.Now()
	if !fx.e.safe.has(safeV6, now) || !fx.e.safe.has(unmappedV4, now) {
		t.Fatal("safe AAAA addresses not recorded")
	}
	if got := fx.e.snoop.lookup(d.id, safeV6); got != "www.google.it" {
		t.Errorf("snoop(d.id, safeV6) = %q, want www.google.it", got)
	}
	if got := fx.e.snoop.lookup(d.id, unmappedV4); got != "www.google.it" {
		t.Errorf("snoop(d.id, unmappedV4) = %q, want www.google.it", got)
	}

	c := d.compiled.Load()
	off, _ := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "acme", DeviceID: "d1", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow}})
	f := &Filter{e: fx.e}

	tests := []struct {
		name      string
		compiled  *policy.Compiled
		host      string
		dst       netip.Addr
		wantBlock bool
		wantRule  string
	}{
		{"covered host to safe ipv6", c, "www.google.it", safeV6, false, ""},
		{"covered host to unmapped safe addr", c, "www.google.it", unmappedV4, false, ""},
		{"covered host to hardcoded ipv6", c, "www.google.it", otherV6, true, "safesearch:bypass"},
		{"uncovered host to ipv6", c, "example.com", otherV6, false, ""},
		{"safesearch disabled", off, "www.google.it", otherV6, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flow := policy.Flow{Protocol: "tcp", DstPort: 443, Domain: tc.host}
			dec, block := f.hostDecision(tc.compiled, flow, tc.dst)
			if block != tc.wantBlock {
				t.Fatalf("block=%v want %v (dec=%+v)", block, tc.wantBlock, dec)
			}
			if tc.wantBlock && (dec.RuleID != tc.wantRule || dec.Layer != LayerWeb) {
				t.Errorf("decision = %+v, want rule %q layer %q", dec, tc.wantRule, LayerWeb)
			}
		})
	}
}
