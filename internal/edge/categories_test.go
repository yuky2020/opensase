package edge

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/policy"
)

func testCategories(t *testing.T) *categories.DB {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"blacklists/gambling/domains": "casino.example\nlucky.example\n",
		"blacklists/gambling/urls":    "example.com/poker\n",
		"blacklists/adult/domains":    "adult.example\n",
	} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	db, err := categories.ParseUT1(&b)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// TestWebCategoriesEdge checks ADR-0022 at the Edge: only the categories the devices' tenants
// block are fetched, refreshed with an ETag, and enforced on DNS answers and on the hostname
// of flows; DNS AllowDomains override them; nothing is enforced before the list arrives.
func TestWebCategoriesEdge(t *testing.T) {
	fx := newFixture(t)
	fx.cats = []string{"gambling"}
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	c := d.compiled.Load()

	if _, ok := fx.e.category(c, "casino.example"); ok {
		t.Fatal("enforced before any list arrived")
	}
	if err := fx.e.syncCategories(context.Background(), time.Now()); err == nil {
		t.Fatal("sync without a list on the Control Plane succeeded")
	}
	fx.cp.mu.Lock()
	fx.cp.categories = testCategories(t)
	fx.cp.mu.Unlock()
	now := time.Now()
	if err := fx.e.syncCategories(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{"casino.example": true, "www.lucky.example": true, "adult.example": false, "example.com": false} {
		if _, got := fx.e.category(c, host); got != want {
			t.Errorf("category(%s) = %v", host, got)
		}
	}
	// Up to date: no fetch; after the refresh period: a conditional fetch (304).
	_ = fx.e.syncCategories(context.Background(), now.Add(time.Minute))
	_ = fx.e.syncCategories(context.Background(), now.Add(2*time.Hour))
	fx.cp.mu.Lock()
	gets := append([]string(nil), fx.cp.catGets...)
	fx.cp.mu.Unlock()
	if len(gets) != 2 || gets[0] != "gambling" {
		t.Fatalf("fetches %v", gets)
	}
	if fx.e.cats.Load() == nil {
		t.Fatal("list dropped after a 304")
	}

	// The hostname of a flow (TLS SNI or HTTP Host, ADR-0017).
	flow := policy.Flow{Protocol: "tcp", DstIP: "198.51.100.7", DstPort: 443, Domain: "www.casino.example"}
	f := &Filter{e: fx.e}
	if dec, block := f.hostDecision(c, flow, netip.MustParseAddr("198.51.100.7")); !block || dec.RuleID != "cat:gambling" || dec.Layer != LayerWeb {
		t.Fatalf("hostDecision %+v %v", dec, block)
	}

	// DNS, through the Edge resolver.
	r := fx.e.reg
	r.mu.Lock()
	d.offset, d.ip4, d.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd7a:5a5e::2")
	r.reindexLocked()
	r.mu.Unlock()
	upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Name == "promo.example." {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "casino.example."})
		}
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 7)})
		_ = w.WriteMsg(m)
	}))
	edgeDNS := startDNS(t, newResolver(fx.e, upstream))
	for name, want := range map[string]int{"casino.example.": dns.RcodeNameError, "promo.example.": dns.RcodeNameError, "example.com.": dns.RcodeSuccess} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		resp, err := dns.Exchange(m, edgeDNS)
		if err != nil || resp.Rcode != want {
			t.Errorf("%s: %v rcode %d want %d", name, err, resp.Rcode, want)
		}
	}

	// AllowDomains of the tenant win over categories.
	fx.cp.mu.Lock()
	fx.cp.categories = testCategories(t)
	fx.cp.mu.Unlock()
	allow, err := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "acme", DeviceID: "d1", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow},
		DNS: policy.DNSPolicy{AllowDomains: []string{"lucky.example"}}, Categories: []string{"gambling"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fx.e.category(allow, "lucky.example"); ok {
		t.Error("AllowDomains did not override the category")
	}

	// No device asks for categories any more: the list is dropped.
	fx.cats = nil
	fx.setPeer("d1", 2)
	_ = fx.e.syncPeers(context.Background())
	_ = fx.e.syncCategories(context.Background(), now.Add(3*time.Hour))
	if fx.e.cats.Load() != nil {
		t.Error("list kept with no category in any policy")
	}
}
