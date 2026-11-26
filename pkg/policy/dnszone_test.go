package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestInternalDNS(t *testing.T) {
	s := baseSnapshot()
	s.DNS.Zone = "Corp.Internal."
	s.DNS.Records = []DNSRecord{
		{Name: "nas.corp.internal", Type: "A", Value: "10.0.0.5"},
		{Name: "nas.corp.internal", Type: "aaaa", Value: "fd00::5", TTL: 60},
		{Name: "wiki.corp.internal", Type: "CNAME", Value: "nas.corp.internal."},
		{Name: "corp.internal", Type: "TXT", Value: "v=spf1 -all"},
	}
	s.DNS.Forwarders = []DNSForwarder{
		{Zone: "example.local", Servers: []string{"10.0.0.53"}},
		{Zone: "eu.example.local", Servers: []string{"10.1.0.53:5353"}},
	}
	s.DNS.LogQueries = true
	c, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Zone() != "corp.internal" || !c.LogQueries() {
		t.Fatalf("zone %q log %v", c.Zone(), c.LogQueries())
	}
	if r := c.Records("nas.corp.internal"); len(r) != 2 || r[0].Addr != netip.MustParseAddr("10.0.0.5") || r[1].TTL != 60 || r[0].TTL != 300 {
		t.Fatalf("records %+v", r)
	}
	if r := c.Records("wiki.corp.internal"); len(r) != 1 || r[0].Value != "nas.corp.internal" {
		t.Fatalf("cname %+v", r)
	}
	if f, ok := c.Forwarder("db.eu.example.local"); !ok || f.Servers[0].String() != "10.1.0.53:5353" {
		t.Fatalf("most specific forwarder: %+v %v", f, ok)
	}
	if f, ok := c.Forwarder("example.local"); !ok || f.Servers[0].Port() != 53 {
		t.Fatalf("zone apex forwarder: %+v %v", f, ok)
	}
	if _, ok := c.Forwarder("notexample.local"); ok {
		t.Fatal("suffix without a dot boundary matched")
	}

	bad := []struct {
		name string
		mod  func(*DNSPolicy)
		want string
	}{
		{"zone", func(d *DNSPolicy) { d.Zone = "nodot" }, "dns.zone"},
		{"type", func(d *DNSPolicy) { d.Records = []DNSRecord{{Name: "a.b", Type: "MX", Value: "x"}} }, "type"},
		{"a value", func(d *DNSPolicy) { d.Records = []DNSRecord{{Name: "a.b", Type: "A", Value: "fd00::1"}} }, "IPv4"},
		{"cname clash", func(d *DNSPolicy) {
			d.Records = []DNSRecord{{Name: "a.b", Type: "A", Value: "10.0.0.1"}, {Name: "a.b", Type: "CNAME", Value: "c.d"}}
		}, "CNAME"},
		{"server", func(d *DNSPolicy) { d.Forwarders = []DNSForwarder{{Zone: "x.y", Servers: []string{"dns.example"}}} }, "server"},
		{"no server", func(d *DNSPolicy) { d.Forwarders = []DNSForwarder{{Zone: "x.y"}} }, "servers"},
	}
	for _, tc := range bad {
		s := baseSnapshot()
		tc.mod(&s.DNS)
		if _, err := Compile(s); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
