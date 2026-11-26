package dnsfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/policy"
)

func compile(t *testing.T, blockResponse string) *policy.Compiled {
	t.Helper()
	s := &policy.Snapshot{
		SchemaVersion: 1,
		Version:       1,
		Firewall:      policy.FirewallPolicy{DefaultAction: policy.ActionAllow},
		DNS: policy.DNSPolicy{
			BlockResponse: blockResponse,
			Blocklists:    []policy.Blocklist{{ID: "ads", Name: "Ads", Category: "ads", Domains: []string{"*.ads.example"}}},
			BlockDomains:  []string{"bad.example"},
			AllowDomains:  []string{"ok.ads.example"},
		},
	}
	c, err := policy.Compile(s)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = 0x1234
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkPacket validates the IP and UDP checksums independently and returns the DNS payload.
func checkPacket(t *testing.T, pkt []byte, wantSrc, wantDst netip.AddrPort) []byte {
	t.Helper()
	var src, dst netip.Addr
	var udp []byte
	switch pkt[0] >> 4 {
	case 4:
		if got := foldChecksum(sum(pkt[:20], 0)); got != 0xffff {
			t.Fatalf("bad IPv4 header checksum: %#x", got)
		}
		if int(binary.BigEndian.Uint16(pkt[2:])) != len(pkt) {
			t.Fatalf("bad total length")
		}
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		udp = pkt[20:]
	case 6:
		if int(binary.BigEndian.Uint16(pkt[4:])) != len(pkt)-40 {
			t.Fatalf("bad payload length")
		}
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		udp = pkt[40:]
	default:
		t.Fatalf("bad IP version %d", pkt[0]>>4)
	}
	acc := sum(src.AsSlice(), 0)
	acc = sum(dst.AsSlice(), acc)
	acc += protoUDP + uint32(len(udp))
	acc = sum(udp, acc)
	if got := foldChecksum(acc); got != 0xffff {
		t.Fatalf("bad UDP checksum: %#x", got)
	}
	gotSrc := netip.AddrPortFrom(src, binary.BigEndian.Uint16(udp[0:]))
	gotDst := netip.AddrPortFrom(dst, binary.BigEndian.Uint16(udp[2:]))
	if gotSrc != wantSrc || gotDst != wantDst {
		t.Fatalf("addresses: got %v->%v, want %v->%v", gotSrc, gotDst, wantSrc, wantDst)
	}
	return udp[8:]
}

func TestHandleQuery(t *testing.T) {
	app4 := netip.MustParseAddrPort("100.64.0.7:40000")
	dns4 := netip.MustParseAddrPort("100.64.0.1:53")
	app6 := netip.MustParseAddrPort("[fd7a:5a5e::7]:40000")
	dns6 := netip.MustParseAddrPort("[fd7a:5a5e::1]:53")

	tests := []struct {
		name        string
		blockResp   string
		qname       string
		qtype       uint16
		src, dst    netip.AddrPort
		wantBlocked bool
		wantList    string
		wantRcode   int
		wantAnswer  string // "" = no answer
	}{
		{"allowed", "nxdomain", "example.com", dns.TypeA, app4, dns4, false, "", 0, ""},
		{"blocklist nxdomain", "nxdomain", "tracker.ads.example", dns.TypeA, app4, dns4, true, "ads", dns.RcodeNameError, ""},
		{"apex of wildcard", "nxdomain", "ADS.example.", dns.TypeA, app4, dns4, true, "ads", dns.RcodeNameError, ""},
		{"allow overrides list", "nxdomain", "ok.ads.example", dns.TypeA, app4, dns4, false, "", 0, ""},
		{"block domain v6 transport", "nxdomain", "bad.example", dns.TypeA, app6, dns6, true, "custom", dns.RcodeNameError, ""},
		{"zero A", "zero", "bad.example", dns.TypeA, app4, dns4, true, "custom", dns.RcodeSuccess, "0.0.0.0"},
		{"zero AAAA", "zero", "x.ads.example", dns.TypeAAAA, app6, dns6, true, "ads", dns.RcodeSuccess, "::"},
		{"zero other type is NODATA", "zero", "bad.example", dns.TypeTXT, app4, dns4, true, "custom", dns.RcodeSuccess, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := New(Config{})
			c := compile(t, tt.blockResp)
			res, err := i.HandleQuery(c, "com.app", tt.src, tt.dst, query(t, tt.qname, tt.qtype))
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if res.Blocked != tt.wantBlocked || res.ListID != tt.wantList {
				t.Fatalf("blocked=%v list=%q, want %v %q", res.Blocked, res.ListID, tt.wantBlocked, tt.wantList)
			}
			if !tt.wantBlocked {
				if res.Response != nil {
					t.Fatal("response for allowed query")
				}
				return
			}
			payload := checkPacket(t, res.Response, tt.dst, tt.src)
			var m dns.Msg
			if err := m.Unpack(payload); err != nil {
				t.Fatalf("unpack response: %v", err)
			}
			if !m.Response || m.Id != 0x1234 || m.Rcode != tt.wantRcode {
				t.Fatalf("response=%v id=%#x rcode=%d", m.Response, m.Id, m.Rcode)
			}
			switch {
			case tt.wantAnswer == "" && len(m.Answer) != 0:
				t.Fatalf("unexpected answers %v", m.Answer)
			case tt.wantAnswer != "":
				if len(m.Answer) != 1 {
					t.Fatalf("answers %v", m.Answer)
				}
				var got net.IP
				switch rr := m.Answer[0].(type) {
				case *dns.A:
					got = rr.A
				case *dns.AAAA:
					got = rr.AAAA
				}
				if got.String() != tt.wantAnswer {
					t.Fatalf("answer %v, want %s", got, tt.wantAnswer)
				}
			}
		})
	}
}

func TestHandleQueryRejects(t *testing.T) {
	i := New(Config{})
	c := compile(t, "nxdomain")
	src := netip.MustParseAddrPort("10.0.0.2:1000")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	if _, err := i.HandleQuery(c, "", src, dst, []byte{1, 2, 3}); err == nil {
		t.Fatal("garbage accepted")
	}
	m := new(dns.Msg)
	m.SetQuestion("a.example.", dns.TypeA)
	m.Response = true
	b, _ := m.Pack()
	if _, err := i.HandleQuery(c, "", src, dst, b); !errors.Is(err, ErrNotQuery) {
		t.Fatalf("response accepted as query: %v", err)
	}
	// nil policy never blocks.
	res, err := i.HandleQuery(nil, "", src, dst, query(t, "bad.example", dns.TypeA))
	if err != nil || res.Blocked {
		t.Fatalf("nil policy: %v %v", res, err)
	}
}

var (
	snoopClient = netip.MustParseAddrPort("100.64.0.7:40000")
	snoopServer = netip.MustParseAddrPort("100.64.0.1:53")
)

// ask runs a forwarded query for qname from snoopClient to snoopServer and returns its ID.
func ask(t *testing.T, i *Interceptor, qname string) uint16 {
	t.Helper()
	b := query(t, qname, dns.TypeA)
	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	if _, err := i.HandleQuery(nil, "", snoopClient, snoopServer, b); err != nil {
		t.Fatal(err)
	}
	return m.Id
}

func response(t *testing.T, id uint16, qname string, rrs ...string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	m.Id = id
	m.Response = true
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSnoopCNAMEAndTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	i := New(Config{Now: func() time.Time { return now }})
	id := ask(t, i, "www.example.com")
	n := i.SnoopResponse(snoopServer, snoopClient, response(t, id, "WWW.Example.com.",
		"www.example.com. 300 IN CNAME edge.cdn.example.",
		"edge.cdn.example. 120 IN A 203.0.113.5",
		"edge.cdn.example. 120 IN AAAA 2001:db8::5",
		"edge.cdn.example. 1 IN A 203.0.113.6", // TTL below floor
	))
	if n != 3 {
		t.Fatalf("learned %d, want 3", n)
	}
	for _, ip := range []string{"203.0.113.5", "2001:db8::5", "::ffff:203.0.113.5"} {
		if got := i.Domain(netip.MustParseAddr(ip)); got != "www.example.com" {
			t.Fatalf("Domain(%s)=%q", ip, got)
		}
	}
	now = now.Add(DefaultMinTTL - time.Second)
	if i.Domain(netip.MustParseAddr("203.0.113.6")) == "" {
		t.Fatal("TTL floor not applied")
	}
	now = now.Add(2 * time.Second)
	if i.Domain(netip.MustParseAddr("203.0.113.6")) != "" {
		t.Fatal("entry did not expire at floor")
	}
	now = now.Add(2 * time.Minute)
	if i.Domain(netip.MustParseAddr("203.0.113.5")) != "" {
		t.Fatal("entry did not expire with TTL")
	}
}

func TestSnoopMatchesOutstandingQuery(t *testing.T) {
	const ans = "a.example. 300 IN A 203.0.113.9"
	otherPort := netip.MustParseAddrPort("100.64.0.7:40001")
	otherServer := netip.MustParseAddrPort("198.51.100.53:53")
	tests := []struct {
		name    string
		qname   string // asked
		rname   string // answered
		idOff   uint16
		server  netip.AddrPort
		client  netip.AddrPort
		rcode   int
		advance time.Duration
		replay  bool // deliver a second matching response after a first valid one
		want    int
	}{
		{name: "match", qname: "a.example", rname: "a.example", server: snoopServer, client: snoopClient, want: 1},
		{name: "case-insensitive qname", qname: "a.example", rname: "A.EXAMPLE", server: snoopServer, client: snoopClient, want: 1},
		{name: "wrong txid", qname: "a.example", rname: "a.example", idOff: 1, server: snoopServer, client: snoopClient},
		{name: "wrong qname", qname: "b.example", rname: "a.example", server: snoopServer, client: snoopClient},
		{name: "wrong client port", qname: "a.example", rname: "a.example", server: snoopServer, client: otherPort},
		{name: "wrong server", qname: "a.example", rname: "a.example", server: otherServer, client: snoopClient},
		{name: "expired query", qname: "a.example", rname: "a.example", server: snoopServer, client: snoopClient, advance: DefaultQueryTimeout},
		{name: "nxdomain", qname: "a.example", rname: "a.example", server: snoopServer, client: snoopClient, rcode: dns.RcodeNameError},
		{name: "replayed response", qname: "a.example", rname: "a.example", server: snoopServer, client: snoopClient, replay: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1_000_000, 0)
			i := New(Config{Now: func() time.Time { return now }})
			id := ask(t, i, tt.qname)
			now = now.Add(tt.advance)
			b := response(t, id+tt.idOff, tt.rname, ans)
			if tt.rcode != 0 {
				var m dns.Msg
				m.Unpack(b)
				m.Rcode = tt.rcode
				b, _ = m.Pack()
			}
			if tt.replay {
				if n := i.SnoopResponse(tt.server, tt.client, b); n != 1 {
					t.Fatalf("first response learned %d", n)
				}
				i.cache = newDomainCache(DefaultMaxEntries)
			}
			if n := i.SnoopResponse(tt.server, tt.client, b); n != tt.want {
				t.Fatalf("learned %d, want %d", n, tt.want)
			}
			if tt.want == 0 && i.Domain(netip.MustParseAddr("203.0.113.9")) != "" {
				t.Fatal("cache poisoned")
			}
		})
	}
	// An unsolicited response (no query at all) is ignored.
	i := New(Config{})
	if i.SnoopResponse(snoopServer, snoopClient, response(t, 42, "a.example", ans)) != 0 {
		t.Fatal("learned from an unsolicited response")
	}
	// The outstanding table is bounded.
	i = New(Config{MaxPending: 3})
	for k := range 10 {
		src := netip.AddrPortFrom(snoopClient.Addr(), uint16(41000+k))
		if _, err := i.HandleQuery(nil, "", src, snoopServer, query(t, fmt.Sprintf("h%d.example", k), dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	if i.PendingLen() != 3 {
		t.Fatalf("pending %d", i.PendingLen())
	}
}

func TestCacheLRUBound(t *testing.T) {
	i := New(Config{MaxEntries: 4})
	for k := range 10 {
		name := fmt.Sprintf("h%d.example", k)
		i.SnoopResponse(snoopServer, snoopClient, response(t, ask(t, i, name), name, fmt.Sprintf("h%d.example. 300 IN A 192.0.2.%d", k, k+1)))
	}
	if i.CacheLen() != 4 {
		t.Fatalf("len=%d", i.CacheLen())
	}
	if i.Domain(netip.MustParseAddr("192.0.2.1")) != "" {
		t.Fatal("oldest not evicted")
	}
	if i.Domain(netip.MustParseAddr("192.0.2.10")) != "h9.example" {
		t.Fatal("newest missing")
	}
}

func TestStats(t *testing.T) {
	i := New(Config{})
	c := compile(t, "nxdomain")
	src := netip.MustParseAddrPort("10.0.0.2:1000")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	for _, q := range []struct{ app, name string }{
		{"a", "ok.example"}, {"a", "bad.example"}, {"b", "x.ads.example"}, {"a", "fine.example"},
	} {
		if _, err := i.HandleQuery(c, q.app, src, dst, query(t, q.name, dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	got := i.Stats()
	want := []AppStats{{App: "a", Queries: 3, Blocked: 1}, {App: "b", Queries: 1, Blocked: 1}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("stats %v, want %v", got, want)
	}
}

func TestTakeDNSTimes(t *testing.T) {
	// Table-driven: matched response yields duration; unmatched responses add nothing.
	t.Run("query and response timing", func(t *testing.T) {
		const ans = "a.example. 300 IN A 203.0.113.9"
		otherPort := netip.MustParseAddrPort("100.64.0.7:40001")
		otherServer := netip.MustParseAddrPort("198.51.100.53:53")
		tests := []struct {
			name     string
			ask      bool
			qname    string
			rname    string
			idOff    uint16
			server   netip.AddrPort
			client   netip.AddrPort
			advance  time.Duration
			replay   bool
			wantTime time.Duration
			wantLen  int
		}{
			{
				name:     "matched response",
				ask:      true,
				qname:    "a.example",
				rname:    "a.example",
				server:   snoopServer,
				client:   snoopClient,
				advance:  25 * time.Millisecond,
				wantTime: 25 * time.Millisecond,
				wantLen:  1,
			},
			{
				name:    "unmatched wrong txid",
				ask:     true,
				qname:   "a.example",
				rname:   "a.example",
				idOff:   1,
				server:  snoopServer,
				client:  snoopClient,
				advance: 25 * time.Millisecond,
				wantLen: 0,
			},
			{
				name:    "unmatched wrong qname",
				ask:     true,
				qname:   "b.example",
				rname:   "a.example",
				server:  snoopServer,
				client:  snoopClient,
				advance: 25 * time.Millisecond,
				wantLen: 0,
			},
			{
				name:    "unmatched wrong client port",
				ask:     true,
				qname:   "a.example",
				rname:   "a.example",
				server:  snoopServer,
				client:  otherPort,
				advance: 25 * time.Millisecond,
				wantLen: 0,
			},
			{
				name:    "unmatched wrong server",
				ask:     true,
				qname:   "a.example",
				rname:   "a.example",
				server:  otherServer,
				client:  snoopClient,
				advance: 25 * time.Millisecond,
				wantLen: 0,
			},
			{
				name:    "unmatched expired query",
				ask:     true,
				qname:   "a.example",
				rname:   "a.example",
				server:  snoopServer,
				client:  snoopClient,
				advance: DefaultQueryTimeout + time.Second,
				wantLen: 0,
			},
			{
				name:    "unmatched unsolicited",
				ask:     false,
				rname:   "a.example",
				server:  snoopServer,
				client:  snoopClient,
				wantLen: 0,
			},
			{
				name:     "unmatched replayed response adds nothing extra",
				ask:      true,
				qname:    "a.example",
				rname:    "a.example",
				server:   snoopServer,
				client:   snoopClient,
				advance:  15 * time.Millisecond,
				replay:   true,
				wantTime: 15 * time.Millisecond,
				wantLen:  1,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				now := time.Unix(1_000_000, 0)
				i := New(Config{Now: func() time.Time { return now }})
				var id uint16
				if tt.ask {
					id = ask(t, i, tt.qname)
				} else {
					id = 42
				}
				now = now.Add(tt.advance)
				respPkt := response(t, id+tt.idOff, tt.rname, ans)
				_ = i.SnoopResponse(tt.server, tt.client, respPkt)
				if tt.replay {
					now = now.Add(10 * time.Millisecond)
					_ = i.SnoopResponse(tt.server, tt.client, respPkt)
				}
				got := i.TakeDNSTimes()
				if len(got) != tt.wantLen {
					t.Fatalf("got %d durations, want %d", len(got), tt.wantLen)
				}
				if tt.wantLen > 0 && got[0] != tt.wantTime {
					t.Fatalf("got duration %v, want %v", got[0], tt.wantTime)
				}
			})
		}
	})

	// Buffer bounded at 256, drops the oldest.
	t.Run("buffer bounded at 256", func(t *testing.T) {
		now := time.Unix(1_000_000, 0)
		i := New(Config{Now: func() time.Time { return now }})
		const total = 300
		for k := 0; k < total; k++ {
			name := fmt.Sprintf("h%d.example", k)
			src := netip.AddrPortFrom(snoopClient.Addr(), uint16(30000+k%10000))
			qPkt := query(t, name, dns.TypeA)
			var m dns.Msg
			_ = m.Unpack(qPkt)
			m.Id = uint16(k + 1)
			qPkt, _ = m.Pack()
			if _, err := i.HandleQuery(nil, "", src, snoopServer, qPkt); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Duration(k+1) * time.Millisecond
			now = now.Add(elapsed)
			rPkt := response(t, uint16(k+1), name, fmt.Sprintf("%s. 300 IN A 192.0.2.1", name))
			i.SnoopResponse(snoopServer, src, rPkt)
		}
		got := i.TakeDNSTimes()
		if len(got) != 256 {
			t.Fatalf("buffer len = %d, want 256", len(got))
		}
		if got[0] != 45*time.Millisecond {
			t.Fatalf("oldest kept duration = %v, want 45ms", got[0])
		}
		if got[len(got)-1] != 300*time.Millisecond {
			t.Fatalf("newest kept duration = %v, want 300ms", got[len(got)-1])
		}
	})

	// Take clears buffer.
	t.Run("take clears buffer", func(t *testing.T) {
		now := time.Unix(1_000_000, 0)
		i := New(Config{Now: func() time.Time { return now }})
		id := ask(t, i, "clear.example")
		now = now.Add(10 * time.Millisecond)
		i.SnoopResponse(snoopServer, snoopClient, response(t, id, "clear.example", "clear.example. 300 IN A 192.0.2.1"))
		first := i.TakeDNSTimes()
		if len(first) != 1 {
			t.Fatalf("first take len = %d, want 1", len(first))
		}
		second := i.TakeDNSTimes()
		if len(second) != 0 {
			t.Fatalf("second take len = %d, want 0", len(second))
		}
	})
}

func BenchmarkDomainLookup(b *testing.B) {
	i := New(Config{})
	q := query(&testing.T{}, "www.example.com", dns.TypeA)
	var m dns.Msg
	m.Unpack(q)
	i.HandleQuery(nil, "", snoopClient, snoopServer, q)
	m.Response = true
	rr, _ := dns.NewRR("www.example.com. 300 IN A 203.0.113.5")
	m.Answer = []dns.RR{rr}
	pkt, _ := m.Pack()
	i.SnoopResponse(snoopServer, snoopClient, pkt)
	ip := netip.MustParseAddr("203.0.113.5")
	for b.Loop() {
		_ = i.Domain(ip)
	}
}
