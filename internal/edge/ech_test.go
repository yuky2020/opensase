package edge

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/policy"
)

func TestStripECH(t *testing.T) {
	alpnParam := &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}
	echParam := &dns.SVCBECHConfig{ECH: []byte{0x00, 0x01, 0x02, 0x03}}

	tests := []struct {
		name        string
		msg         *dns.Msg
		wantRemoved int
		check       func(t *testing.T, m *dns.Msg)
	}{
		{
			name: "HTTPS record with alpn+ech -> only alpn left",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.HTTPS{
						SVCB: dns.SVCB{
							Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
							Priority: 1,
							Target:   ".",
							Value:    []dns.SVCBKeyValue{alpnParam, echParam},
						},
					},
				},
			},
			wantRemoved: 1,
			check: func(t *testing.T, m *dns.Msg) {
				h := m.Answer[0].(*dns.HTTPS)
				if len(h.Value) != 1 {
					t.Fatalf("expected 1 param, got %d", len(h.Value))
				}
				if h.Value[0].Key() != dns.SVCB_ALPN {
					t.Fatalf("expected ALPN param, got key %d", h.Value[0].Key())
				}
			},
		},
		{
			name: "SVCB record",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300},
						Priority: 1,
						Target:   ".",
						Value:    []dns.SVCBKeyValue{echParam},
					},
				},
			},
			wantRemoved: 1,
			check: func(t *testing.T, m *dns.Msg) {
				s := m.Answer[0].(*dns.SVCB)
				if len(s.Value) != 0 {
					t.Fatalf("expected 0 params, got %d", len(s.Value))
				}
			},
		},
		{
			name: "record without ech unchanged",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.HTTPS{
						SVCB: dns.SVCB{
							Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
							Priority: 1,
							Target:   ".",
							Value:    []dns.SVCBKeyValue{alpnParam},
						},
					},
				},
			},
			wantRemoved: 0,
			check: func(t *testing.T, m *dns.Msg) {
				h := m.Answer[0].(*dns.HTTPS)
				if len(h.Value) != 1 || h.Value[0].Key() != dns.SVCB_ALPN {
					t.Fatalf("record changed: %+v", h.Value)
				}
			},
		},
		{
			name: "A record untouched",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.IPv4(192, 0, 2, 1),
					},
				},
			},
			wantRemoved: 0,
			check: func(t *testing.T, m *dns.Msg) {
				a, ok := m.Answer[0].(*dns.A)
				if !ok || !a.A.Equal(net.IPv4(192, 0, 2, 1)) {
					t.Fatalf("A record altered: %+v", m.Answer[0])
				}
			},
		},
		{
			name: "ech in Extra",
			msg: &dns.Msg{
				Extra: []dns.RR{
					&dns.HTTPS{
						SVCB: dns.SVCB{
							Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
							Priority: 1,
							Target:   ".",
							Value:    []dns.SVCBKeyValue{echParam},
						},
					},
				},
			},
			wantRemoved: 1,
			check: func(t *testing.T, m *dns.Msg) {
				h := m.Extra[0].(*dns.HTTPS)
				if len(h.Value) != 0 {
					t.Fatalf("expected 0 params in Extra, got %d", len(h.Value))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripECH(tc.msg)
			if got != tc.wantRemoved {
				t.Errorf("stripECH() = %d, want %d", got, tc.wantRemoved)
			}
			if tc.check != nil {
				tc.check(t, tc.msg)
			}
		})
	}
}

func TestResolverBlockECH(t *testing.T) {
	for _, tc := range []struct {
		name     string
		blockECH bool
		wantECH  bool
	}{
		{"block_ech_true", true, false},
		{"block_ech_false", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			fx.web = policy.WebPolicy{BlockECH: tc.blockECH}
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
				m.Answer = append(m.Answer, &dns.HTTPS{
					SVCB: dns.SVCB{
						Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
						Priority: 1,
						Target:   ".",
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{Alpn: []string{"h2"}},
							&dns.SVCBECHConfig{ECH: []byte("ech-config-bytes")},
						},
					},
				})
				_ = w.WriteMsg(m)
			}))
			edgeDNS := startDNS(t, newResolver(fx.e, upstream))

			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeHTTPS)
			resp, _, err := c.Exchange(m, edgeDNS)
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode %s", dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
			}
			https, ok := resp.Answer[0].(*dns.HTTPS)
			if !ok {
				t.Fatalf("expected *dns.HTTPS, got %T", resp.Answer[0])
			}
			hasECH := false
			for _, p := range https.Value {
				if p.Key() == dns.SVCB_ECHCONFIG {
					hasECH = true
					break
				}
			}
			if hasECH != tc.wantECH {
				t.Errorf("hasECH = %v, want %v", hasECH, tc.wantECH)
			}
		})
	}
}
