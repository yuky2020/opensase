package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func baseSnapshot() *Snapshot {
	return &Snapshot{
		SchemaVersion: 1,
		Version:       7,
		TenantID:      "t1",
		UserID:        "u1",
		DeviceID:      "d1",
		IssuedAt:      time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
		Firewall:      FirewallPolicy{DefaultAction: ActionAllow},
	}
}

func mustCompile(t testing.TB, s *Snapshot) *Compiled {
	t.Helper()
	c, err := Compile(s)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func TestCompileValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(s *Snapshot)
		field  string // expected ValidationError.Field prefix; "" = valid
	}{
		{"valid", func(s *Snapshot) {}, ""},
		{"schema 0", func(s *Snapshot) { s.SchemaVersion = 0 }, "schemaVersion"},
		{"schema 2", func(s *Snapshot) { s.SchemaVersion = 2 }, "schemaVersion"},
		{"empty default", func(s *Snapshot) { s.Firewall.DefaultAction = "" }, "firewall.defaultAction"},
		{"bad default", func(s *Snapshot) { s.Firewall.DefaultAction = "deny" }, "firewall.defaultAction"},
		{"rule no id", func(s *Snapshot) { s.Firewall.Rules = []Rule{{Source: SourceTenant, Action: ActionBlock}} }, "firewall.rules[0].id"},
		{"rule bad action", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: "drop"}}
		}, "firewall.rules[0].action"},
		{"rule bad source", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: "admin", Action: ActionBlock}}
		}, "firewall.rules[0].source"},
		{"bad cidr", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{CIDRs: []string{"10.0.0.0/33"}}}}
		}, "firewall.rules[0].match.cidrs[0]"},
		{"cidr garbage", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{CIDRs: []string{"example.com"}}}}
		}, "firewall.rules[0].match.cidrs[0]"},
		{"cidr zone", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{CIDRs: []string{"fe80::1%eth0"}}}}
		}, "firewall.rules[0].match.cidrs[0]"},
		{"bad port range", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{Ports: []PortRange{{From: 100, To: 50}}}}}
		}, "firewall.rules[0].match.ports[0]"},
		{"bad protocol", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{Protocols: []string{"sctp"}}}}
		}, "firewall.rules[0].match.protocols[0]"},
		{"bad network", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{Networks: []NetworkType{"5g"}}}}
		}, "firewall.rules[0].match.networks[0]"},
		{"empty app", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{Apps: []string{""}}}}
		}, "firewall.rules[0].match.apps[0]"},
		{"bad domain", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceTenant, Action: ActionBlock, Match: Match{Domains: []string{"a..b"}}}}
		}, "firewall.rules[0].match.domains[0]"},
		{"bad app action", func(s *Snapshot) { s.Firewall.Apps = map[string]AppPolicy{"com.x": {WiFi: "nope"}} }, "firewall.apps[com.x]"},
		{"empty app key", func(s *Snapshot) { s.Firewall.Apps = map[string]AppPolicy{"": {WiFi: ActionAllow}} }, "firewall.apps[]"},
		{"bad block response", func(s *Snapshot) { s.DNS.BlockResponse = "refused" }, "dns.blockResponse"},
		{"bad allow domain", func(s *Snapshot) { s.DNS.AllowDomains = []string{"*"} }, "dns.allowDomains[0]"},
		{"bad block domain", func(s *Snapshot) { s.DNS.BlockDomains = []string{"ok.com", "bad domain"} }, "dns.blockDomains[1]"},
		{"blocklist no id", func(s *Snapshot) { s.DNS.Blocklists = []Blocklist{{Domains: []string{"a.com"}}} }, "dns.blocklists[0].id"},
		{"blocklist bad domain", func(s *Snapshot) {
			s.DNS.Blocklists = []Blocklist{{ID: "ads", Domains: []string{"a.com", "-x.com"}}}
		}, "dns.blocklists[0].domains[1]"},
		{"valid full", func(s *Snapshot) {
			s.Firewall.Rules = []Rule{{ID: "r", Source: SourceUser, Action: ActionAsk, Match: Match{
				Apps: []string{"com.a"}, Networks: []NetworkType{NetworkWiFi}, Protocols: []string{"TCP", "udp", "icmp", "icmpv6"},
				CIDRs: []string{"10.0.0.0/8", "2001:db8::/32", "192.0.2.1", "::ffff:10.0.0.0/104"},
				Ports: []PortRange{{From: 443}, {From: 1000, To: 2000}}, Domains: []string{"Example.COM.", "*.x.org"},
			}}}
			s.DNS = DNSPolicy{BlockResponse: "zero", AllowDomains: []string{"a.com"}, Blocklists: []Blocklist{{ID: "ads", Domains: []string{"*.ads.net"}}}}
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := baseSnapshot()
			tt.mutate(s)
			_, err := Compile(s)
			if tt.field == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want ValidationError for %s, got %v", tt.field, err)
			}
			if ve.Field != tt.field {
				t.Fatalf("field = %q, want %q (%v)", ve.Field, tt.field, err)
			}
		})
	}
	if _, err := Compile(nil); err == nil {
		t.Fatal("Compile(nil) succeeded")
	}
}

func TestNormalizePattern(t *testing.T) {
	for _, tc := range domainPatternCases {
		name, wc, err := normalizePattern(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("normalizePattern(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && (name != tc.wantName || wc != tc.wantWildcard) {
			t.Errorf("normalizePattern(%q) = %q,%v want %q,%v", tc.in, name, wc, tc.wantName, tc.wantWildcard)
		}
	}
}

// precedenceSnapshot exercises every layer.
func precedenceSnapshot() *Snapshot {
	s := baseSnapshot()
	s.Firewall = FirewallPolicy{
		DefaultAction:  ActionAsk,
		AllowUserRules: true,
		Rules: []Rule{
			// Deliberately unsorted: priorities decide, ties keep snapshot order.
			{ID: "u-allow-all-games", Source: SourceUser, Priority: 5, Action: ActionAllow, Match: Match{Apps: []string{"com.game"}}},
			{ID: "t-block-smb", Source: SourceTenant, Priority: 20, Action: ActionBlock, Log: true, Match: Match{Protocols: []string{"tcp"}, Ports: []PortRange{{From: 445}, {From: 137, To: 139}}}},
			{ID: "t-allow-corp", Source: SourceTenant, Priority: 10, Action: ActionAllow, Match: Match{CIDRs: []string{"10.10.0.0/16", "2001:db8:10::/48"}}},
			{ID: "t-block-bad", Source: SourceTenant, Priority: 30, Action: ActionBlock, Match: Match{Domains: []string{"*.evil.com", "exact.bad.org"}}},
			{ID: "t-tie-first", Source: SourceTenant, Priority: 40, Action: ActionBlock, Match: Match{Ports: []PortRange{{From: 9999}}}},
			{ID: "t-tie-second", Source: SourceTenant, Priority: 40, Action: ActionAllow, Match: Match{Ports: []PortRange{{From: 9999}}}},
			{ID: "t-block-cell-video", Source: SourceTenant, Priority: 50, Action: ActionBlock, Match: Match{Apps: []string{"com.video"}, Networks: []NetworkType{NetworkCellular}}},
			{ID: "t-block-icmp", Source: SourceTenant, Priority: 60, Action: ActionBlock, Match: Match{Protocols: []string{"icmp"}, CIDRs: []string{"203.0.113.0/24", "2001:db8:dead::/48"}}},
			{ID: "t-block-icmpv6", Source: SourceTenant, Priority: 65, Action: ActionBlock, Match: Match{Protocols: []string{"icmpv6"}, CIDRs: []string{"198.51.100.0/24", "2001:db8:cafe::/48"}}},
			{ID: "u-block-social", Source: SourceUser, Priority: 1, Action: ActionBlock, Match: Match{Domains: []string{"*.social.example"}}},
			{ID: "u-block-dns-udp", Source: SourceUser, Priority: 2, Action: ActionBlock, Match: Match{Protocols: []string{"udp"}, Ports: []PortRange{{From: 53}}, CIDRs: []string{"8.8.8.8"}}},
		},
		Apps: map[string]AppPolicy{
			"com.mail":  {WiFi: ActionAllow, Cellular: ActionAllow},
			"com.video": {WiFi: ActionAllow, Cellular: ActionAllow},
			"com.chat":  {WiFi: ActionAllow, Cellular: ActionBlock},
			"com.maps":  {WiFi: ActionAllow, Cellular: ActionAllow, Roaming: ActionBlock},
			"com.ask":   {WiFi: ActionAsk},
		},
		TenantApps: []string{"com.mail", "com.video", "com.chat", "com.maps", "com.ask"},
	}
	return s
}

func TestEvaluatePrecedence(t *testing.T) {
	type want struct {
		action Action
		rule   string
		layer  string
		log    bool
	}
	tcp := func(app string, net NetworkType, ip string, port uint16, domain string) Flow {
		return Flow{App: app, Network: net, Protocol: "tcp", DstIP: ip, DstPort: port, Domain: domain}
	}
	tests := []struct {
		name string
		mod  func(s *Snapshot)
		flow Flow
		edge bool
		want want
	}{
		{"default ask", nil, tcp("com.unknown", NetworkWiFi, "1.1.1.1", 443, ""), false, want{ActionAsk, "", LayerDefault, false}},
		{"tenant cidr v4", nil, tcp("com.game", NetworkWiFi, "10.10.3.4", 445, ""), false, want{ActionAllow, "t-allow-corp", LayerTenant, false}},
		{"tenant cidr v6", nil, tcp("", "", "2001:db8:10:ffff::1", 445, ""), false, want{ActionAllow, "t-allow-corp", LayerTenant, false}},
		{"tenant cidr v4-mapped flow", nil, tcp("", "", "::ffff:10.10.0.1", 80, ""), false, want{ActionAllow, "t-allow-corp", LayerTenant, false}},
		{"v6 outside prefix", nil, tcp("", "", "2001:db8:11::1", 80, ""), false, want{ActionAsk, "", LayerDefault, false}},
		{"tenant port exact, log", nil, tcp("com.game", NetworkWiFi, "1.2.3.4", 445, ""), false, want{ActionBlock, "t-block-smb", LayerTenant, true}},
		{"tenant port range low", nil, tcp("", NetworkWiFi, "1.2.3.4", 137, ""), false, want{ActionBlock, "t-block-smb", LayerTenant, true}},
		{"tenant port range high", nil, tcp("", NetworkWiFi, "1.2.3.4", 139, ""), false, want{ActionBlock, "t-block-smb", LayerTenant, true}},
		{"port range outside", nil, tcp("", NetworkWiFi, "1.2.3.4", 140, ""), false, want{ActionAsk, "", LayerDefault, false}},
		{"port rule wrong proto", nil, Flow{Protocol: "udp", DstIP: "1.2.3.4", DstPort: 445}, false, want{ActionAsk, "", LayerDefault, false}},
		{"protocol case-insensitive", nil, Flow{Protocol: "TCP", DstIP: "1.2.3.4", DstPort: 445}, false, want{ActionBlock, "t-block-smb", LayerTenant, true}},
		{"tenant beats user (user prio lower)", nil, tcp("com.game", NetworkWiFi, "1.2.3.4", 445, "x.social.example"), false, want{ActionBlock, "t-block-smb", LayerTenant, true}},
		{"domain wildcard sub", nil, tcp("", "", "1.2.3.4", 443, "a.b.evil.com"), false, want{ActionBlock, "t-block-bad", LayerTenant, false}},
		{"domain wildcard apex", nil, tcp("", "", "1.2.3.4", 443, "evil.com"), false, want{ActionBlock, "t-block-bad", LayerTenant, false}},
		{"domain wildcard not suffix-substring", nil, tcp("", "", "1.2.3.4", 443, "notevil.com"), false, want{ActionAsk, "", LayerDefault, false}},
		{"domain exact", nil, tcp("", "", "1.2.3.4", 443, "exact.bad.org"), false, want{ActionBlock, "t-block-bad", LayerTenant, false}},
		{"domain exact no sub", nil, tcp("", "", "1.2.3.4", 443, "x.exact.bad.org"), false, want{ActionAsk, "", LayerDefault, false}},
		{"domain mixed case + dot", nil, tcp("", "", "1.2.3.4", 443, "WWW.Evil.Com."), false, want{ActionBlock, "t-block-bad", LayerTenant, false}},
		{"domain rule never matches empty domain", nil, tcp("", "", "1.2.3.4", 443, ""), false, want{ActionAsk, "", LayerDefault, false}},
		{"tie keeps snapshot order", nil, tcp("", "", "1.2.3.4", 9999, ""), false, want{ActionBlock, "t-tie-first", LayerTenant, false}},
		{"tenant app+network", nil, tcp("com.video", NetworkCellular, "1.2.3.4", 443, ""), false, want{ActionBlock, "t-block-cell-video", LayerTenant, false}},
		{"tenant app+network other net -> app layer", nil, tcp("com.video", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionAllow, "app:com.video", LayerApp, false}},
		{"rule networks exact, roaming not cellular", nil, tcp("com.video", NetworkRoaming, "1.2.3.4", 443, ""), false, want{ActionAllow, "app:com.video", LayerApp, false}},
		{"icmp v4", nil, Flow{Protocol: "icmp", DstIP: "203.0.113.9"}, false, want{ActionBlock, "t-block-icmp", LayerTenant, false}},
		{"icmp rule matches icmpv6", nil, Flow{Protocol: "icmpv6", DstIP: "2001:db8:dead::1"}, false, want{ActionBlock, "t-block-icmp", LayerTenant, false}},
		{"icmpv6 rule matches icmpv6", nil, Flow{Protocol: "icmpv6", DstIP: "2001:db8:cafe::1"}, false, want{ActionBlock, "t-block-icmpv6", LayerTenant, false}},
		{"icmpv6 rule case-insensitive", nil, Flow{Protocol: "ICMPv6", DstIP: "2001:db8:cafe::1"}, false, want{ActionBlock, "t-block-icmpv6", LayerTenant, false}},
		{"icmpv6 rule rejects icmp v4", nil, Flow{Protocol: "icmp", DstIP: "198.51.100.1"}, false, want{ActionAsk, "", LayerDefault, false}},
		{"icmpv6 rule rejects icmp on v6 cidr", nil, Flow{Protocol: "icmp", DstIP: "2001:db8:cafe::1"}, false, want{ActionAsk, "", LayerDefault, false}},
		{"icmpv6 rule matches in edge mode", nil, Flow{Protocol: "icmpv6", DstIP: "2001:db8:cafe::1"}, true, want{ActionBlock, "t-block-icmpv6", LayerTenant, false}},
		{"invalid dst ip skips cidr rules", nil, Flow{Protocol: "icmp", DstIP: "not-an-ip"}, false, want{ActionAsk, "", LayerDefault, false}},
		{"user domain", nil, tcp("com.mail", NetworkWiFi, "1.2.3.4", 443, "feed.social.example"), false, want{ActionBlock, "u-block-social", LayerUser, false}},
		{"user prio order", nil, tcp("com.game", NetworkWiFi, "1.2.3.4", 443, "social.example"), false, want{ActionBlock, "u-block-social", LayerUser, false}},
		{"user app", nil, tcp("com.game", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionAllow, "u-allow-all-games", LayerUser, false}},
		{"user AND fields", nil, Flow{Protocol: "udp", DstIP: "8.8.8.8", DstPort: 53}, false, want{ActionBlock, "u-block-dns-udp", LayerUser, false}},
		{"user AND fields mismatch ip", nil, Flow{Protocol: "udp", DstIP: "8.8.4.4", DstPort: 53}, false, want{ActionAsk, "", LayerDefault, false}},
		{"user rules disabled", func(s *Snapshot) { s.Firewall.AllowUserRules = false }, tcp("com.game", NetworkWiFi, "1.2.3.4", 443, "a.social.example"), false, want{ActionAsk, "", LayerDefault, false}},
		{"app wifi allow", nil, tcp("com.chat", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionAllow, "app:com.chat", LayerApp, false}},
		{"app cellular block", nil, tcp("com.chat", NetworkCellular, "1.2.3.4", 443, ""), false, want{ActionBlock, "app:com.chat", LayerApp, false}},
		{"app roaming falls back to cellular", nil, tcp("com.chat", NetworkRoaming, "1.2.3.4", 443, ""), false, want{ActionBlock, "app:com.chat", LayerApp, false}},
		{"app roaming explicit", nil, tcp("com.maps", NetworkRoaming, "1.2.3.4", 443, ""), false, want{ActionBlock, "app:com.maps", LayerApp, false}},
		{"app ask", nil, tcp("com.ask", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionAsk, "app:com.ask", LayerApp, false}},
		{"app unset network -> default", nil, tcp("com.ask", NetworkCellular, "1.2.3.4", 443, ""), false, want{ActionAsk, "", LayerDefault, false}},
		{"app ethernet -> default", nil, tcp("com.mail", NetworkEthernet, "1.2.3.4", 443, ""), false, want{ActionAsk, "", LayerDefault, false}},
		{"lockdown blocks unlisted app", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("com.unknown", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionBlock, "lockdown", LayerLockdown, false}},
		{"lockdown blocks app without verdict on this net", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("com.ask", NetworkCellular, "1.2.3.4", 443, ""), false, want{ActionBlock, "lockdown", LayerLockdown, false}},
		{"lockdown keeps allowed app", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("com.mail", NetworkCellular, "1.2.3.4", 443, ""), false, want{ActionAllow, "app:com.mail", LayerApp, false}},
		{"lockdown unknown uid", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionBlock, "lockdown", LayerLockdown, false}},
		// D1: under Lockdown the user layer can only block.
		{"lockdown skips user allow rule", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("com.game", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionBlock, "lockdown", LayerLockdown, false}},
		{"lockdown keeps user block rule", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("com.mail", NetworkWiFi, "1.2.3.4", 443, "a.social.example"), false, want{ActionBlock, "u-block-social", LayerUser, false}},
		{"lockdown skips user ask rule", func(s *Snapshot) {
			s.Firewall.Lockdown = true
			s.Firewall.Rules = append(s.Firewall.Rules, Rule{ID: "u-ask-7777", Source: SourceUser, Priority: 0, Action: ActionAsk, Match: Match{Ports: []PortRange{{From: 7777}}}})
		}, tcp("com.unknown", NetworkWiFi, "1.2.3.4", 7777, ""), false, want{ActionBlock, "lockdown", LayerLockdown, false}},
		{"user ask rule without lockdown", func(s *Snapshot) {
			s.Firewall.Rules = append(s.Firewall.Rules, Rule{ID: "u-ask-7777", Source: SourceUser, Priority: 0, Action: ActionAsk, Match: Match{Ports: []PortRange{{From: 7777}}}})
		}, tcp("com.unknown", NetworkWiFi, "1.2.3.4", 7777, ""), false, want{ActionAsk, "u-ask-7777", LayerUser, false}},
		{"lockdown user block keeps priority order", func(s *Snapshot) { s.Firewall.Lockdown = true }, Flow{Protocol: "udp", DstIP: "8.8.8.8", DstPort: 53}, false, want{ActionBlock, "u-block-dns-udp", LayerUser, false}},
		{"lockdown ignores user per-app allow", func(s *Snapshot) {
			s.Firewall.Lockdown = true
			s.Firewall.TenantApps = []string{"com.video", "com.chat", "com.maps", "com.ask"} // com.mail is a user entry
		}, tcp("com.mail", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionBlock, "lockdown", LayerLockdown, false}},
		{"lockdown keeps user per-app block", func(s *Snapshot) {
			s.Firewall.Lockdown = true
			s.Firewall.TenantApps = nil // every entry is a user entry
		}, tcp("com.chat", NetworkCellular, "1.2.3.4", 443, ""), false, want{ActionBlock, "app:com.chat", LayerApp, false}},
		{"user per-app allow counts without lockdown", func(s *Snapshot) { s.Firewall.TenantApps = nil }, tcp("com.mail", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionAllow, "app:com.mail", LayerApp, false}},
		{"lockdown does not override tenant allow", func(s *Snapshot) { s.Firewall.Lockdown = true }, tcp("com.unknown", NetworkWiFi, "10.10.0.1", 443, ""), false, want{ActionAllow, "t-allow-corp", LayerTenant, false}},
		// Edge mode.
		{"edge skips app rules", nil, tcp("com.game", NetworkWiFi, "1.2.3.4", 443, ""), true, want{ActionAsk, "", LayerDefault, false}},
		{"edge skips app+network rules", nil, tcp("com.video", NetworkCellular, "1.2.3.4", 443, ""), true, want{ActionAsk, "", LayerDefault, false}},
		{"edge skips app layer", nil, Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443}, true, want{ActionAsk, "", LayerDefault, false}},
		{"edge skips lockdown", func(s *Snapshot) { s.Firewall.Lockdown = true }, Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443}, true, want{ActionAsk, "", LayerDefault, false}},
		{"edge keeps tenant cidr", nil, Flow{Protocol: "tcp", DstIP: "10.10.0.1", DstPort: 443}, true, want{ActionAllow, "t-allow-corp", LayerTenant, false}},
		{"edge keeps tenant domain", nil, Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443, Domain: "evil.com"}, true, want{ActionBlock, "t-block-bad", LayerTenant, false}},
		{"edge keeps user domain", nil, Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443, Domain: "social.example"}, true, want{ActionBlock, "u-block-social", LayerUser, false}},
		{"default block", func(s *Snapshot) { s.Firewall.DefaultAction = ActionBlock }, tcp("com.x", NetworkWiFi, "1.2.3.4", 443, ""), false, want{ActionBlock, "", LayerDefault, false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := precedenceSnapshot()
			if tt.mod != nil {
				tt.mod(s)
			}
			c := mustCompile(t, s)
			got := c.Evaluate(tt.flow, tt.edge)
			w := Decision{Action: tt.want.action, RuleID: tt.want.rule, Layer: tt.want.layer, Log: tt.want.log}
			if got != w {
				t.Fatalf("Evaluate = %+v, want %+v", got, w)
			}
		})
	}
}

func TestEvaluateDNS(t *testing.T) {
	s := baseSnapshot()
	s.DNS = DNSPolicy{
		BlockResponse: "zero",
		AllowDomains:  []string{"good.ads.net", "*.safe.tracker.io"},
		BlockDomains:  []string{"custom.example", "*.myblock.org"},
		Blocklists: []Blocklist{
			{ID: "ads", Category: "ads", Domains: []string{"*.ads.net", "doubleclick.net"}},
			{ID: "trackers", Category: "trackers", Domains: []string{"*.tracker.io", "doubleclick.net", "custom.example"}},
		},
	}
	c := mustCompile(t, s)
	tests := []struct {
		name    string
		blocked bool
		list    string
	}{
		{"x.ads.net", true, "ads"},
		{"ads.net", true, "ads"},
		{"ADS.NET.", true, "ads"},
		{"good.ads.net", false, ""},
		{"sub.good.ads.net", true, "ads"}, // allow is exact only
		{"doubleclick.net", true, "ads"},  // first list wins
		{"www.doubleclick.net", false, ""},
		{"a.tracker.io", true, "trackers"},
		{"safe.tracker.io", false, ""},
		{"x.safe.tracker.io", false, ""},
		{"custom.example", true, "custom"}, // BlockDomains before blocklists
		{"myblock.org", true, "custom"},
		{"a.b.myblock.org", true, "custom"},
		{"example.org", false, ""},
		{"", false, ""},
		{".", false, ""},
		{strings.Repeat("a", 300), false, ""},
	}
	for _, tt := range tests {
		blocked, list := c.EvaluateDNS(tt.name)
		if blocked != tt.blocked || list != tt.list {
			t.Errorf("EvaluateDNS(%q) = %v,%q want %v,%q", tt.name, blocked, list, tt.blocked, tt.list)
		}
	}
	if got := c.BlockResponse(); got != "zero" {
		t.Errorf("BlockResponse = %q", got)
	}
	if got := mustCompile(t, baseSnapshot()).BlockResponse(); got != "nxdomain" {
		t.Errorf("default BlockResponse = %q", got)
	}
	if c.Version() != 7 {
		t.Errorf("Version = %d", c.Version())
	}
}

func TestCompileDoesNotAliasInput(t *testing.T) {
	s := precedenceSnapshot()
	c := mustCompile(t, s)
	s.Firewall.Rules[0].Match.Apps[0] = "com.other"
	s.Firewall.Rules[2].Match.CIDRs[0] = "0.0.0.0/0"
	got := c.Evaluate(Flow{App: "com.game", Network: NetworkWiFi, Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443}, false)
	if got.RuleID != "u-allow-all-games" {
		t.Fatalf("compiled policy changed with input: %+v", got)
	}
}

func TestEvaluateNoAllocs(t *testing.T) {
	c := mustCompile(t, precedenceSnapshot())
	flows := []Flow{
		{App: "com.chat", Network: NetworkRoaming, Protocol: "tcp", DstIP: "2001:db8:99::1", DstPort: 443, Domain: "Deep.Sub.Social.Example."},
		{App: "com.x", Network: NetworkWiFi, Protocol: "udp", DstIP: "8.8.8.8", DstPort: 53},
		{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443, Domain: "www.evil.com"},
	}
	for _, f := range flows {
		if n := testing.AllocsPerRun(100, func() { _ = c.Evaluate(f, false) }); n != 0 {
			t.Errorf("Evaluate(%+v) allocs = %v", f, n)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = c.EvaluateDNS("A.B.Example.COM.") }); n != 0 {
		t.Errorf("EvaluateDNS allocs = %v", n)
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"k1": pub, "k2": otherPub}

	s := precedenceSnapshot()
	env, err := Sign(s, "k1", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Roundtrip through the JSON wire form.
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var env2 Envelope
	if err := json.Unmarshal(wire, &env2); err != nil {
		t.Fatal(err)
	}
	got, err := Verify(&env2, keys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Version != s.Version || got.DeviceID != s.DeviceID || len(got.Firewall.Rules) != len(s.Firewall.Rules) {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if _, err := Compile(got); err != nil {
		t.Fatalf("Compile verified snapshot: %v", err)
	}

	resign := func(mod func(*Snapshot)) *Envelope {
		s := precedenceSnapshot()
		mod(s)
		b, _ := json.Marshal(s)
		return &Envelope{KeyID: "k1", Algorithm: AlgEd25519, Payload: b, Signature: ed25519.Sign(priv, b)}
	}
	tamperedPayload := *env
	tamperedPayload.Payload = []byte(strings.Replace(string(env.Payload), `"defaultAction":"ask"`, `"defaultAction":"allow"`, 1))
	if string(tamperedPayload.Payload) == string(env.Payload) {
		t.Fatal("tamper did not change payload")
	}
	tamperedSig := *env
	tamperedSig.Signature = append([]byte(nil), env.Signature...)
	tamperedSig.Signature[0] ^= 1

	tests := []struct {
		name string
		env  *Envelope
		want error
	}{
		{"tampered payload", &tamperedPayload, ErrBadSignature},
		{"tampered signature", &tamperedSig, ErrBadSignature},
		{"short signature", &Envelope{KeyID: "k1", Algorithm: AlgEd25519, Payload: env.Payload, Signature: env.Signature[:10]}, ErrBadSignature},
		{"wrong key", &Envelope{KeyID: "k2", Algorithm: AlgEd25519, Payload: env.Payload, Signature: env.Signature}, ErrBadSignature},
		{"unknown key", &Envelope{KeyID: "k9", Algorithm: AlgEd25519, Payload: env.Payload, Signature: env.Signature}, ErrUnknownKey},
		{"bad alg", &Envelope{KeyID: "k1", Algorithm: "none", Payload: env.Payload, Signature: env.Signature}, ErrBadAlgorithm},
		{"schema 2", resign(func(s *Snapshot) { s.SchemaVersion = 2 }), ErrSchemaVersion},
		{"no tenant", resign(func(s *Snapshot) { s.TenantID = "" }), ErrMissingSubject},
		{"no device", resign(func(s *Snapshot) { s.DeviceID = "" }), ErrMissingSubject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify(tt.env, keys); !errors.Is(err, tt.want) {
				t.Fatalf("Verify err = %v, want %v", err, tt.want)
			}
		})
	}
	if _, err := Verify(nil, keys); err == nil {
		t.Error("Verify(nil) succeeded")
	}
	if _, err := Verify(env, map[string]ed25519.PublicKey{"k1": pub[:5]}); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("short public key: %v", err)
	}
	// Signed garbage must fail at decode, not panic.
	garbage := []byte("{not json")
	if _, err := Verify(&Envelope{KeyID: "k1", Algorithm: AlgEd25519, Payload: garbage, Signature: ed25519.Sign(priv, garbage)}, keys); err == nil {
		t.Error("garbage payload accepted")
	}
	// Expired snapshots verify fine; Stale reports them.
	exp := resign(func(s *Snapshot) { s.ExpiresAt = time.Unix(0, 0) })
	if _, err := Verify(exp, keys); err != nil {
		t.Errorf("expired snapshot rejected: %v", err)
	}

	// Sign refuses invalid input.
	bad := precedenceSnapshot()
	bad.Firewall.DefaultAction = "x"
	if _, err := Sign(bad, "k1", priv); err == nil {
		t.Error("Sign accepted invalid snapshot")
	}
	noDev := precedenceSnapshot()
	noDev.DeviceID = ""
	if _, err := Sign(noDev, "k1", priv); !errors.Is(err, ErrMissingSubject) {
		t.Errorf("Sign without device: %v", err)
	}
	if _, err := Sign(s, "", priv); err == nil {
		t.Error("Sign accepted empty key ID")
	}
	if _, err := Sign(s, "k1", priv[:3]); err == nil {
		t.Error("Sign accepted short key")
	}
}

func TestStale(t *testing.T) {
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		expires time.Time
		now     time.Time
		want    bool
	}{
		{exp, exp.Add(-time.Second), false},
		{exp, exp, true},
		{exp, exp.Add(time.Hour), true},
		{time.Time{}, exp, true},
	}
	for _, tt := range tests {
		s := &Snapshot{ExpiresAt: tt.expires}
		if got := s.Stale(tt.now); got != tt.want {
			t.Errorf("Stale(exp=%v, now=%v) = %v", tt.expires, tt.now, got)
		}
	}
}

func FuzzCompileEvaluate(f *testing.F) {
	seed, _ := json.Marshal(precedenceSnapshot())
	f.Add(seed, "com.game", "wifi", "tcp", "10.10.0.1", uint16(443), "a.evil.com", false)
	f.Add([]byte(`{"schemaVersion":1,"firewall":{"defaultAction":"block","rules":[{"id":"x","source":"tenant","action":"allow","match":{"cidrs":["::/0"],"domains":["*.a"]}}]}}`),
		"", "roaming", "UDP", "::1", uint16(0), "A.", true)
	f.Fuzz(func(t *testing.T, snap []byte, app, network, proto, ip string, port uint16, domain string, edge bool) {
		var s Snapshot
		if json.Unmarshal(snap, &s) != nil {
			return
		}
		c, err := Compile(&s)
		if err != nil {
			return
		}
		d := c.Evaluate(Flow{App: app, Network: NetworkType(network), Protocol: proto, DstIP: ip, DstPort: port, Domain: domain}, edge)
		if !validAction(d.Action) {
			t.Fatalf("invalid action %q", d.Action)
		}
		if edge && (d.Layer == LayerApp || d.Layer == LayerLockdown) {
			t.Fatalf("edge mode returned layer %q", d.Layer)
		}
		_, _ = c.EvaluateDNS(domain)
	})
}

// benchSnapshot has 500 rules (mixed CIDR/port/domain/app) and 10k blocklist domains.
func benchSnapshot() *Snapshot {
	s := baseSnapshot()
	s.Firewall.AllowUserRules = true
	for i := range 500 {
		r := Rule{ID: fmt.Sprintf("r%d", i), Priority: i, Action: ActionBlock, Source: SourceTenant}
		if i%2 == 1 {
			r.Source = SourceUser
		}
		switch i % 4 {
		case 0:
			r.Match.CIDRs = []string{fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), fmt.Sprintf("2001:db8:%x::/48", i)}
		case 1:
			r.Match.Protocols = []string{"tcp"}
			r.Match.Ports = []PortRange{{From: uint16(20000 + i), To: uint16(20000 + i + 2)}}
		case 2:
			r.Match.Domains = []string{fmt.Sprintf("*.d%d.example", i), fmt.Sprintf("host%d.example.net", i)}
		case 3:
			r.Match.Apps = []string{fmt.Sprintf("com.app%d", i)}
			r.Match.Networks = []NetworkType{NetworkCellular}
		}
		s.Firewall.Rules = append(s.Firewall.Rules, r)
	}
	s.Firewall.Apps = map[string]AppPolicy{"com.bench": {WiFi: ActionAllow}}
	doms := make([]string, 10000)
	for i := range doms {
		if i%10 == 0 {
			doms[i] = fmt.Sprintf("*.track%d.example", i)
		} else {
			doms[i] = fmt.Sprintf("ads%d.example.com", i)
		}
	}
	s.DNS.Blocklists = []Blocklist{{ID: "ads", Domains: doms}}
	return s
}

// BenchmarkEvaluate measures the worst case: a flow that misses all 500 rules (with a domain,
// so the domain index is consulted) and falls through to the app layer.
func BenchmarkEvaluate(b *testing.B) {
	c := mustCompile(b, benchSnapshot())
	f := Flow{App: "com.bench", Network: NetworkWiFi, Protocol: "tcp", DstIP: "2001:db8:ffff::1", DstPort: 443, Domain: "www.cdn.d999.example"}
	if d := c.Evaluate(f, false); d.Layer != LayerApp {
		b.Fatalf("unexpected decision %+v", d)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Evaluate(f, false)
	}
}

func BenchmarkEvaluateDNS(b *testing.B) {
	c := mustCompile(b, benchSnapshot())
	if blocked, _ := c.EvaluateDNS("x.y.track990.example"); !blocked {
		b.Fatal("expected block")
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = c.EvaluateDNS("www.not-listed.example.org")
	}
}

// TestConcurrentEvaluateSwap evaluates from several goroutines while the compiled policy is
// swapped through an atomic.Pointer, as the client and the Edge do. Run with -race.
func TestConcurrentEvaluateSwap(t *testing.T) {
	var cur atomic.Pointer[Compiled]
	cur.Store(mustCompile(t, precedenceSnapshot()))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 2000 {
				c := cur.Load()
				d := c.Evaluate(Flow{App: "com.chat", Network: NetworkCellular, Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443, Domain: "a.evil.com"}, false)
				if d.RuleID != "t-block-bad" {
					t.Errorf("unexpected decision %+v", d)
					return
				}
				_, _ = c.EvaluateDNS("x.example")
			}
		})
	}
	for i := range 50 {
		s := precedenceSnapshot()
		s.Version = uint64(100 + i)
		cur.Store(mustCompile(t, s))
	}
	wg.Wait()
}

// TestLockdownTenantApps covers the per-app half of D1: under Lockdown a per-app allow or
// ask counts only if the package is in TenantApps; a user per-app block still applies.
func TestLockdownTenantApps(t *testing.T) {
	tests := []struct {
		name     string
		lockdown bool
		tenant   bool // com.x listed in TenantApps
		action   Action
		want     Action
		layer    string
	}{
		{"tenant allow under lockdown", true, true, ActionAllow, ActionAllow, LayerApp},
		{"tenant ask under lockdown", true, true, ActionAsk, ActionAsk, LayerApp},
		{"user allow under lockdown", true, false, ActionAllow, ActionBlock, LayerLockdown},
		{"user ask under lockdown", true, false, ActionAsk, ActionBlock, LayerLockdown},
		{"user block under lockdown", true, false, ActionBlock, ActionBlock, LayerApp},
		{"user allow without lockdown", false, false, ActionAllow, ActionAllow, LayerApp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := precedenceSnapshot()
			s.Firewall.Lockdown = tt.lockdown
			s.Firewall.Apps = map[string]AppPolicy{"com.x": {WiFi: tt.action}}
			s.Firewall.TenantApps = nil
			if tt.tenant {
				s.Firewall.TenantApps = []string{"com.x", "com.not-in-apps"} // unknown names are harmless
			}
			c, err := Compile(s)
			if err != nil {
				t.Fatal(err)
			}
			d := c.Evaluate(Flow{App: "com.x", Network: NetworkWiFi, Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 443}, false)
			if d.Action != tt.want || d.Layer != tt.layer {
				t.Fatalf("got %s/%s, want %s/%s", d.Action, d.Layer, tt.want, tt.layer)
			}
		})
	}
	s := precedenceSnapshot()
	s.Firewall.TenantApps = []string{""}
	if _, err := Compile(s); err == nil {
		t.Fatal("empty TenantApps entry accepted")
	}
}

// BenchmarkEvaluateLockdownUserApp measures a Lockdown flow whose user per-app allow is
// ignored: the rule layers miss, the app entry is found and discarded, lockdown blocks.
func BenchmarkEvaluateLockdownUserApp(b *testing.B) {
	s := benchSnapshot()
	s.Firewall.Lockdown = true
	s.Firewall.TenantApps = nil
	c := mustCompile(b, s)
	f := Flow{App: "com.bench", Network: NetworkWiFi, Protocol: "tcp", DstIP: "2001:db8:ffff::1", DstPort: 443, Domain: "www.cdn.d999.example"}
	if d := c.Evaluate(f, false); d.Layer != LayerLockdown {
		b.Fatalf("unexpected decision %+v", d)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Evaluate(f, false)
	}
}
