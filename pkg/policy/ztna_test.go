package policy

import (
	"errors"
	"testing"
)

func ztnaSnapshot() *Snapshot {
	s := baseSnapshot()
	s.Firewall.DefaultAction = ActionBlock
	s.Firewall.Rules = []Rule{
		{ID: "t-block-wiki", Source: SourceTenant, Priority: 1, Action: ActionBlock, Match: Match{Domains: []string{"wiki.acme.internal"}}},
	}
	s.PrivateApps = []PrivateApp{
		{ID: "intranet", Name: "Intranet", Domains: []string{"*.acme.internal"}, Ports: []PortRange{{From: 443}, {From: 8000, To: 8080}}, ConnectorGroup: "dc1"},
		{ID: "db", Name: "DB", Domains: []string{"DB.Acme.Internal."}, Ports: []PortRange{{From: 5432}}, ConnectorGroup: "dc2"},
		{ID: "noports", Name: "No ports", Domains: []string{"closed.example"}, ConnectorGroup: "dc1"},
	}
	return s
}

func TestPrivateAppLookup(t *testing.T) {
	c := mustCompile(t, ztnaSnapshot())
	tests := []struct {
		name     string
		host     string
		port     uint16
		wantName string // PrivateApp(host) ID, "" = none
		wantAcc  string // PrivateAppAccess(host, port) ID, "" = none
	}{
		{"suffix apex", "acme.internal", 443, "intranet", "intranet"},
		{"suffix sub", "portal.acme.internal", 443, "intranet", "intranet"},
		{"suffix deep, mixed case, trailing dot", "A.B.ACME.internal.", 8080, "intranet", "intranet"},
		{"port range low", "portal.acme.internal", 8000, "intranet", "intranet"},
		{"wrong port", "portal.acme.internal", 22, "intranet", ""},
		{"exact beats suffix", "db.acme.internal", 5432, "db", "db"},
		// The exact app lacks 443, but the suffix app covers db.acme.internal:443.
		{"exact without port falls back to suffix", "db.acme.internal", 443, "db", "intranet"},
		{"exact no port anywhere", "db.acme.internal", 22, "db", ""},
		{"not a suffix substring", "notacme.internal", 443, "", ""},
		{"exact only, no subdomain", "x.db.acme.internal", 5432, "intranet", ""},
		{"empty ports never grant", "closed.example", 443, "noports", ""},
		{"unknown", "example.com", 443, "", ""},
		{"empty name", "", 443, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := c.PrivateApp(tt.host)
			if got := id(a, ok); got != tt.wantName {
				t.Errorf("PrivateApp = %q, want %q", got, tt.wantName)
			}
			a, ok = c.PrivateAppAccess(tt.host, tt.port)
			if got := id(a, ok); got != tt.wantAcc {
				t.Errorf("PrivateAppAccess = %q, want %q", got, tt.wantAcc)
			}
		})
	}
	if a, _ := c.PrivateApp("db.acme.internal"); a.ConnectorGroup != "dc2" || a.Name != "DB" || len(a.Ports) != 1 || a.Ports[0].To != 5432 {
		t.Fatalf("returned app %+v (ports must be normalized)", a)
	}
}

func id(a PrivateApp, ok bool) string {
	if !ok {
		return ""
	}
	return a.ID
}

func TestEvaluateZTNA(t *testing.T) {
	tcp := func(domain string, port uint16) Flow {
		return Flow{App: "com.browser", Network: NetworkWiFi, Protocol: "tcp", DstIP: "100.96.0.5", DstPort: port, Domain: domain}
	}
	tests := []struct {
		name   string
		mod    func(*Snapshot)
		flow   Flow
		edge   bool
		action Action
		rule   string
		layer  string
	}{
		{"entitled app", nil, tcp("portal.acme.internal", 443), false, ActionAllow, "ztna:intranet", LayerZTNA},
		{"entitled app, edge mode", nil, tcp("portal.acme.internal", 443), true, ActionAllow, "ztna:intranet", LayerZTNA},
		{"exact app", nil, tcp("db.acme.internal", 5432), false, ActionAllow, "ztna:db", LayerZTNA},
		{"wrong port falls through to default", nil, tcp("portal.acme.internal", 22), false, ActionBlock, "", LayerDefault},
		{"no domain", nil, tcp("", 443), false, ActionBlock, "", LayerDefault},
		{"udp is not ztna", nil, Flow{Protocol: "udp", DstIP: "100.96.0.5", DstPort: 443, Domain: "portal.acme.internal"}, false, ActionBlock, "", LayerDefault},
		{"protocol case-insensitive", nil, Flow{Protocol: "TCP", DstIP: "100.96.0.5", DstPort: 443, Domain: "portal.acme.internal"}, true, ActionAllow, "ztna:intranet", LayerZTNA},
		{"empty ports no access", nil, tcp("closed.example", 443), false, ActionBlock, "", LayerDefault},
		{"tenant block beats ztna", nil, tcp("wiki.acme.internal", 443), false, ActionBlock, "t-block-wiki", LayerTenant},
		{"tenant block beats ztna, edge mode", nil, tcp("wiki.acme.internal", 443), true, ActionBlock, "t-block-wiki", LayerTenant},
		{"user block beats ztna", func(s *Snapshot) {
			s.Firewall.AllowUserRules = true
			s.Firewall.Rules = append(s.Firewall.Rules, Rule{ID: "u-no-portal", Source: SourceUser, Action: ActionBlock, Match: Match{Domains: []string{"portal.acme.internal"}}})
		}, tcp("portal.acme.internal", 443), false, ActionBlock, "u-no-portal", LayerUser},
		{"app layer beats ztna", func(s *Snapshot) {
			s.Firewall.Apps = map[string]AppPolicy{"com.browser": {WiFi: ActionBlock}}
		}, tcp("portal.acme.internal", 443), false, ActionBlock, "app:com.browser", LayerApp},
		{"lockdown beats ztna for a non-tenant app", func(s *Snapshot) {
			s.Firewall.Lockdown = true
		}, tcp("portal.acme.internal", 443), false, ActionBlock, LayerLockdown, LayerLockdown},
		{"lockdown, tenant-mandated app allows at app layer", func(s *Snapshot) {
			s.Firewall.Lockdown = true
			s.Firewall.Apps = map[string]AppPolicy{"com.browser": {WiFi: ActionAllow}}
			s.Firewall.TenantApps = []string{"com.browser"}
		}, tcp("portal.acme.internal", 443), false, ActionAllow, "app:com.browser", LayerApp},
		{"lockdown is device-only: edge mode reaches ztna", func(s *Snapshot) {
			s.Firewall.Lockdown = true
		}, tcp("portal.acme.internal", 443), true, ActionAllow, "ztna:intranet", LayerZTNA},
		{"default allow, no app", func(s *Snapshot) {
			s.Firewall.DefaultAction = ActionAllow
			s.PrivateApps = nil
		}, tcp("portal.acme.internal", 443), false, ActionAllow, "", LayerDefault},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ztnaSnapshot()
			if tt.mod != nil {
				tt.mod(s)
			}
			d := mustCompile(t, s).Evaluate(tt.flow, tt.edge)
			if d.Action != tt.action || d.RuleID != tt.rule || d.Layer != tt.layer {
				t.Fatalf("got %+v, want %s/%q/%s", d, tt.action, tt.rule, tt.layer)
			}
		})
	}
}

func TestCompilePrivateAppsValidation(t *testing.T) {
	tests := []struct {
		name  string
		mod   func(*Snapshot)
		field string
	}{
		{"empty id", func(s *Snapshot) { s.PrivateApps[0].ID = "" }, "privateApps[0].id"},
		{"duplicate id", func(s *Snapshot) { s.PrivateApps[1].ID = "intranet" }, "privateApps[1].id"},
		{"no domains", func(s *Snapshot) { s.PrivateApps[1].Domains = nil }, "privateApps[1].domains"},
		{"bad domain", func(s *Snapshot) { s.PrivateApps[0].Domains = []string{"bad domain"} }, "privateApps[0].domains[0]"},
		{"bare wildcard", func(s *Snapshot) { s.PrivateApps[2].Domains = []string{"*."} }, "privateApps[2].domains[0]"},
		{"bad port range", func(s *Snapshot) { s.PrivateApps[0].Ports = []PortRange{{From: 9, To: 1}} }, "privateApps[0].ports[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ztnaSnapshot()
			tt.mod(s)
			_, err := Compile(s)
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Field != tt.field {
				t.Fatalf("err %v, want field %s", err, tt.field)
			}
		})
	}
}

func TestPrivateAppsNotAliased(t *testing.T) {
	s := ztnaSnapshot()
	c := mustCompile(t, s)
	s.PrivateApps[0].Ports[0].From = 1
	s.PrivateApps[0].Domains[0] = "x.example"
	if _, ok := c.PrivateAppAccess("portal.acme.internal", 443); !ok {
		t.Fatal("compiled apps changed with input")
	}
	if a, _ := c.PrivateApp("portal.acme.internal"); a.Domains[0] != "*.acme.internal" {
		t.Fatalf("domains aliased: %v", a.Domains)
	}
}

func TestEvaluateZTNANoAllocs(t *testing.T) {
	c := mustCompile(t, ztnaSnapshot())
	flows := []Flow{
		{Protocol: "tcp", DstIP: "100.96.0.5", DstPort: 443, Domain: "Portal.Acme.Internal."},
		{Protocol: "tcp", DstIP: "100.96.0.5", DstPort: 22, Domain: "portal.acme.internal"},
		{Protocol: "tcp", DstIP: "100.96.0.5", DstPort: 443, Domain: "wiki.acme.internal"},
	}
	for _, f := range flows {
		if n := testing.AllocsPerRun(100, func() { _ = c.Evaluate(f, true) }); n != 0 {
			t.Errorf("Evaluate(%+v) allocs = %v", f, n)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = c.PrivateAppAccess("a.b.acme.internal", 8080) }); n != 0 {
		t.Errorf("PrivateAppAccess allocs = %v", n)
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = c.PrivateApp("db.acme.internal") }); n != 0 {
		t.Errorf("PrivateApp allocs = %v", n)
	}
}

// BenchmarkEvaluateZTNA measures a flow that misses the rule layers and is allowed by the
// ZTNA layer through a suffix pattern.
func BenchmarkEvaluateZTNA(b *testing.B) {
	s := benchSnapshot()
	s.Firewall.Apps = nil
	s.Firewall.TenantApps = nil
	s.PrivateApps = ztnaSnapshot().PrivateApps
	c := mustCompile(b, s)
	f := Flow{Protocol: "tcp", DstIP: "100.96.0.5", DstPort: 8080, Domain: "a.b.acme.internal"}
	if d := c.Evaluate(f, true); d.Layer != LayerZTNA {
		b.Fatalf("unexpected decision %+v", d)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Evaluate(f, true)
	}
}
