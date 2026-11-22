package policy

import (
	"strings"
	"testing"
)

func webSnapshot(w WebPolicy) *Snapshot {
	return &Snapshot{SchemaVersion: CurrentSchemaVersion, TenantID: "t", DeviceID: "d",
		Firewall: FirewallPolicy{DefaultAction: ActionAllow}, Web: w}
}

func TestWebDecide(t *testing.T) {
	c, err := Compile(webSnapshot(WebPolicy{
		Inspect: true,
		Bypass:  []string{"*.bank.example"},
		Rules: []WebRule{
			{ID: "allow-public", Domains: []string{"app.example"}, PathPrefixes: []string{"/admin/public"}, Action: ActionAllow},
			{ID: "no-admin", Domains: []string{"app.example"}, PathPrefixes: []string{"/admin/"}, Action: ActionBlock},
			{ID: "no-upload", Domains: []string{"*.files.example"}, Methods: []string{"post", "PUT"}, Action: ActionBlock},
		},
		Headers: []WebHeader{{Domains: []string{"*.saas.example"}, Name: "x-allowed-tenant", Value: "acme"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, method, path string
		want               Action
		rule               string
	}{
		{"app.example", "GET", "/admin/users", ActionBlock, "no-admin"},
		{"app.example", "GET", "/admin", ActionBlock, "no-admin"},
		{"APP.example.", "GET", "/ADMIN/x", ActionBlock, "no-admin"},
		{"app.example", "GET", "//admin//x", ActionBlock, "no-admin"},
		{"app.example", "GET", "/x/../admin/y", ActionBlock, "no-admin"},
		{"app.example", "GET", "/admin/public/a", ActionAllow, "allow-public"},
		{"app.example", "GET", "/administrator", ActionAllow, ""},
		{"app.example", "GET", "/", ActionAllow, ""},
		{"other.example", "GET", "/admin/x", ActionAllow, ""},
		{"a.files.example", "POST", "/up", ActionBlock, "no-upload"},
		{"a.files.example", "get", "/up", ActionAllow, ""},
	} {
		got, rule := c.WebDecide(tc.host, tc.method, tc.path)
		if got != tc.want || rule != tc.rule {
			t.Errorf("%s %s %s: %s %q, want %s %q", tc.method, tc.host, tc.path, got, rule, tc.want, tc.rule)
		}
	}
	for host, want := range map[string]bool{"app.example": true, "x.bank.example": false, "bank.example": false, "bank.example.org": true, "1.2.3.4x_": true, "": false, "bad host": false} {
		if got := c.Inspects(host); got != want {
			t.Errorf("Inspects(%q) = %v", host, got)
		}
	}
	if h := c.WebHeaders("login.saas.example"); len(h) != 1 || h[0].Name != "X-Allowed-Tenant" || h[0].Value != "acme" {
		t.Errorf("headers %+v", h)
	}
	if h := c.WebHeaders("saas.example.org"); len(h) != 0 {
		t.Errorf("headers for other host %+v", h)
	}
	none, _ := Compile(webSnapshot(WebPolicy{}))
	if none.Inspects("app.example") || none.HasWebRules() || none.BlockECH() {
		t.Error("empty web policy inspects")
	}
}

func TestBlockECH(t *testing.T) {
	tests := []struct {
		name     string
		w        WebPolicy
		wantECH  bool
		wantInsp bool
	}{
		{"empty", WebPolicy{}, false, false},
		{"inspect_only", WebPolicy{Inspect: true}, false, true},
		{"ech_only", WebPolicy{BlockECH: true}, true, false},
		{"both", WebPolicy{Inspect: true, BlockECH: true}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Compile(webSnapshot(tc.w))
			if err != nil {
				t.Fatal(err)
			}
			if got := c.BlockECH(); got != tc.wantECH {
				t.Errorf("BlockECH() = %v, want %v", got, tc.wantECH)
			}
			if got := c.InspectEnabled(); got != tc.wantInsp {
				t.Errorf("InspectEnabled() = %v, want %v", got, tc.wantInsp)
			}
		})
	}
	var nilC *Compiled
	if nilC.BlockECH() {
		t.Error("nil Compiled BlockECH() = true, want false")
	}
}

func TestWebPolicyValidation(t *testing.T) {
	ok := WebRule{ID: "r", Domains: []string{"a.example"}, Action: ActionBlock}
	for name, tc := range map[string]struct {
		w     WebPolicy
		field string
	}{
		"bad bypass":       {WebPolicy{Bypass: []string{"bad domain"}}, "web.bypass[0]"},
		"no id":            {WebPolicy{Rules: []WebRule{{Domains: ok.Domains, Action: ActionBlock}}}, "web.rules[0].id"},
		"duplicate id":     {WebPolicy{Rules: []WebRule{ok, ok}}, "web.rules[1].id"},
		"ask action":       {WebPolicy{Rules: []WebRule{{ID: "r", Domains: ok.Domains, Action: ActionAsk}}}, "web.rules[0].action"},
		"no domains":       {WebPolicy{Rules: []WebRule{{ID: "r", Action: ActionBlock}}}, "web.rules[0].domains"},
		"relative path":    {WebPolicy{Rules: []WebRule{{ID: "r", Domains: ok.Domains, PathPrefixes: []string{"admin"}, Action: ActionBlock}}}, "web.rules[0].pathPrefixes[0]"},
		"bad method":       {WebPolicy{Rules: []WebRule{{ID: "r", Domains: ok.Domains, Methods: []string{"GE T"}, Action: ActionBlock}}}, "web.rules[0].methods[0]"},
		"host header":      {WebPolicy{Headers: []WebHeader{{Domains: ok.Domains, Name: "host", Value: "x"}}}, "web.headers[0].name"},
		"framing header":   {WebPolicy{Headers: []WebHeader{{Domains: ok.Domains, Name: "Transfer-Encoding", Value: "chunked"}}}, "web.headers[0].name"},
		"bad header name":  {WebPolicy{Headers: []WebHeader{{Domains: ok.Domains, Name: "a b", Value: "x"}}}, "web.headers[0].name"},
		"header injection": {WebPolicy{Headers: []WebHeader{{Domains: ok.Domains, Name: "X-A", Value: "x\r\nEvil: 1"}}}, "web.headers[0].value"},
		"header no domain": {WebPolicy{Headers: []WebHeader{{Name: "X-A", Value: "x"}}}, "web.headers[0].domains"},
	} {
		_, err := Compile(webSnapshot(tc.w))
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: err %v, want field %s", name, err, tc.field)
		}
	}
}

func TestDLPRules(t *testing.T) {
	c, err := Compile(webSnapshot(WebPolicy{Inspect: true, DLP: []DLPRule{
		{ID: "pci", Detectors: []string{"credit-card"}, Action: ActionBlock, BlockUnscanned: true},
		{ID: "bulk-mail", Domains: []string{"*.share.example"}, Detectors: []string{"email"}, MinMatches: 50, Action: ActionAllow},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.DLPChecks("www.example"); len(got) != 1 || got[0].ID != "pci" || got[0].MinMatches != 1 || !got[0].BlockUnscanned {
		t.Fatalf("checks for other host %+v", got)
	}
	if got := c.DLPChecks("x.share.example"); len(got) != 2 || got[1].MinMatches != 50 || got[1].Action != ActionAllow {
		t.Fatalf("checks %+v", got)
	}
	if !c.HasWebRules() {
		t.Fatal("DLP rules do not count as web rules")
	}
	for name, r := range map[string]DLPRule{
		"no id":        {Detectors: []string{"iban"}, Action: ActionBlock},
		"bad action":   {ID: "x", Detectors: []string{"iban"}, Action: ActionAsk},
		"unknown":      {ID: "x", Detectors: []string{"ssn"}, Action: ActionBlock},
		"nothing":      {ID: "x", Action: ActionBlock},
		"bad pattern":  {ID: "x", Patterns: []string{"("}, Action: ActionBlock},
		"bad domain":   {ID: "x", Domains: []string{"a b"}, Detectors: []string{"iban"}, Action: ActionBlock},
		"negative min": {ID: "x", Detectors: []string{"iban"}, MinMatches: -1, Action: ActionBlock},
	} {
		if _, err := Compile(webSnapshot(WebPolicy{DLP: []DLPRule{r}})); err == nil || !strings.Contains(err.Error(), "web.dlp[0]") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
