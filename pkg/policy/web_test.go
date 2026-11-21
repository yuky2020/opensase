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
	if none.Inspects("app.example") || none.HasWebRules() {
		t.Error("empty web policy inspects")
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
