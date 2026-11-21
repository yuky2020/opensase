package controlplane

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// TestSaaSPolicy checks ADR-0017 on the Control Plane: the SaaS policy is validated, compiled
// into DNS blocklists of the device snapshot, and flow records are tagged with their app.
func TestSaaSPolicy(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)

	var cat []api.SaaSApp
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/saas/catalog", nil, 200), &cat)
	if len(cat) < 20 || !slices.ContainsFunc(cat, func(a api.SaaSApp) bool { return a.ID == "dropbox" && a.Category == "file-sharing" }) {
		t.Fatalf("catalog %d apps", len(cat))
	}

	tp := examplePolicy()
	for _, bad := range []api.SaaSPolicy{
		{BlockApps: []string{"nope"}},
		{AllowApps: []string{"nope"}},
		{BlockCategories: []string{"gambling"}},
	} {
		tp.SaaS = bad
		b := e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 400)
		if !strings.Contains(string(b), "saas.") {
			t.Errorf("%+v: %s", bad, b)
		}
	}
	tp.SaaS = api.SaaSPolicy{BlockApps: []string{"dropbox"}, BlockCategories: []string{"ai-assistant"}, AllowApps: []string{"claude"}}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)
	var got api.TenantPolicy
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/policy", nil, 200), &got)
	if !slices.Equal(got.SaaS.BlockApps, []string{"dropbox"}) {
		t.Fatalf("stored saas %+v", got.SaaS)
	}

	_, cert := e.enroll(key)
	dev := e.client(&cert)
	resp, body := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("snapshot %d", resp.StatusCode)
	}
	var env policy.Envelope
	_ = json.Unmarshal(body, &env)
	snap, err := policy.Verify(&env, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Compile(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, list string
	}{
		{"www.dropbox.com", "saas:dropbox"},
		{"chatgpt.com", "saas:chatgpt"},
		{"gemini.google.com", "saas:gemini"},
		{"claude.ai", ""}, // allowed out of the blocked category
		{"github.com", ""},
	} {
		blocked, list := c.EvaluateDNS(tc.name)
		if blocked != (tc.list != "") || list != tc.list {
			t.Errorf("%s: blocked=%v list=%q want %q", tc.name, blocked, list, tc.list)
		}
	}

	// Discovery: the Control Plane tags records from the hostname and ignores the reporter.
	now := time.Now()
	recs := api.FlowBatch{Records: []api.FlowRecord{
		{Start: now, Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.9", DstPort: 443, Domain: "uc.dropboxusercontent.com"}, SaaSApp: "spoofed"},
		{Start: now, Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.9", DstPort: 443, Domain: "example.com"}, SaaSApp: "github"},
	}}
	if resp, b := e.do(dev, "POST", "/v1/flows", recs, nil); resp.StatusCode != 202 {
		t.Fatalf("flows %d %s", resp.StatusCode, b)
	}
	apps := map[string]string{}
	for _, r := range e.flows() {
		apps[r.Flow.Domain] = r.SaaSApp
	}
	if apps["uc.dropboxusercontent.com"] != "dropbox" || apps["example.com"] != "" {
		t.Fatalf("tags %v", apps)
	}
}
