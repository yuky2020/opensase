package controlplane

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// TestTenantAdminTokens checks ST-03: a tenant admin token administers its tenant only;
// other tenants look nonexistent, super-admin routes are refused, and revocation and expiry
// take effect at once.
func TestTenantAdminTokens(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1) // acme
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)

	var created api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "acme ops"}, 201), &created)
	if !strings.HasPrefix(created.Token, adminTokenPrefix) || created.TenantID != "acme" || created.ID == "" {
		t.Fatalf("created %+v", created.AdminToken)
	}
	if d := created.ExpiresAt.Sub(created.CreatedAt); d != defaultAdminTokenValid {
		t.Fatalf("validity %v", d)
	}
	e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: " "}, 400)
	e.adminDo("POST", "/v1/admin/tenants/ghost/admin-tokens", api.AdminTokenRequest{Name: "x"}, 404)

	as := func(tok, method, path string, body any) (int, []byte) {
		resp, b := e.do(e.admin, method, path, body, map[string]string{"Authorization": "Bearer " + tok})
		return resp.StatusCode, b
	}
	tok := created.Token
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"GET", "/v1/admin/tenants/acme/users", nil, 200},
		{"GET", "/v1/admin/tenants/acme/devices", nil, 200},
		{"GET", "/v1/admin/tenants/acme/policy", nil, 200},
		{"GET", "/v1/admin/tenants/acme/flows", nil, 200},
		{"POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u9", Email: "u9@acme"}, 201},
		// Another tenant, existing or not, is indistinguishable.
		{"GET", "/v1/admin/tenants/beta/devices", nil, 404},
		{"GET", "/v1/admin/tenants/beta/policy", nil, 404},
		{"PUT", "/v1/admin/tenants/beta/policy", examplePolicy(), 404},
		{"POST", "/v1/admin/tenants/beta/admin-tokens", api.AdminTokenRequest{Name: "escalate"}, 404},
		{"GET", "/v1/admin/tenants/ghost/devices", nil, 404},
		// Super-admin routes.
		{"POST", "/v1/admin/tenants", api.AdminTenant{ID: "gamma", Name: "G"}, 403},
		{"GET", "/v1/admin/edges", nil, 403},
		{"POST", "/v1/admin/edges", AdminEdge{ID: "e9", TenantID: "acme"}, 403},
		{"POST", "/v1/admin/edges/e9/revoke", nil, 403},
	} {
		if code, b := as(tok, tc.method, tc.path, tc.body); code != tc.want {
			t.Errorf("%s %s: %d want %d: %s", tc.method, tc.path, code, tc.want, b)
		}
	}

	// Tenant list and identity are scoped.
	code, b := as(tok, "GET", "/v1/admin/tenants", nil)
	var ts []api.AdminTenant
	_ = json.Unmarshal(b, &ts)
	if code != 200 || len(ts) != 1 || ts[0].ID != "acme" {
		t.Fatalf("tenants %d %s", code, b)
	}
	var who api.AdminIdentity
	_, b = as(tok, "GET", "/v1/admin/whoami", nil)
	_ = json.Unmarshal(b, &who)
	if who != (api.AdminIdentity{Role: "tenant", TenantID: "acme", TokenID: created.ID}) {
		t.Fatalf("whoami %+v", who)
	}
	who = api.AdminIdentity{}
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/whoami", nil, 200), &who)
	if who.Role != "super" || who.TenantID != "" {
		t.Fatalf("super whoami %+v", who)
	}

	// The list never carries secrets and shows the last use.
	b = e.adminDo("GET", "/v1/admin/tenants/acme/admin-tokens", nil, 200)
	if strings.Contains(string(b), tok) || strings.Contains(string(b), `"token"`) {
		t.Fatalf("token list leaks the secret: %s", b)
	}
	var list []api.AdminToken
	_ = json.Unmarshal(b, &list)
	if len(list) != 1 || list[0].LastUsed.IsZero() {
		t.Fatalf("list %s", b)
	}
	if code, _ := as(tok, "GET", "/v1/admin/tenants/beta/admin-tokens", nil); code != 404 {
		t.Fatalf("beta tokens via acme: %d", code)
	}

	// Wrong tokens: unknown, tampered, beta's token on acme.
	var betaTok api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/beta/admin-tokens", api.AdminTokenRequest{Name: "b"}, 201), &betaTok)
	for _, bad := range []string{adminTokenPrefix + "nope", tok + "x", ""} {
		if code, _ := as(bad, "GET", "/v1/admin/tenants/acme/users", nil); code != 401 {
			t.Errorf("token %q: %d", bad, code)
		}
	}
	if code, _ := as(betaTok.Token, "GET", "/v1/admin/tenants/acme/users", nil); code != 404 {
		t.Errorf("beta token on acme: %d", code)
	}
	// A tenant admin cannot revoke another tenant's token.
	if code, _ := as(tok, "POST", "/v1/admin/tenants/beta/admin-tokens/"+betaTok.ID+"/revoke", nil); code != 404 {
		t.Errorf("cross-tenant revoke: %d", code)
	}
	if code, _ := as(betaTok.Token, "GET", "/v1/admin/tenants/beta/users", nil); code != 200 {
		t.Errorf("beta token after cross-tenant revoke attempt: %d", code)
	}

	// Revocation is immediate.
	if code, _ := as(tok, "POST", "/v1/admin/tenants/acme/admin-tokens/"+created.ID+"/revoke", nil); code != 204 {
		t.Fatalf("self revoke: %d", code)
	}
	if code, _ := as(tok, "GET", "/v1/admin/tenants/acme/users", nil); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
	e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens/nope/revoke", nil, 404)
}

func TestAdminTokenExpiry(t *testing.T) {
	var skew atomic.Int64
	e := newEnvCfg(t, func(c *Config) { c.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) } })
	e.setupTenant(1)
	var c api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "short", ValidFor: 60}, 201), &c)
	get := func() int {
		resp, _ := e.do(e.admin, "GET", "/v1/admin/tenants/acme/users", nil, map[string]string{"Authorization": "Bearer " + c.Token})
		return resp.StatusCode
	}
	if get() != http.StatusOK {
		t.Fatal("fresh token refused")
	}
	skew.Store(int64(61 * time.Second))
	if got := get(); got != http.StatusUnauthorized {
		t.Fatalf("expired token: %d", got)
	}
	// Validity is capped.
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "long", ValidFor: 10 * 365 * 86400}, 201), &c)
	if d := c.ExpiresAt.Sub(c.CreatedAt); d != maxAdminTokenValid {
		t.Fatalf("capped validity %v", d)
	}
}
