package controlplane

import (
	"encoding/json"
	"net/http"
	"strconv"
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
	if who != (api.AdminIdentity{Role: "tenant", TenantID: "acme", TokenID: created.ID, TenantRole: api.TenantRoleAdmin}) {
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

// TestAdminAudit checks that every admin write is recorded with its actor and outcome, that
// reads are not, and that a tenant admin sees only its tenant's trail.
func TestAdminAudit(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	var c api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "ops"}, 201), &c)
	as := func(method, path string, body any) int {
		resp, _ := e.do(e.admin, method, path, body, map[string]string{"Authorization": "Bearer " + c.Token})
		return resp.StatusCode
	}
	as("POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u7", Email: "u7@acme"}) // 201
	as("GET", "/v1/admin/tenants/acme/users", nil)                                        // read: not recorded
	as("PUT", "/v1/admin/tenants/beta/policy", examplePolicy())                           // 404, recorded under beta
	as("POST", "/v1/admin/edges", AdminEdge{ID: "x"})                                     // 403, global

	var mine []api.AuditEntry
	resp, b := e.do(e.admin, "GET", "/v1/admin/tenants/acme/audit", nil, map[string]string{"Authorization": "Bearer " + c.Token})
	_ = json.Unmarshal(b, &mine)
	if resp.StatusCode != 200 {
		t.Fatalf("tenant audit %d %s", resp.StatusCode, b)
	}
	actor := "token:" + c.ID
	if len(mine) == 0 || mine[0].Actor != actor || mine[0].Method != "POST" || mine[0].Path != "/v1/admin/tenants/acme/users" || mine[0].Status != 201 {
		t.Fatalf("newest acme entry %+v", mine)
	}
	for _, x := range mine {
		if x.TenantID != "acme" || x.Method == "GET" {
			t.Fatalf("tenant audit leaks or records reads: %+v", x)
		}
	}
	if code := as("GET", "/v1/admin/tenants/beta/audit", nil); code != 404 {
		t.Fatalf("beta audit via acme token: %d", code)
	}
	if code := as("GET", "/v1/admin/audit", nil); code != 403 {
		t.Fatalf("global audit via tenant token: %d", code)
	}

	var all []api.AuditEntry
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/audit?limit=50", nil, 200), &all)
	seen := map[string]bool{}
	for _, x := range all {
		seen[x.Actor+" "+x.Method+" "+x.Path+" "+strconv.Itoa(x.Status)] = true
		if strings.Contains(x.Path, c.Token) {
			t.Fatal("audit contains a token")
		}
	}
	for _, want := range []string{
		"super POST /v1/admin/tenants 201",
		"super POST /v1/admin/tenants/acme/admin-tokens 201",
		actor + " PUT /v1/admin/tenants/beta/policy 404",
		actor + " POST /v1/admin/edges 403",
	} {
		if !seen[want] {
			t.Errorf("missing audit entry %q in %v", want, seen)
		}
	}
	var beta []api.AuditEntry
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/audit?tenant=beta", nil, 200), &beta)
	if len(beta) != 1 || beta[0].Status != 404 {
		t.Fatalf("beta audit %+v", beta)
	}
	e.adminDo("GET", "/v1/admin/audit?limit=0", nil, 400)
}

// TestPolicyNullBody checks that a JSON null (or a non-object) cannot wipe a tenant policy.
func TestPolicyNullBody(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)
	before := e.adminDo("GET", "/v1/admin/tenants/acme/policy", nil, 200)
	for _, body := range []string{"null", " null ", "[]", "\"x\"", "", "{} {}"} {
		req, _ := http.NewRequest("PUT", e.srv.URL+"/v1/admin/tenants/acme/policy", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := e.admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("body %q: %d", body, resp.StatusCode)
		}
	}
	if after := e.adminDo("GET", "/v1/admin/tenants/acme/policy", nil, 200); string(after) != string(before) {
		t.Fatal("policy changed")
	}
}

// TestTenantRoles checks ADR-0027: viewers only read, policy editors also replace the policy,
// admins do everything; tokens of every role stay inside their tenant.
func TestTenantRoles(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)
	mint := func(role string) string {
		var c api.AdminTokenCreated
		_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: role, Role: role}, 201), &c)
		if c.Role != role {
			t.Fatalf("created role %q want %q", c.Role, role)
		}
		return c.Token
	}
	e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "x", Role: "owner"}, 400)
	viewer, editor, admin := mint(api.TenantRoleViewer), mint(api.TenantRolePolicyEditor), mint(api.TenantRoleAdmin)
	as := func(tok, method, path string, body any) int {
		resp, _ := e.do(e.admin, method, path, body, map[string]string{"Authorization": "Bearer " + tok})
		return resp.StatusCode
	}
	policy := examplePolicy()
	for _, tc := range []struct {
		method, path          string
		body                  any
		viewer, editor, admin int
	}{
		{"GET", "/v1/admin/tenants/acme/policy", nil, 200, 200, 200},
		{"GET", "/v1/admin/tenants/acme/flows", nil, 200, 200, 200},
		{"GET", "/v1/admin/tenants/acme/audit", nil, 200, 200, 200},
		{"PUT", "/v1/admin/tenants/acme/policy", policy, 403, 204, 204},
		{"POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u9", Email: "u9@acme"}, 403, 403, 201},
		{"POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 403, 403, 201},
		{"POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "esc", Role: "admin"}, 403, 403, 201},
		{"GET", "/v1/admin/tenants/beta/policy", nil, 404, 404, 404},
	} {
		for who, tok := range map[string]string{"viewer": viewer, "editor": editor, "admin": admin} {
			want := map[string]int{"viewer": tc.viewer, "editor": tc.editor, "admin": tc.admin}[who]
			if got := as(tok, tc.method, tc.path, tc.body); got != want {
				t.Errorf("%s %s %s: %d want %d", who, tc.method, tc.path, got, want)
			}
		}
	}
	var who api.AdminIdentity
	resp, b := e.do(e.admin, "GET", "/v1/admin/whoami", nil, map[string]string{"Authorization": "Bearer " + viewer})
	_ = json.Unmarshal(b, &who)
	if resp.StatusCode != 200 || who.TenantRole != api.TenantRoleViewer {
		t.Fatalf("whoami %+v", who)
	}
	// Refusals are audited with the actor.
	var audit []api.AuditEntry
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/audit?limit=200", nil, 200), &audit)
	refused := 0
	for _, a := range audit {
		if a.Status == 403 && strings.HasPrefix(a.Actor, "token:") {
			refused++
		}
	}
	if refused < 5 {
		t.Fatalf("refusals audited: %d", refused)
	}
}
