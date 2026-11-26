package controlplane

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

// TestEnrollOIDC covers issue #68: a sign-in at the identity provider ends at the client's
// loopback URL with a single-use provisioning key for the signed-in user, who is created on
// first use with the identity provider groups.
func TestEnrollOIDC(t *testing.T) {
	idp := newFakeIDP(t)
	idp.customEmail = "carol@acme.example"
	idp.customGroups = []string{"sales", "everyone"}
	e := newEnv(t)
	e.setupTenant(1)
	e.adminDo("PUT", "/v1/admin/tenants/acme/oidc", api.TenantOIDC{Issuer: idp.server.URL, ClientID: "app", GroupRoles: map[string]string{"admins": "admin"}}, 200)
	cli := noRedirectClient(e)

	for _, bad := range []string{"https://evil.example/cb", "http://evil.example:8080/cb", "http://127.0.0.1/cb", "opensase://other"} {
		resp, _ := e.do(cli, "GET", "/v1/enroll/oidc/acme/start?return_to="+url.QueryEscape(bad), nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("return_to %s: %d", bad, resp.StatusCode)
		}
	}

	resp, _ := e.do(cli, "GET", "/v1/enroll/oidc/acme/start?return_to="+url.QueryEscape("http://127.0.0.1:53111/callback")+"&state=xyz", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	idpResp, err := cli.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := url.Parse(idpResp.Header.Get("Location"))
	cbResp, _ := e.do(cli, "GET", "/v1/auth/oidc/callback?"+cb.RawQuery, nil, nil)
	if cbResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: %d", cbResp.StatusCode)
	}
	dest, err := url.Parse(cbResp.Header.Get("Location"))
	if err != nil || dest.Host != "127.0.0.1:53111" || dest.Query().Get("state") != "xyz" || dest.Query().Get("code") == "" {
		t.Fatalf("redirect %v %v", dest, err)
	}
	er, _ := e.enroll(dest.Query().Get("code"))
	u, err := e.s.cfg.Store.UserByEmail(context.Background(), "acme", "carol@acme.example")
	if err != nil || er.UserID != u.ID {
		t.Fatalf("enrolled user %q, store user %+v %v", er.UserID, u, err)
	}
	if g, _ := e.s.cfg.Store.UserGroups(context.Background(), u.ID); len(g) != 2 || g[0] != "everyone" {
		t.Fatalf("groups %v", g)
	}
	// The key is single use.
	var resp2 *http.Response
	resp2, _ = e.do(e.client(nil), "POST", "/v1/enroll", api.EnrollRequest{ProvisioningKey: dest.Query().Get("code"), DeviceName: "again", Platform: "linux", CSRPEM: "x"}, nil)
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("enrolment key used twice")
	}
}

func TestScopeRules(t *testing.T) {
	rules := []policy.Rule{
		{ID: "all"},
		{ID: "sales", Groups: []string{"sales"}},
		{ID: "carol", Users: []string{"CAROL@acme.example"}},
		{ID: "dave", Users: []string{"u-dave"}},
	}
	got := scopeRules(rules, store.User{ID: "u-carol", Email: "carol@acme.example"}, []string{"sales"})
	var ids []string
	for _, r := range got {
		ids = append(ids, r.ID)
		if r.Users != nil || r.Groups != nil {
			t.Fatalf("rule %s keeps its scope", r.ID)
		}
	}
	if strings.Join(ids, ",") != "all,sales,carol" {
		t.Fatalf("rules %v", ids)
	}
	if rules[1].Groups == nil {
		t.Fatal("scopeRules modified the tenant policy")
	}
}
