package controlplane

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

// edgeClientID returns a client presenting an edge certificate for id.
func (e *env) edgeClientID(id string) *http.Client {
	e.t.Helper()
	auth, err := pki.OpenAuthority(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	c, k, err := auth.Root.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindEdge, ID: id, DNSNames: []string{"x"}})
	if err != nil {
		e.t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(append(c, auth.Root.CertPEM()...), k)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.client(&cert)
}

func edgeIDs(es []api.EdgeInfo) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.ID)
	}
	return out
}

// TestPrivateEdgeScope checks ADR-0014: a Private Edge sees, decides for and reports only its
// tenant, and only the tenant's devices and connectors are told about it.
func TestPrivateEdgeScope(t *testing.T) {
	e := newEnvCfg(t, func(c *Config) {
		c.Edges = []api.EdgeInfo{
			{ID: "pub", SessionURL: "https://pub:8443", BrokerAddr: "pub:8444"},
			{ID: "priv-acme", SessionURL: "https://pa:8443", BrokerAddr: "pa:8444"},
			{ID: "priv-beta", SessionURL: "https://pb:8443", BrokerAddr: "pb:8444"},
		}
	})
	acmeKey := e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/beta/users", api.AdminUser{ID: "b1", Email: "b1@beta"}, 201)
	e.adminDo("PUT", "/v1/admin/tenants/beta/policy", examplePolicy(), 204)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/beta/provisioning-keys", api.ProvisioningKeyRequest{UserID: "b1", MaxUses: 1}, 201), &pk)

	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "pub"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "priv-acme", TenantID: "acme"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "priv-beta", TenantID: "beta"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "priv-x", TenantID: "ghost"}, 404)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "priv-y", TenantID: "../x"}, 400)

	da, _ := e.enroll(acmeKey)
	db, _ := e.enroll(pk.Key)
	if got := edgeIDs(da.Edges); !slices.Equal(got, []string{"pub", "priv-acme"}) {
		t.Fatalf("acme device edges %v", got)
	}
	if got := edgeIDs(db.Edges); !slices.Equal(got, []string{"pub", "priv-beta"}) {
		t.Fatalf("beta device edges %v", got)
	}

	ca := e.createConnector("acme", "c1", "dc")
	_, ccert := e.enrollConnector(ca.ProvisioningKey)
	if code, _, cfg := e.connectorConfig(e.client(&ccert), nil, ""); code != 200 || !slices.Equal(edgeIDs(cfg.Edges), []string{"pub", "priv-acme"}) {
		t.Fatalf("connector config %d %v", code, edgeIDs(cfg.Edges))
	}

	pub, pa, pb := e.edgeClientID("pub"), e.edgeClientID("priv-acme"), e.edgeClientID("priv-beta")
	devs := func(p api.EdgePeers) (ids []string) {
		for _, d := range p.Devices {
			ids = append(ids, d.TenantID)
		}
		for _, c := range p.Connectors {
			ids = append(ids, "conn:"+c.TenantID)
		}
		slices.Sort(ids)
		return ids
	}
	for _, tc := range []struct {
		name string
		c    *http.Client
		want []string
	}{
		{"public edge", pub, []string{"acme", "beta", "conn:acme"}},
		{"acme private edge", pa, []string{"acme", "conn:acme"}},
		{"beta private edge", pb, []string{"beta"}},
	} {
		if got := devs(e.peers(tc.c)); !slices.Equal(got, tc.want) {
			t.Errorf("%s peers %v want %v", tc.name, got, tc.want)
		}
	}

	// A Private Edge reporting another tenant's device gets no session for it, so it can
	// neither decide nor report flows for it.
	for _, c := range []*http.Client{pa, pb, pub} {
		if resp, _ := e.do(c, "POST", "/v1/edge/sessions", EdgeSessions{DeviceIDs: []string{da.DeviceID, db.DeviceID}}, nil); resp.StatusCode != 204 {
			t.Fatalf("report %d", resp.StatusCode)
		}
	}
	ask := api.DecideRequest{Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.5", DstPort: 443}}
	for _, tc := range []struct {
		name   string
		c      *http.Client
		device string
		want   int
	}{
		{"own tenant", pa, da.DeviceID, 200},
		{"other tenant", pa, db.DeviceID, 403},
		{"beta edge, acme device", pb, da.DeviceID, 403},
		{"public edge", pub, db.DeviceID, 200},
	} {
		if resp, body := e.do(tc.c, "POST", "/v1/decide?device="+tc.device, ask, nil); resp.StatusCode != tc.want {
			t.Errorf("%s: %d want %d: %s", tc.name, resp.StatusCode, tc.want, body)
		}
	}

	var edges []AdminEdge
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/edges", nil, 200), &edges)
	tenants := map[string]string{}
	for _, ed := range edges {
		tenants[ed.ID] = ed.TenantID
	}
	if len(edges) != 3 || tenants["pub"] != "" || tenants["priv-acme"] != "acme" || tenants["priv-beta"] != "beta" {
		t.Fatalf("admin edges %+v", edges)
	}
}
