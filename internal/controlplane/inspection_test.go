package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

func inspectionCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), k
}

// TestInspectionCA checks ADR-0018 on the Control Plane: Edges get a short-lived
// intermediate only for tenants they serve that turned inspection on; admins download the
// tenant's inspection root.
func TestInspectionCA(t *testing.T) {
	e := newEnvCfg(t, func(c *Config) {
		c.Edges = append(c.Edges, api.EdgeInfo{ID: "priv-beta", SessionURL: "https://pb:8443"})
	})
	devKey := e.setupTenant(2)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "priv-beta", TenantID: "beta"}, 201)
	pub, pb := e.edgeClientID("edge-1"), e.edgeClientID("priv-beta")
	csr, key := inspectionCSR(t)
	ask := func(c *http.Client, tenant, csr string) (int, api.InspectionCAResponse) {
		resp, b := e.do(c, "POST", "/v1/edge/inspection-ca", api.InspectionCARequest{TenantID: tenant, CSR: csr}, nil)
		var out api.InspectionCAResponse
		_ = json.Unmarshal(b, &out)
		return resp.StatusCode, out
	}
	if code, _ := ask(pub, "acme", csr); code != http.StatusForbidden {
		t.Fatalf("inspection off: %d", code)
	}
	tp := examplePolicy()
	tp.Web = policy.WebPolicy{Inspect: true, Rules: []policy.WebRule{{ID: "r", Domains: []string{"x.example"}, Action: "ask"}}}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 400)
	tp.Web.Rules[0].Action = policy.ActionBlock
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)

	for name, tc := range map[string]struct {
		c      *http.Client
		tenant string
		csr    string
		want   int
	}{
		"private edge, other tenant": {pb, "acme", csr, http.StatusForbidden},
		"unknown tenant":             {pub, "ghost", csr, http.StatusForbidden},
		"bad tenant id":              {pub, "../x", csr, http.StatusBadRequest},
		"bad csr":                    {pub, "acme", "nope", http.StatusBadRequest},
		"device cert":                {nil, "acme", csr, http.StatusForbidden},
	} {
		c := tc.c
		if c == nil {
			_, cert := e.enroll(devKey)
			c = e.client(&cert)
		}
		if code, _ := ask(c, tc.tenant, tc.csr); code != tc.want {
			t.Errorf("%s: %d want %d", name, code, tc.want)
		}
	}

	code, out := ask(pub, "acme", csr)
	if code != 200 {
		t.Fatalf("issue: %d", code)
	}
	certs, err := pki.ParseCertsPEM([]byte(out.Chain))
	if err != nil || len(certs) != 2 {
		t.Fatalf("chain %v", err)
	}
	ic := certs[0]
	if !ic.IsCA || !ic.MaxPathLenZero || !ic.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) || time.Until(ic.NotAfter) > pki.InspectionIntermediateValidity {
		t.Fatalf("intermediate %+v", ic)
	}
	if len(ic.ExtKeyUsage) != 1 || ic.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("intermediate EKU %v", ic.ExtKeyUsage)
	}

	// The admin's root is the one the intermediate chains to, separate from the mTLS PKI.
	resp, b := e.do(e.admin, "GET", "/v1/admin/tenants/acme/inspection-ca", nil, map[string]string{"Authorization": "Bearer " + testToken})
	if resp.StatusCode != 200 {
		t.Fatalf("root download %d", resp.StatusCode)
	}
	roots, err := pki.ParseCertsPEM(b)
	if err != nil || !roots[0].Equal(certs[1]) || ic.CheckSignatureFrom(roots[0]) != nil {
		t.Fatalf("root %v", err)
	}
	if roots[0].Equal(e.s.cfg.Authority.Root.Cert) {
		t.Fatal("inspection root is the provider root")
	}
	e.adminDo("GET", "/v1/admin/tenants/ghost/inspection-ca", nil, 404)
}
