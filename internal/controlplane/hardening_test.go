package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

// setupTenant creates tenant acme, user u1, the example policy and returns a provisioning
// key with n uses.
func (e *env) setupTenant(n int) string {
	e.t.Helper()
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "acme", Name: "Acme"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u1", Email: "u1@acme"}, 201)
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", examplePolicy(), 204)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: n}, 201), &pk)
	return pk.Key
}

func newCSR(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func keyPair(t *testing.T, certPEM string, k *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	c, err := tls.X509KeyPair([]byte(certPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRenew(t *testing.T) {
	e := newEnv(t)
	er, oldCert := e.enroll(e.setupTenant(1))
	old := e.client(&oldCert)

	// The same key is refused: renewal must rotate the device key.
	oldKey := oldCert.PrivateKey.(*ecdsa.PrivateKey)
	if resp, _ := e.do(old, "POST", "/v1/renew", api.RenewRequest{CSRPEM: newCSR(t, oldKey)}, nil); resp.StatusCode != 400 {
		t.Fatalf("same key: %d", resp.StatusCode)
	}
	if resp, _ := e.do(old, "POST", "/v1/renew", api.RenewRequest{CSRPEM: "nope"}, nil); resp.StatusCode != 400 {
		t.Fatalf("bad CSR: %d", resp.StatusCode)
	}
	if resp, _ := e.do(e.admin, "POST", "/v1/renew", api.RenewRequest{}, nil); resp.StatusCode != 401 {
		t.Fatalf("no cert: %d", resp.StatusCode)
	}

	renew := func(c *http.Client, want int) (tls.Certificate, *x509.Certificate) {
		t.Helper()
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		resp, body := e.do(c, "POST", "/v1/renew", api.RenewRequest{CSRPEM: newCSR(t, k)}, nil)
		if resp.StatusCode != want {
			t.Fatalf("renew: %d want %d: %s", resp.StatusCode, want, body)
		}
		if want != 200 {
			return tls.Certificate{}, nil
		}
		var rr api.RenewResponse
		if err := json.Unmarshal(body, &rr); err != nil {
			t.Fatal(err)
		}
		cert := keyPair(t, rr.CertificatePEM, k)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(rr.CAPEM))
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("renewed cert vs CAPEM: %v", err)
		}
		return cert, cert.Leaf
	}

	lostCert, _ := renew(old, 200) // response "lost": the device keeps using the old cert
	if resp, _ := e.do(old, "GET", "/v1/snapshot", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("superseded cert on a device route: %d", resp.StatusCode)
	}
	newCert, leaf := renew(old, 200) // retry with the old cert succeeds
	if id, err := pki.ParseURI(leaf.URIs[0].String()); err != nil || id.DeviceID != er.DeviceID || id.TenantID != "acme" {
		t.Fatalf("renewed identity %+v %v", id, err)
	}
	if d := time.Until(leaf.NotAfter); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("renewed validity %v", d)
	}
	if resp, _ := e.do(e.client(&lostCert), "GET", "/v1/snapshot", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("undelivered cert accepted: %d", resp.StatusCode)
	}
	cur := e.client(&newCert)
	if resp, _ := e.do(cur, "GET", "/v1/snapshot", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("renewed cert: %d", resp.StatusCode)
	}
	// Renewing with the newest cert moves "previous" forward: the first cert is now dead.
	newest, _ := renew(cur, 200)
	renew(old, 403)
	e.adminDo("POST", "/v1/admin/tenants/acme/devices/"+er.DeviceID+"/revoke", nil, 204)
	renew(e.client(&newest), 403)
	renew(cur, 403)
}

func TestEdgeRegistryAndSessionScope(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(2)
	d1, _ := e.enroll(key)
	d2, _ := e.enroll(key)
	auth, err := pki.OpenAuthority(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	edgeClient := func(id string) *http.Client {
		c, k, err := auth.Root.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindEdge, ID: id, DNSNames: []string{"x"}})
		if err != nil {
			t.Fatal(err)
		}
		cert, err := tls.X509KeyPair(append(c, auth.Root.CertPEM()...), k)
		if err != nil {
			t.Fatal(err)
		}
		return e.client(&cert)
	}
	e1, e2 := edgeClient("edge-1"), edgeClient("edge-2")
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-2"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "../x"}, 400)
	if resp, _ := e.do(e1, "POST", "/v1/edge/sessions", EdgeSessions{DeviceIDs: []string{d1.DeviceID}}, nil); resp.StatusCode != 204 {
		t.Fatalf("report: %d", resp.StatusCode)
	}
	ask := api.DecideRequest{Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.5", DstPort: 443}}
	tests := []struct {
		name   string
		c      *http.Client
		device string
		want   int
	}{
		{"own session", e1, d1.DeviceID, 200},
		{"device without session on this edge", e1, d2.DeviceID, 403},
		{"session on another edge", e2, d1.DeviceID, 403},
		{"unknown device", e1, "ghost", 403},
	}
	for _, tc := range tests {
		if resp, body := e.do(tc.c, "POST", "/v1/decide?device="+tc.device, ask, nil); resp.StatusCode != tc.want {
			t.Errorf("%s: %d want %d: %s", tc.name, resp.StatusCode, tc.want, body)
		}
	}
	// Flows: only records of devices with a live session on the posting edge are stored.
	before := len(e.flows())
	recs := []api.FlowRecord{{Start: time.Now(), DeviceID: d1.DeviceID}, {Start: time.Now(), DeviceID: d2.DeviceID}}
	if resp, _ := e.do(e2, "POST", "/v1/flows", api.FlowBatch{Records: recs}, nil); resp.StatusCode != 202 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(e1, "POST", "/v1/flows", api.FlowBatch{Records: recs}, nil); resp.StatusCode != 202 {
		t.Fatal(resp.StatusCode)
	}
	got := e.flows()
	if len(got) != before+1 || got[0].DeviceID != d1.DeviceID || got[0].Where != "edge" {
		t.Fatalf("edge flows %+v", got[:len(got)-before])
	}

	// Revoked edge: every edge route is refused.
	e.adminDo("POST", "/v1/admin/edges/edge-1/revoke", nil, 204)
	e.adminDo("POST", "/v1/admin/edges/nope/revoke", nil, 404)
	for _, path := range []string{"/v1/edge/peers"} {
		if resp, _ := e.do(e1, "GET", path, nil, nil); resp.StatusCode != 403 {
			t.Fatalf("revoked edge %s: %d", path, resp.StatusCode)
		}
	}
	if resp, _ := e.do(e1, "POST", "/v1/decide?device="+d1.DeviceID, ask, nil); resp.StatusCode != 403 {
		t.Fatalf("revoked edge decide: %d", resp.StatusCode)
	}
	var edges []AdminEdge
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/edges", nil, 200), &edges)
	if len(edges) != 2 || !edges[0].Revoked || edges[1].Revoked {
		t.Fatalf("edges %+v", edges)
	}
}

func (e *env) flows() []api.FlowRecord {
	e.t.Helper()
	var fb api.FlowBatch
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/flows?limit=10000", nil, 200), &fb)
	return fb.Records
}

func TestLongPollCap(t *testing.T) {
	e := newEnv(t)
	_, cert := e.enroll(e.setupTenant(1))
	dev := e.client(&cert)
	resp, _ := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	tag := resp.Header.Get("ETag")
	poll := func() int {
		req, _ := http.NewRequest("GET", e.srv.URL+"/v1/snapshot?wait=3", nil)
		req.Header.Set("If-None-Match", tag)
		r, err := dev.Do(req)
		if err != nil {
			return 0
		}
		r.Body.Close()
		return r.StatusCode
	}
	var wg sync.WaitGroup
	codes := make(chan int, maxLongPollsPerDev)
	for range maxLongPollsPerDev {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- poll() }()
	}
	waitUntil(t, func() bool {
		e.s.polls.mu.Lock()
		defer e.s.polls.mu.Unlock()
		return len(e.s.polls.n) == 1 && e.s.polls.n[firstKey(e.s.polls.n)] == maxLongPollsPerDev
	})
	if got := poll(); got != http.StatusTooManyRequests {
		t.Fatalf("third long-poll: %d", got)
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusNotModified {
			t.Fatalf("capped long-poll returned %d", c)
		}
	}
	if got := poll(); got != http.StatusNotModified { // slots released
		t.Fatalf("after release: %d", got)
	}
}

func firstKey(m map[string]int) string {
	for k := range m {
		return k
	}
	return ""
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFlowRateLimit(t *testing.T) {
	e := newEnv(t)
	_, cert := e.enroll(e.setupTenant(1))
	dev := e.client(&cert)
	recs := make([]api.FlowRecord, 1200)
	for i := range recs {
		recs[i] = api.FlowRecord{Start: time.Now(), Flow: policy.Flow{Protocol: "tcp", DstIP: "9.9.9.9", DstPort: 443}}
	}
	if resp, _ := e.do(dev, "POST", "/v1/flows", api.FlowBatch{Records: recs}, nil); resp.StatusCode != 202 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(dev, "POST", "/v1/flows", api.FlowBatch{Records: recs[:10]}, nil); resp.StatusCode != 202 {
		t.Fatal(resp.StatusCode)
	}
	if n := len(e.flows()); n != DefaultFlowRate {
		t.Fatalf("stored %d records, want %d", n, DefaultFlowRate)
	}
}

func TestRateLimiterWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newRateLimiter(10, time.Minute, func() time.Time { return now })
	tests := []struct {
		advance time.Duration
		key     string
		n, want int
	}{
		{0, "a", 6, 6},
		{0, "a", 6, 4},
		{0, "a", 1, 0},
		{0, "b", 3, 3},
		{59 * time.Second, "a", 1, 0},
		{time.Second, "a", 12, 10}, // new window
	}
	for i, tc := range tests {
		now = now.Add(tc.advance)
		if got := l.take(tc.key, tc.n); got != tc.want {
			t.Errorf("step %d: got %d want %d", i, got, tc.want)
		}
	}
	now = now.Add(2 * time.Minute)
	l.prune()
	if len(l.m) != 0 {
		t.Fatal("prune kept expired windows")
	}
}

func TestSanitizeFlow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	long := strings.Repeat("a", 1000)
	tests := []struct {
		name       string
		in         api.FlowRecord
		start, end time.Time
	}{
		{"in range", api.FlowRecord{Start: now.Add(-time.Hour), End: now}, now.Add(-time.Hour), now},
		{"ancient", api.FlowRecord{Start: time.Unix(0, 0)}, now.Add(-flowPast), time.Time{}},
		{"future", api.FlowRecord{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)}, now.Add(flowFuture), now.Add(flowFuture)},
		{"end before start", api.FlowRecord{Start: now, End: now.Add(-time.Hour)}, now, now},
	}
	for _, tc := range tests {
		got := sanitizeFlow(tc.in, now)
		if !got.Start.Equal(tc.start) || !got.End.Equal(tc.end) {
			t.Errorf("%s: start %v end %v", tc.name, got.Start, got.End)
		}
	}
	got := sanitizeFlow(api.FlowRecord{Start: now, BytesIn: 1 << 62, BytesOut: 5, Flow: policy.Flow{Domain: long, App: long}, Decision: policy.Decision{RuleID: long}}, now)
	if got.BytesIn != maxFlowBytes || got.BytesOut != 5 || len(got.Flow.Domain) != maxDomainLen || len(got.Flow.App) != maxStringLen || len(got.Decision.RuleID) != maxRuleIDLen {
		t.Fatalf("bounds: %d %d %d %d", got.BytesIn, len(got.Flow.Domain), len(got.Flow.App), len(got.Decision.RuleID))
	}
}
