package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
	"github.com/yuky2020/opensase/pkg/store"
)

const testToken = "test-admin-token-0123456789"

type env struct {
	t     *testing.T
	srv   *httptest.Server
	s     *Server
	root  *x509.CertPool
	dir   string
	admin *http.Client
	keys  map[string]ed25519.PublicKey
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvCfg(t, nil)
}

// newEnvCfg is newEnv with a hook to adjust the server Config before New.
func newEnvCfg(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	dir := t.TempDir()
	if err := pki.InitDir(dir, pki.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	return newEnvAt(t, dir, filepath.Join(dir, "cp.db"), mod)
}

// newEnvAt starts a Control Plane on an existing PKI directory and database, so two calls
// with the same arguments behave as two replicas (ADR-0033).
func newEnvAt(t *testing.T, dir, dsn string, mod func(*Config)) *env {
	t.Helper()
	auth, err := pki.OpenAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	sk, kid, err := pki.LoadOrCreateSigningKey(filepath.Join(dir, pki.SnapshotKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kek, err := pki.LoadOrCreateKEK(filepath.Join(dir, pki.CAKeyEncryptionKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.UseStore(context.Background(), st, kek); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Store: st, Authority: auth, SigningKey: sk, SigningKeyID: kid, AdminToken: testToken,
		Edges:  []api.EdgeInfo{{ID: "edge-1", SessionURL: "https://edge:8443", WGEndpoint: "edge:51820"}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, pki.CPCertFile), filepath.Join(dir, pki.CPKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(s.Handler())
	hs.TLS = s.TLSConfig(cert)
	hs.StartTLS()
	t.Cleanup(hs.Close)
	root := x509.NewCertPool()
	root.AddCert(auth.Root.Cert)
	e := &env{t: t, srv: hs, s: s, root: root, dir: dir, keys: map[string]ed25519.PublicKey{kid: sk.Public().(ed25519.PublicKey)}}
	e.admin = e.client(nil)
	return e
}

// client returns a PQ TLS client, optionally presenting cert.
func (e *env) client(cert *tls.Certificate) *http.Client {
	cfg := pqsession.Harden(&tls.Config{RootCAs: e.root, ServerName: "localhost"})
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}, Timeout: 20 * time.Second}
}

func (e *env) do(c *http.Client, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) adminDo(method, path string, body any, want int) []byte {
	e.t.Helper()
	resp, b := e.do(e.admin, method, path, body, map[string]string{"Authorization": "Bearer " + testToken})
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: status %d want %d: %s", method, path, resp.StatusCode, want, b)
	}
	return b
}

// enroll creates a device key + CSR, enrolls and returns a client cert.
func (e *env) enroll(key string) (api.EnrollResponse, tls.Certificate) {
	e.t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	resp, b := e.do(e.admin, "POST", "/v1/enroll", api.EnrollRequest{ProvisioningKey: key, DeviceName: "pixel", Platform: "android", CSRPEM: string(csr)}, nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("enroll: %d %s", resp.StatusCode, b)
	}
	var er api.EnrollResponse
	if err := json.Unmarshal(b, &er); err != nil {
		e.t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	cert, err := tls.X509KeyPair([]byte(er.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
	if err != nil {
		e.t.Fatal(err)
	}
	return er, cert
}

func (e *env) edgeCert() tls.Certificate {
	c, err := tls.LoadX509KeyPair(filepath.Join(e.dir, pki.EdgeDir, pki.EdgeCertFile), filepath.Join(e.dir, pki.EdgeDir, pki.EdgeKeyFile))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func examplePolicy() api.TenantPolicy {
	return api.TenantPolicy{
		DefaultAction:  policy.ActionAllow,
		AllowUserRules: true,
		Rules: []policy.Rule{
			{ID: "no-smtp", Priority: 10, Action: policy.ActionBlock, Match: policy.Match{Protocols: []string{"tcp"}, Ports: []policy.PortRange{{From: 25}}}},
			{ID: "ask-test-net", Priority: 20, Action: policy.ActionAsk, Match: policy.Match{CIDRs: []string{"203.0.113.0/24"}}},
		},
		DNS:                policy.DNSPolicy{BlockResponse: "nxdomain", Blocklists: []policy.Blocklist{{ID: "ads", Name: "Ads", Category: "ads", Domains: []string{"*.doubleclick.net"}}}},
		DecideBlockDomains: []string{"bad.example"},
		DecideBlockCIDRs:   []string{"203.0.113.66/32"},
		DecideDefault:      policy.ActionAllow,
	}
}

func TestEndToEndAPI(t *testing.T) {
	e := newEnv(t)

	// Admin auth.
	if resp, _ := e.do(e.admin, "POST", "/v1/admin/tenants", api.AdminTenant{Name: "x"}, nil); resp.StatusCode != 401 {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	if resp, _ := e.do(e.admin, "POST", "/v1/admin/tenants", api.AdminTenant{Name: "x"}, map[string]string{"Authorization": "Bearer wrong"}); resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "acme", Name: "Acme"}, 201)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "acme", Name: "Acme"}, 409)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "../x", Name: "bad"}, 400)
	e.adminDo("POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u1", Email: "u1@acme", Name: "U1"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/nope/users", api.AdminUser{Email: "x"}, 404)
	e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "ghost"}, 404)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1, ValidFor: 3600}, 201), &pk)
	if !strings.HasPrefix(pk.Key, "osk_") {
		t.Fatalf("key %q", pk.Key)
	}
	bad := examplePolicy()
	bad.DecideDefault = policy.ActionAsk
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", bad, 400)
	bad = examplePolicy()
	bad.Rules[0].Match.CIDRs = []string{"nonsense"}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", bad, 400)
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", examplePolicy(), 204)

	// Enrollment; the key is single use.
	er, devCert := e.enroll(pk.Key)
	// The issued certificate verifies against CAPEM alone (no intermediates), as clients do it.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(er.CAPEM))
	if _, err := devCert.Leaf.Verify(x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("device cert vs CAPEM: %v", err)
	}
	if er.TenantID != "acme" || er.UserID != "u1" || len(er.Edges) != 1 || len(er.SnapshotKeys) != 1 {
		t.Fatalf("enroll response %+v", er)
	}
	if resp, _ := e.do(e.admin, "POST", "/v1/enroll", api.EnrollRequest{ProvisioningKey: pk.Key, DeviceName: "x", Platform: "linux", CSRPEM: "x"}, nil); resp.StatusCode != 400 {
		t.Fatalf("bad CSR: %d", resp.StatusCode)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if resp, _ := e.do(e.admin, "POST", "/v1/enroll", api.EnrollRequest{ProvisioningKey: pk.Key, DeviceName: "x", Platform: "linux", CSRPEM: csr}, nil); resp.StatusCode != 403 {
		t.Fatalf("reused key: %d", resp.StatusCode)
	}

	dev := e.client(&devCert)
	// Device routes need a device cert.
	if resp, _ := e.do(e.admin, "GET", "/v1/snapshot", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("snapshot without cert: %d", resp.StatusCode)
	}

	resp, body := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("snapshot: %d %s", resp.StatusCode, body)
	}
	var envl policy.Envelope
	_ = json.Unmarshal(body, &envl)
	snap, err := policy.Verify(&envl, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	tag := resp.Header.Get("ETag")
	if tag != etag(snap.Version) || snap.DeviceID != er.DeviceID || snap.Firewall.Rules[0].Source != policy.SourceTenant {
		t.Fatalf("snapshot %+v etag %s", snap, tag)
	}
	if d := snap.ExpiresAt.Sub(snap.IssuedAt); d != DefaultSnapshotTTL {
		t.Fatalf("ttl %v", d)
	}
	if resp, _ := e.do(dev, "GET", "/v1/snapshot", nil, map[string]string{"If-None-Match": tag}); resp.StatusCode != 304 {
		t.Fatalf("If-None-Match: %d", resp.StatusCode)
	}

	// Long-poll wakes up on a user rules change.
	type result struct {
		code int
		tag  string
	}
	done := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("GET", e.srv.URL+"/v1/snapshot?wait=30", nil)
		req.Header.Set("If-None-Match", tag)
		r, err := dev.Do(req)
		if err != nil {
			done <- result{}
			return
		}
		r.Body.Close()
		done <- result{r.StatusCode, r.Header.Get("ETag")}
	}()
	time.Sleep(200 * time.Millisecond)
	ur := api.UserRules{
		Rules: []policy.Rule{{ID: "u-block", Source: policy.SourceTenant, Priority: 1, Action: policy.ActionBlock, Match: policy.Match{CIDRs: []string{"198.51.100.0/24"}}}},
		Apps:  map[string]policy.AppPolicy{"com.example": {Cellular: policy.ActionBlock}},
	}
	resp, body = e.do(dev, "PUT", "/v1/self/rules", ur, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("self rules: %d %s", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &envl)
	snap2, err := policy.Verify(&envl, e.keys)
	if err != nil || snap2.Version <= snap.Version {
		t.Fatalf("new snapshot %v %v", snap2, err)
	}
	if r := snap2.Firewall.Rules[len(snap2.Firewall.Rules)-1]; r.ID != "u-block" || r.Source != policy.SourceUser {
		t.Fatalf("user rule not forced to user source: %+v", r)
	}
	select {
	case r := <-done:
		if r.code != 200 || r.tag != etag(snap2.Version) {
			t.Fatalf("long-poll result %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll did not wake")
	}

	// Decide never returns ask.
	tests := []struct {
		name   string
		flow   policy.Flow
		action policy.Action
		rule   string
		layer  string
	}{
		{"tenant block", policy.Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 25}, policy.ActionBlock, "no-smtp", "tenant"},
		{"user block", policy.Flow{Protocol: "tcp", DstIP: "198.51.100.9", DstPort: 443}, policy.ActionBlock, "u-block", "user"},
		{"ask cidr blocked", policy.Flow{Protocol: "tcp", DstIP: "203.0.113.66", DstPort: 443}, policy.ActionBlock, "decide:cidr", "cloud"},
		{"ask domain blocked", policy.Flow{Protocol: "tcp", DstIP: "203.0.113.5", DstPort: 443, Domain: "bad.example"}, policy.ActionBlock, "decide:domain", "cloud"},
		{"ask default", policy.Flow{Protocol: "tcp", DstIP: "203.0.113.5", DstPort: 443}, policy.ActionAllow, "decide:default", "cloud"},
		{"default allow", policy.Flow{Protocol: "udp", DstIP: "8.8.8.8", DstPort: 53}, policy.ActionAllow, "", "default"},
	}
	for _, tc := range tests {
		resp, body := e.do(dev, "POST", "/v1/decide", api.DecideRequest{Flow: tc.flow}, nil)
		var dr api.DecideResponse
		_ = json.Unmarshal(body, &dr)
		if resp.StatusCode != 200 || dr.Decision.Action != tc.action || dr.Decision.RuleID != tc.rule || dr.Decision.Layer != tc.layer || dr.TTL != DecideTTL {
			t.Errorf("%s: %d %+v", tc.name, resp.StatusCode, dr)
		}
	}

	// Flows.
	if resp, _ := e.do(dev, "POST", "/v1/flows", api.FlowBatch{Records: []api.FlowRecord{{Start: time.Now(), DeviceID: "spoofed", Flow: policy.Flow{Protocol: "tcp", DstIP: "9.9.9.9", DstPort: 443}}}}, nil); resp.StatusCode != 202 {
		t.Fatalf("flows: %d", resp.StatusCode)
	}
	var fb api.FlowBatch
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/flows?limit=100", nil, 200), &fb)
	if len(fb.Records) != len(tests)+1 || fb.Records[0].DeviceID != er.DeviceID || fb.Records[0].Where != "device" || fb.Records[1].Where != "cloud" {
		t.Fatalf("flows %+v", fb.Records)
	}

	// Edge routes: the edge cert is accepted only once edge-1 is registered.
	ec := e.edgeCert()
	edge := e.client(&ec)
	if resp, _ := e.do(edge, "GET", "/v1/edge/peers", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("unregistered edge: %d", resp.StatusCode)
	}
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 409)
	if resp, _ := e.do(dev, "GET", "/v1/edge/peers", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("device on edge route: %d", resp.StatusCode)
	}
	if resp, _ := e.do(edge, "GET", "/v1/snapshot", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("edge on device route: %d", resp.StatusCode)
	}
	var peers api.EdgePeers
	resp, body = e.do(edge, "GET", "/v1/edge/peers", nil, nil)
	_ = json.Unmarshal(body, &peers)
	if resp.StatusCode != 200 || len(peers.Devices) != 1 || peers.Devices[0].DeviceID != er.DeviceID {
		t.Fatalf("peers %d %+v", resp.StatusCode, peers)
	}
	if s, err := policy.Verify(&peers.Devices[0].Snapshot, e.keys); err != nil || s.Version != snap2.Version {
		t.Fatalf("peer snapshot %v %v", s, err)
	}
	// Edge decides on behalf of a device (edgeMode), only once it reported a live session.
	ask := api.DecideRequest{Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.66", DstPort: 443}}
	if resp, _ := e.do(edge, "POST", "/v1/decide?device="+er.DeviceID, ask, nil); resp.StatusCode != 403 {
		t.Fatalf("edge decide without session: %d", resp.StatusCode)
	}
	if resp, _ := e.do(edge, "POST", "/v1/edge/sessions", EdgeSessions{DeviceIDs: []string{er.DeviceID}}, nil); resp.StatusCode != 204 {
		t.Fatalf("edge sessions: %d", resp.StatusCode)
	}
	resp, body = e.do(edge, "POST", "/v1/decide?device="+er.DeviceID, api.DecideRequest{Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.66", DstPort: 443}}, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "decide:cidr") {
		t.Fatalf("edge decide %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.do(edge, "POST", "/v1/flows", api.FlowBatch{Records: []api.FlowRecord{{Start: time.Now(), DeviceID: er.DeviceID}, {DeviceID: "ghost"}}}, nil); resp.StatusCode != 202 {
		t.Fatalf("edge flows: %d", resp.StatusCode)
	}
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/flows?limit=1", nil, 200), &fb)
	if len(fb.Records) != 1 || fb.Records[0].Where != "edge" {
		t.Fatalf("edge flow %+v", fb.Records)
	}

	// User rules disabled by the tenant: 403, and existing user rules leave the snapshot.
	p := examplePolicy()
	p.AllowUserRules = false
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)
	if resp, _ := e.do(dev, "PUT", "/v1/self/rules", ur, nil); resp.StatusCode != 403 {
		t.Fatalf("self rules disallowed: %d", resp.StatusCode)
	}
	_, body = e.do(dev, "GET", "/v1/snapshot", nil, nil)
	_ = json.Unmarshal(body, &envl)
	snap3, _ := policy.Verify(&envl, e.keys)
	for _, r := range snap3.Firewall.Rules {
		if r.Source == policy.SourceUser {
			t.Fatal("user rule survived AllowUserRules=false")
		}
	}
	if _, ok := snap3.Firewall.Apps["com.example"]; ok {
		t.Fatal("user app policy survived AllowUserRules=false")
	}

	// Revocation.
	e.adminDo("POST", "/v1/admin/tenants/acme/devices/"+er.DeviceID+"/revoke", nil, 204)
	if resp, _ := e.do(dev, "GET", "/v1/snapshot", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("revoked device: %d", resp.StatusCode)
	}
	_, body = e.do(edge, "GET", "/v1/edge/peers", nil, nil)
	_ = json.Unmarshal(body, &peers)
	if len(peers.Devices) != 0 {
		t.Fatal("revoked device still a peer")
	}

	// PKI bundle (no auth) lists root + tenant CA.
	var bundle api.PKIBundle
	_, body = e.do(e.admin, "GET", "/v1/pki/ca", nil, nil)
	_ = json.Unmarshal(body, &bundle)
	if certs, err := pki.ParseCertsPEM([]byte(bundle.CAPEM)); err != nil || len(certs) != 2 || len(bundle.SnapshotKeys) != 1 {
		t.Fatalf("bundle: %v", err)
	}
}

func TestClassicTLSRejected(t *testing.T) {
	e := newEnv(t)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: e.root, ServerName: "localhost", CurvePreferences: []tls.CurveID{tls.X25519},
	}}}
	if _, err := c.Get(e.srv.URL + "/v1/pki/ca"); err == nil {
		t.Fatal("classic X25519-only handshake succeeded")
	}
	resp, _ := e.do(e.admin, "GET", "/v1/pki/ca", nil, nil)
	if resp.TLS == nil || resp.TLS.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %v", resp.TLS.CurveID)
	}
}

func TestMergeLayers(t *testing.T) {
	tp := api.TenantPolicy{
		Rules: []policy.Rule{{ID: "t1", Source: policy.SourceUser, Action: policy.ActionBlock}},
		Apps:  map[string]policy.AppPolicy{"a": {WiFi: policy.ActionBlock}, "b": {WiFi: policy.ActionAllow}},
	}
	ur := &api.UserRules{
		Rules: []policy.Rule{{ID: "u1", Source: policy.SourceTenant, Action: policy.ActionAllow}},
		Apps:  map[string]policy.AppPolicy{"a": {WiFi: policy.ActionAllow}, "c": {Cellular: policy.ActionBlock}},
	}
	tests := []struct {
		name       string
		allowUser  bool
		ur         *api.UserRules
		rules      []string
		appA       policy.Action
		hasC       bool
		defaultAct policy.Action
	}{
		{"user disallowed", false, ur, []string{"t1:tenant"}, policy.ActionBlock, false, policy.ActionBlock},
		// D1: the tenant entry for "a" is mandatory; the user may only add "c".
		{"user allowed", true, ur, []string{"t1:tenant", "u1:user"}, policy.ActionBlock, true, policy.ActionBlock},
		{"no user layer", true, nil, []string{"t1:tenant"}, policy.ActionBlock, false, policy.ActionBlock},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tp
			p.AllowUserRules = tc.allowUser
			fw, dns := MergeLayers(p, tc.ur)
			var got []string
			for _, r := range fw.Rules {
				got = append(got, r.ID+":"+string(r.Source))
			}
			if strings.Join(got, ",") != strings.Join(tc.rules, ",") {
				t.Errorf("rules %v want %v", got, tc.rules)
			}
			if fw.Apps["a"].WiFi != tc.appA {
				t.Errorf("app a = %v", fw.Apps["a"].WiFi)
			}
			if _, ok := fw.Apps["c"]; ok != tc.hasC {
				t.Errorf("app c present = %v", ok)
			}
			if fw.Apps["b"].WiFi != policy.ActionAllow {
				t.Error("tenant app b lost")
			}
			if got := strings.Join(fw.TenantApps, ","); got != "a,b" {
				t.Errorf("TenantApps = %q, want a,b (user app c must not be listed)", got)
			}
			if fw.DefaultAction != tc.defaultAct || dns.BlockResponse != "nxdomain" {
				t.Errorf("default %v dns %v", fw.DefaultAction, dns.BlockResponse)
			}
		})
	}
	// The tenant's map is not mutated by the merge.
	if tp.Apps["a"].WiFi != policy.ActionBlock {
		t.Fatal("tenant apps mutated")
	}
}

func TestExamplePolicyValid(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/dev/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var tp api.TenantPolicy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tp); err != nil {
		t.Fatal(err)
	}
	if err := validateTenantPolicy(tp); err != nil {
		t.Fatal(err)
	}
	fw, dns := MergeLayers(tp, nil)
	c, err := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "t", DeviceID: "d", Firewall: fw, DNS: dns})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Evaluate(policy.Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 25}, true); d.Action != policy.ActionBlock {
		t.Fatalf("port 25: %+v", d)
	}
	if b, _ := c.EvaluateDNS("ad.doubleclick.net"); !b {
		t.Fatal("doubleclick not blocked")
	}
	if d := c.Evaluate(policy.Flow{Protocol: "tcp", DstIP: "203.0.113.9", DstPort: 443}, true); d.Action != policy.ActionAsk {
		t.Fatalf("ask rule: %+v", d)
	}
}

func TestSelfRulesValidationAndChain(t *testing.T) {
	e := newEnv(t)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "acme", Name: "Acme"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u1", Email: "u1@acme"}, 201)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1"}, 201), &pk)

	// Field-level 400s on the tenant policy.
	fieldOf := func(b []byte) string {
		var eb errorBody
		_ = json.Unmarshal(b, &eb)
		return eb.Field
	}
	tests := []struct {
		name  string
		mod   func(*api.TenantPolicy)
		field string
	}{
		{"bad cidr", func(p *api.TenantPolicy) { p.Rules[1].Match.CIDRs = []string{"nope"} }, "rules[1].match.cidrs[0]"},
		{"bad blocklist domain", func(p *api.TenantPolicy) { p.DNS.Blocklists[0].Domains = []string{"bad domain"} }, "dns.blocklists[0].domains[0]"},
		{"bad decide domain", func(p *api.TenantPolicy) { p.DecideBlockDomains = []string{"*."} }, "decideBlockDomains[0]"},
		{"bad decide cidr", func(p *api.TenantPolicy) { p.DecideBlockCIDRs = []string{"x"} }, "decideBlockCidrs[0]"},
		{"bad default", func(p *api.TenantPolicy) { p.DefaultAction = "maybe" }, "defaultAction"},
	}
	for _, tc := range tests {
		p := examplePolicy()
		tc.mod(&p)
		if got := fieldOf(e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 400)); got != tc.field {
			t.Errorf("%s: field %q want %q", tc.name, got, tc.field)
		}
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", examplePolicy(), 204)

	_, cert := e.enroll(pk.Key)
	dev := e.client(&cert)
	resp, body := e.do(dev, "GET", "/v1/self/rules", nil, nil)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != `{"rules":[],"apps":{}}` {
		t.Fatalf("empty self rules: %d %s", resp.StatusCode, body)
	}
	bad := api.UserRules{Rules: []policy.Rule{{ID: "ok", Action: policy.ActionAllow}, {ID: "x", Action: policy.ActionBlock, Match: policy.Match{Domains: []string{"bad domain"}}}}}
	resp, body = e.do(dev, "PUT", "/v1/self/rules", bad, nil)
	if resp.StatusCode != 400 || !strings.HasPrefix(fieldOf(body), "rules[1].match.domains") {
		t.Fatalf("bad user rule: %d %s", resp.StatusCode, body)
	}
	ur := api.UserRules{Rules: []policy.Rule{{ID: "mine", Action: policy.ActionBlock, Match: policy.Match{Ports: []policy.PortRange{{From: 8080}}}}}, Apps: map[string]policy.AppPolicy{"com.a": {WiFi: policy.ActionBlock}}}
	if resp, _ := e.do(dev, "PUT", "/v1/self/rules", ur, nil); resp.StatusCode != 200 {
		t.Fatalf("put: %d", resp.StatusCode)
	}
	resp, body = e.do(dev, "GET", "/v1/self/rules", nil, nil)
	var got api.UserRules
	_ = json.Unmarshal(body, &got)
	if resp.StatusCode != 200 || len(got.Rules) != 1 || got.Rules[0].Source != policy.SourceUser || got.Apps["com.a"].WiFi != policy.ActionBlock {
		t.Fatalf("self rules %+v", got)
	}

	// The server chain includes the root, so a "#sha256=" pin of the root can match.
	if n := len(resp.TLS.PeerCertificates); n != 2 || !resp.TLS.PeerCertificates[1].IsCA {
		t.Fatalf("server sent %d certificates", n)
	}
}
