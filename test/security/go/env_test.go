package securitytest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// env describes the dev stack under test. Everything comes from deploy/dev and the
// environment; nothing secret is ever printed.
type env struct {
	devDir    string // deploy/dev
	cpURL     string // https://localhost:9443
	edgeURL   string // https://localhost:8443
	broker    string // localhost:8444
	wgAddr    string // 127.0.0.1:51820
	edgeID    string // the dev Edge's ID (edge-1)
	token     string // admin token (from .env, never printed)
	root      *x509.Certificate
	rootPool  *x509.CertPool
	serverSNI string
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadEnv() (*env, error) {
	dir := getenv("SECTEST_DEV_DIR", filepath.Join("..", "..", "..", "deploy", "dev"))
	e := &env{
		devDir:    dir,
		cpURL:     getenv("SECTEST_CP_URL", "https://localhost:9443"),
		edgeURL:   getenv("SECTEST_EDGE_URL", "https://localhost:8443"),
		broker:    getenv("SECTEST_BROKER", "localhost:8444"),
		wgAddr:    getenv("SECTEST_WG", "127.0.0.1:51820"),
		edgeID:    getenv("SECTEST_EDGE_ID", "edge-1"),
		serverSNI: "localhost",
	}
	f, err := os.Open(filepath.Join(dir, ".env")) //nolint:gosec // G304: dev stack config
	if err != nil {
		return nil, fmt.Errorf("read deploy/dev/.env (run deploy/dev/bootstrap.sh): %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "OPENSASE_ADMIN_TOKEN="); ok {
			e.token = v
		}
	}
	if e.token == "" {
		return nil, errors.New("no OPENSASE_ADMIN_TOKEN in deploy/dev/.env")
	}
	b, err := os.ReadFile(filepath.Join(dir, "pki", pki.RootCertFile)) //nolint:gosec // G304: dev PKI
	if err != nil {
		return nil, err
	}
	certs, err := pki.ParseCertsPEM(b)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("parse root.crt: %w", err)
	}
	e.root = certs[0]
	e.rootPool = x509.NewCertPool()
	e.rootPool.AddCert(e.root)
	return e, nil
}

// rootCA loads the provider root CA with its key. The harness uses it only to issue Edge
// certificates for its own sectest Edges, exactly as `opensasectl pki` would.
func (e *env) rootCA() (*pki.CA, error) {
	return pki.LoadCA(filepath.Join(e.devDir, "pki", pki.RootCertFile), filepath.Join(e.devDir, "pki", pki.RootKeyFile))
}

// tenantCA loads a sectest tenant's intermediate CA (created by the Control Plane).
func (e *env) tenantCA(t string) (*pki.CA, error) {
	d := filepath.Join(e.devDir, "pki", pki.TenantsDir, t)
	return pki.LoadCA(filepath.Join(d, "ca.crt"), filepath.Join(d, "ca.key"))
}

// --- HTTP over PQ TLS ---

// clientTLS is a hardened client config that checks the server SPIFFE identity.
func (e *env) clientTLS(certs []tls.Certificate, kind, id string) *tls.Config {
	c := pqsession.Harden(&tls.Config{RootCAs: e.rootPool, Certificates: certs, ServerName: e.serverSNI})
	c.VerifyConnection = pki.ExpectServer(kind, id)
	return c
}

func httpClient(c *tls.Config) *http.Client {
	return &http.Client{
		Timeout: 70 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   c,
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,
		},
	}
}

// resp is a minimal HTTP result. code is 0 when no HTTP response arrived (handshake error).
type resp struct {
	code int
	body []byte
	hdr  http.Header
	tls  *tls.ConnectionState
	err  error
}

func (r resp) String() string {
	if r.err != nil {
		return "transport error: " + r.err.Error()
	}
	b := r.body
	if len(b) > 200 {
		b = b[:200]
	}
	return fmt.Sprintf("HTTP %d %s", r.code, bytes.TrimSpace(b))
}

func do(c *http.Client, method, url string, body any, hdr map[string]string) resp {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return resp{err: err}
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, url, rd) //nolint:noctx // client has a timeout
	if err != nil {
		return resp{err: err}
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := c.Do(req)
	if err != nil {
		return resp{err: err}
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	return resp{code: r.StatusCode, body: b, hdr: r.Header, tls: r.TLS}
}

// anon is a CP client without a client certificate.
func (e *env) anon() *http.Client { return httpClient(e.clientTLS(nil, pki.ServerControlPlane, "")) }

// cp is a CP client presenting cert.
func (e *env) cp(cert tls.Certificate) *http.Client {
	return httpClient(e.clientTLS([]tls.Certificate{cert}, pki.ServerControlPlane, ""))
}

// edge is an Edge session-channel client presenting cert.
func (e *env) edge(cert tls.Certificate) *http.Client {
	return httpClient(e.clientTLS([]tls.Certificate{cert}, pki.ServerEdge, e.edgeID))
}

// admin calls the admin API with the real token.
func (e *env) admin(method, path string, body any) resp {
	return do(e.anon(), method, e.cpURL+"/v1/admin"+path, body, map[string]string{"Authorization": "Bearer " + e.token})
}

func decode[T any](r resp) (T, error) {
	var v T
	if r.err != nil {
		return v, r.err
	}
	if r.code/100 != 2 {
		return v, fmt.Errorf("unexpected %s", r)
	}
	return v, json.Unmarshal(r.body, &v)
}

// --- identities ---

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func csrPEM(k *ecdsa.PrivateKey) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sectest"}}, k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// tlsCert builds a tls.Certificate from a PEM chain (leaf first) and key.
func tlsCert(chainPEM []byte, k *ecdsa.PrivateKey) (tls.Certificate, error) {
	certs, err := pki.ParseCertsPEM(chainPEM)
	if err != nil || len(certs) == 0 {
		return tls.Certificate{}, fmt.Errorf("parse chain: %w", err)
	}
	c := tls.Certificate{PrivateKey: k, Leaf: certs[0]}
	for _, x := range certs {
		if x.IsCA && x.CheckSignatureFrom(x) == nil {
			continue // drop a self-signed root if present
		}
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c, nil
}

// ident is an enrolled device or connector.
type ident struct {
	id, tenant string
	key        *ecdsa.PrivateKey
	cert       tls.Certificate
}

func (e *env) enrollDevice(tenant, user, name string) (*ident, error) {
	pk, err := decode[api.ProvisioningKey](e.admin("POST", "/tenants/"+tenant+"/provisioning-keys", api.ProvisioningKeyRequest{UserID: user, MaxUses: 1, ValidFor: 600}))
	if err != nil {
		return nil, fmt.Errorf("provisioning key: %w", err)
	}
	k := newKey()
	er, err := decode[api.EnrollResponse](do(e.anon(), "POST", e.cpURL+"/v1/enroll", api.EnrollRequest{ProvisioningKey: pk.Key, DeviceName: name, Platform: "linux", CSRPEM: csrPEM(k)}, nil))
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	c, err := tlsCert([]byte(er.CertificatePEM), k)
	if err != nil {
		return nil, err
	}
	return &ident{id: er.DeviceID, tenant: er.TenantID, key: k, cert: c}, nil
}

func (e *env) enrollConnector(tenant, name string) (*ident, error) {
	cr, err := decode[api.AdminConnectorCreated](e.admin("POST", "/tenants/"+tenant+"/connectors", api.AdminConnectorRequest{Name: name, Group: "default"}))
	if err != nil {
		return nil, fmt.Errorf("create connector: %w", err)
	}
	k := newKey()
	er, err := decode[api.ConnectorEnrollResponse](do(e.anon(), "POST", e.cpURL+"/v1/connector/enroll", api.ConnectorEnrollRequest{ProvisioningKey: cr.ProvisioningKey, CSRPEM: csrPEM(k)}, nil))
	if err != nil {
		return nil, fmt.Errorf("connector enroll: %w", err)
	}
	c, err := tlsCert([]byte(er.CertificatePEM), k)
	if err != nil {
		return nil, err
	}
	return &ident{id: er.ConnectorID, tenant: er.TenantID, key: k, cert: c}, nil
}

// newEdge issues an Edge certificate for id from the root CA and registers the edge
// (tenant "" = public Edge, else a Private Edge bound to tenant).
func (e *env) newEdge(id, tenant string) (tls.Certificate, error) {
	ca, err := e.rootCA()
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, keyPEM, err := ca.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindEdge, ID: id, DNSNames: []string{"localhost"}})
	if err != nil {
		return tls.Certificate{}, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if r := e.admin("POST", "/edges", api.AdminEdge{ID: id, TenantID: tenant}); r.code != http.StatusCreated {
		return tls.Certificate{}, fmt.Errorf("register edge: %s", r)
	}
	return c, nil
}

// --- fixture: two dedicated tenants, created once per run ---

type fixture struct {
	*env
	run              string
	tA, tB           string // tenant IDs
	uA, uB           string // user IDs
	devA1, devA2     *ident
	devA3            *ident // spare device for destructive checks (revocation, renewal)
	devB1            *ident
	connA, connB     *ident
	connA2           *ident // spare connector for the revocation check
	pubEdge, privEdg string // edge IDs
	pubEdgeCert      tls.Certificate
	privEdgeCert     tls.Certificate // Private Edge bound to tenant A
	appA, appB       string          // private app domains
}

const askNet = "198.51.100.0/24"

func marker(run, tenant, what string) string {
	return what + "-" + tenant + "-" + run + ".sectest.test"
}

func tenantPolicy(run, label, app string) api.TenantPolicy {
	return api.TenantPolicy{
		DefaultAction:  policy.ActionAllow,
		AllowUserRules: true,
		Rules: []policy.Rule{{
			ID: "sectest-block-smtp-" + label, Priority: 10, Action: policy.ActionBlock, Log: true,
			Match: policy.Match{Protocols: []string{"tcp"}, Ports: []policy.PortRange{{From: 25}}},
		}, {
			// TEST-NET-2 is decided by the cloud (POST /v1/decide), so cloud-only data is used.
			ID: "sectest-ask-" + label, Priority: 20, Action: policy.ActionAsk, Log: true,
			Match: policy.Match{CIDRs: []string{askNet}},
		}},
		DNS: policy.DNSPolicy{BlockResponse: "nxdomain", BlockDomains: []string{marker(run, label, "dnsblock")}},
		PrivateApps: []api.TenantPrivateApp{{PrivateApp: policy.PrivateApp{
			ID: "app-" + label, Name: "sectest app " + label, Domains: []string{app},
			Ports: []policy.PortRange{{From: 80}}, ConnectorGroup: "default",
		}}},
		DecideBlockDomains: []string{marker(run, label, "decideblock")},
		DecideDefault:      policy.ActionAllow,
	}
}

var (
	fxOnce sync.Once
	fx     *fixture
	fxErr  error
)

// stack returns the shared fixture, skipping the test unless OPENSASE_SECTEST=1.
func stack(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("OPENSASE_SECTEST") != "1" {
		t.Skip("stack test: set OPENSASE_SECTEST=1 with the dev stack running (make sectest)")
	}
	fxOnce.Do(func() { fx, fxErr = setup() })
	if fxErr != nil {
		t.Fatalf("fixture: %v", fxErr)
	}
	return fx
}

func setup() (*fixture, error) {
	e, err := loadEnv()
	if err != nil {
		return nil, err
	}
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)
	run := hex.EncodeToString(rb)
	f := &fixture{env: e, run: run, tA: "sectest-" + run + "-a", tB: "sectest-" + run + "-b"}
	f.appA, f.appB = "app-a-"+run+".sectest.internal", "app-b-"+run+".sectest.internal"
	for _, x := range []struct{ t, label, app string }{{f.tA, "a", f.appA}, {f.tB, "b", f.appB}} {
		if r := e.admin("POST", "/tenants", api.AdminTenant{ID: x.t, Name: "sectest " + x.label}); r.code != http.StatusCreated {
			return nil, fmt.Errorf("create tenant: %s", r)
		}
		u, err := decode[api.AdminUser](e.admin("POST", "/tenants/"+x.t+"/users", api.AdminUser{ID: "user-" + run + "-" + x.label, Email: "user-" + x.label + "@sectest.test"}))
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		if x.label == "a" {
			f.uA = u.ID
		} else {
			f.uB = u.ID
		}
		if r := e.admin("PUT", "/tenants/"+x.t+"/policy", tenantPolicy(run, x.label, x.app)); r.code != http.StatusNoContent {
			return nil, fmt.Errorf("put policy: %s", r)
		}
	}
	for _, d := range []struct {
		dst          **ident
		tenant, user string
	}{{&f.devA1, f.tA, f.uA}, {&f.devA2, f.tA, f.uA}, {&f.devA3, f.tA, f.uA}, {&f.devB1, f.tB, f.uB}} {
		if *d.dst, err = e.enrollDevice(d.tenant, d.user, "sectest-dev"); err != nil {
			return nil, err
		}
	}
	for _, c := range []struct {
		dst    **ident
		tenant string
	}{{&f.connA, f.tA}, {&f.connA2, f.tA}, {&f.connB, f.tB}} {
		if *c.dst, err = e.enrollConnector(c.tenant, "sectest-conn"); err != nil {
			return nil, err
		}
	}
	f.pubEdge, f.privEdg = "sectest-"+run+"-pub", "sectest-"+run+"-priv"
	if f.pubEdgeCert, err = e.newEdge(f.pubEdge, ""); err != nil {
		return nil, err
	}
	if f.privEdgeCert, err = e.newEdge(f.privEdg, f.tA); err != nil {
		return nil, err
	}
	return f, nil
}

// teardown revokes every identity the run created. Tenants cannot be deleted through the
// API (see the report); they stay, empty of live credentials, named sectest-<run>-*.
func teardown() {
	if fx == nil {
		return
	}
	for _, d := range []*ident{fx.devA1, fx.devA2, fx.devA3, fx.devB1} {
		if d != nil {
			fx.admin("POST", "/tenants/"+d.tenant+"/devices/"+d.id+"/revoke", nil)
		}
	}
	for _, c := range []*ident{fx.connA, fx.connA2, fx.connB} {
		if c != nil {
			fx.admin("POST", "/tenants/"+c.tenant+"/connectors/"+c.id+"/revoke", nil)
		}
	}
	for _, id := range []string{fx.pubEdge, fx.privEdg} {
		if id != "" {
			fx.admin("POST", "/edges/"+id+"/revoke", nil)
		}
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	teardown()
	os.Exit(code)
}

// want returns nil when r has one of the codes, else an error naming what came back.
func want(r resp, what string, codes ...int) error {
	for _, c := range codes {
		if r.code == c {
			return nil
		}
	}
	return fmt.Errorf("%s: got %s, want %v", what, r, codes)
}

// refused returns nil when r is a transport failure (handshake refused) or one of codes.
func refused(r resp, what string, codes ...int) error {
	if r.err != nil {
		return nil
	}
	return want(r, what, codes...)
}

// session posts a fresh epoch-0 session request to the Edge with cert.
func (e *env) session(cert tls.Certificate) resp {
	return do(e.edge(cert), "POST", e.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":0}`, nil)
}

// edgeDenied is nil when the Edge refused: handshake failure, 401 or 403. Any other
// answer (200, but also 5xx/409) is reported, so a broken test cannot pass.
func edgeDenied(r resp, what string) error {
	if r.err != nil || r.code == http.StatusForbidden || r.code == http.StatusUnauthorized {
		return nil
	}
	if r.code == http.StatusOK {
		return fmt.Errorf("%s: edge set up a session (%s)", what, r)
	}
	return fmt.Errorf("%s: inconclusive, want 401/403: %s", what, r)
}
