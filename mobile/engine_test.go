package mobile

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// testPKI is a throwaway tenant CA.
type testPKI struct {
	caKey  *ecdsa.PrivateKey
	ca     *x509.Certificate
	caPEM  string
	serial atomic.Int64
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test tenant CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{caKey: k, ca: ca, caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	p.serial.Store(1)
	return p
}

func (p *testPKI) issue(t *testing.T, pub any, cn string, server bool, uri *url.URL) []byte {
	return p.issueFor(t, pub, cn, server, uri, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func (p *testPKI) issueFor(t *testing.T, pub any, cn string, server bool, uri *url.URL, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if uri != nil {
		tmpl.URIs = []*url.URL{uri}
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (p *testPKI) serverCert(t *testing.T, uri *url.URL) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := p.issue(t, &k.PublicKey, "server", true, uri)
	return tls.Certificate{Certificate: [][]byte{der, p.ca.Raw}, PrivateKey: k}
}

func (p *testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}

// startTLS serves h with a server certificate carrying uri as its SPIFFE identity.
func startTLS(t *testing.T, p *testPKI, h http.Handler, hardened bool, uri *url.URL) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{p.serverCert(t, uri)},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    p.pool(),
	}
	if hardened {
		pqsession.Harden(cfg)
	} else {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519} // classic only
	}
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// fakeCloud is a Control Plane + one Edge.
type fakeCloud struct {
	t       *testing.T
	pki     *testPKI
	signKey ed25519.PrivateKey
	cp      *httptest.Server
	edge    *httptest.Server

	mu       sync.Mutex
	snap     *policy.Snapshot
	updated  chan struct{}
	flows    []api.FlowRecord
	probes   []api.ExperienceSample
	flowFail int
	psks     map[uint64][32]byte // epoch -> PSK derived by the Edge
	rotate   int
	userPuts int

	certFrom, certTo time.Duration // device cert validity relative to issue time
	renewals         int
	renewFail        int                          // fail this many renew calls with 500
	renewMutate      func(*api.RenewResponse)     // tamper with the renew response
	lastClient       map[string]*x509.Certificate // path -> last client cert seen
	sessions0        int                          // epoch-0 session setups
	rotationMode     string                       // "", "409", "lost"
	extraKeys        []api.SigningKey             // served by /v1/pki/ca in addition to k1

	edge2     *httptest.Server      // second Edge (issue #70), listed after edge-1
	down      map[string]bool       // Edge ID -> answers 503 to everything
	forgotten map[string]bool       // Edge ID -> probes answer 404 (restarted, session lost)
	lastEdge  string                // Edge of the last epoch-0 session
	edgesFn   func() []api.EdgeInfo // GET /v1/edges (issue #71); nil: the enrolment list
}

const (
	testTenant = "t1"
	testDevice = "dev-1"
	testKeyID  = "k1"
)

func newFakeCloud(t *testing.T) *fakeCloud {
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	fc := &fakeCloud{t: t, pki: newPKI(t), signKey: sk, updated: make(chan struct{}), psks: map[uint64][32]byte{}, rotate: 600,
		certFrom: -time.Minute, certTo: time.Hour, lastClient: map[string]*x509.Certificate{}}
	fc.snap = &policy.Snapshot{
		SchemaVersion: 1, Version: 1, TenantID: testTenant, DeviceID: testDevice,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Firewall: policy.FirewallPolicy{
			DefaultAction: policy.ActionAllow,
			Rules: []policy.Rule{{ID: "no-8080", Source: policy.SourceTenant, Priority: 1, Action: policy.ActionBlock,
				Match: policy.Match{Ports: []policy.PortRange{{From: 8080}}}}},
		},
		DNS: policy.DNSPolicy{BlockResponse: "nxdomain"},
	}
	cpMux := http.NewServeMux()
	cpMux.HandleFunc("POST /v1/enroll", fc.enroll)
	cpMux.HandleFunc("GET /v1/snapshot", fc.requireCert(fc.snapshot))
	cpMux.HandleFunc("POST /v1/flows", fc.requireCert(fc.postFlows))
	cpMux.HandleFunc("PUT /v1/self/rules", fc.requireCert(fc.putRules))
	cpMux.HandleFunc("POST /v1/decide", fc.requireCert(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.DecideResponse{Decision: policy.Decision{Action: policy.ActionAllow}, TTL: 60})
	}))
	cpMux.HandleFunc("POST /v1/renew", fc.requireCert(fc.renew))
	cpMux.HandleFunc("GET /v1/pki/ca", fc.requireCert(fc.pkiCA))
	cpMux.HandleFunc("GET /v1/edges", fc.requireCert(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		fn := fc.edgesFn
		fc.mu.Unlock()
		edges := fc.edgeInfos()
		if fn != nil {
			edges = fn()
		}
		json.NewEncoder(w).Encode(api.DeviceEdges{Edges: edges})
	}))
	fc.cp = startTLS(t, fc.pki, cpMux, true, pki.ControlPlaneURI())
	fc.down, fc.forgotten = map[string]bool{}, map[string]bool{}
	fc.edge = startTLS(t, fc.pki, fc.edgeMux("edge-1"), true, pki.EdgeURI("edge-1"))
	fc.edge2 = startTLS(t, fc.pki, fc.edgeMux("edge-2"), true, pki.EdgeURI("edge-2"))
	return fc
}

// edgeInfos lists both fake Edges, edge-1 first.
func (fc *fakeCloud) edgeInfos() []api.EdgeInfo {
	return []api.EdgeInfo{
		{ID: "edge-1", Region: "test", SessionURL: fc.edge.URL, WGEndpoint: "127.0.0.1:1", WGPublicKey: base64.StdEncoding.EncodeToString(edgeWGPub(fc.t))},
		{ID: "edge-2", Region: "test", SessionURL: fc.edge2.URL, WGEndpoint: "127.0.0.1:1", WGPublicKey: base64.StdEncoding.EncodeToString(edgeWGPub(fc.t))},
	}
}

// edgeMux serves one fake Edge: session setup and the session probe (issue #70).
func (fc *fakeCloud) edgeMux(id string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/session", fc.requireCert(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		fc.lastEdge = id
		fc.forgotten[id] = false
		fc.mu.Unlock()
		fc.session(w, r)
	}))
	mux.HandleFunc("GET /v1/session/{sid}", fc.requireCert(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		gone := fc.forgotten[id]
		fc.mu.Unlock()
		if gone {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		dead := fc.down[id]
		fc.mu.Unlock()
		if dead {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// deviceCert issues a device certificate for pub with the configured validity.
func (fc *fakeCloud) deviceCert(pub any) []byte {
	fc.mu.Lock()
	from, to := fc.certFrom, fc.certTo
	fc.mu.Unlock()
	now := time.Now()
	return fc.pki.issueFor(fc.t, pub, testDevice, false, pki.DeviceURI(testTenant, testDevice), now.Add(from), now.Add(to))
}

func (fc *fakeCloud) renew(w http.ResponseWriter, r *http.Request) {
	var req api.RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fc.mu.Lock()
	fail := fc.renewFail > 0
	if fail {
		fc.renewFail--
	}
	mut := fc.renewMutate
	fc.mu.Unlock()
	if fail {
		http.Error(w, "try later", http.StatusInternalServerError)
		return
	}
	blk, _ := pem.Decode([]byte(req.CSRPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	if old := r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey); old.Equal(csr.PublicKey) {
		http.Error(w, "renewal must use a new key", http.StatusBadRequest)
		return
	}
	resp := api.RenewResponse{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fc.deviceCert(csr.PublicKey)})) + fc.pki.caPEM,
		CAPEM:          fc.pki.caPEM,
	}
	if mut != nil {
		mut(&resp)
	}
	fc.mu.Lock()
	fc.renewals++
	fc.mu.Unlock()
	json.NewEncoder(w).Encode(resp)
}

func (fc *fakeCloud) pkiCA(w http.ResponseWriter, r *http.Request) {
	fc.mu.Lock()
	keys := append([]api.SigningKey{{KeyID: testKeyID, Algorithm: policy.AlgEd25519, PublicKey: fc.signKey.Public().(ed25519.PublicKey)}}, fc.extraKeys...)
	fc.mu.Unlock()
	json.NewEncoder(w).Encode(api.PKIBundle{CAPEM: fc.pki.caPEM, SnapshotKeys: keys})
}

func (fc *fakeCloud) clientCert(path string) *x509.Certificate {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.lastClient[path]
}

var edgeWGPriv = func() []byte { b := make([]byte, 32); b[0] = 7; return b }()

func edgeWGPub(t *testing.T) []byte {
	k, err := ecdhX25519(edgeWGPriv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (fc *fakeCloud) requireCert(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if err := pqsession.CheckPostQuantum(*r.TLS); err != nil {
			http.Error(w, err.Error(), http.StatusUpgradeRequired)
			return
		}
		fc.mu.Lock()
		fc.lastClient[r.URL.Path] = r.TLS.PeerCertificates[0]
		fc.mu.Unlock()
		h(w, r)
	}
}

func (fc *fakeCloud) enroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ProvisioningKey != "pk-good" {
		http.Error(w, "bad key", http.StatusForbidden)
		return
	}
	blk, _ := pem.Decode([]byte(req.CSRPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	der := fc.deviceCert(csr.PublicKey)
	json.NewEncoder(w).Encode(api.EnrollResponse{
		TenantID: testTenant, UserID: "u1", DeviceID: testDevice,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		CAPEM:          fc.pki.caPEM,
		Edges:          fc.edgeInfos(),
		SnapshotKeys:   []api.SigningKey{{KeyID: testKeyID, Algorithm: policy.AlgEd25519, PublicKey: fc.signKey.Public().(ed25519.PublicKey)}},
		ControlURL:     fc.cp.URL,
	})
}

func (fc *fakeCloud) envelope() (*policy.Envelope, uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	env, err := policy.Sign(fc.snap, testKeyID, fc.signKey)
	if err != nil {
		fc.t.Error(err)
	}
	return env, fc.snap.Version
}

func (fc *fakeCloud) publish(mut func(s *policy.Snapshot)) {
	fc.mu.Lock()
	cp := *fc.snap
	mut(&cp)
	cp.Version++
	fc.snap = &cp
	close(fc.updated)
	fc.updated = make(chan struct{})
	fc.mu.Unlock()
}

func (fc *fakeCloud) snapshot(w http.ResponseWriter, r *http.Request) {
	fc.mu.Lock()
	ver, ch := fc.snap.Version, fc.updated
	fc.mu.Unlock()
	have := strings.Trim(r.Header.Get("If-None-Match"), `"`)
	if have == strconv.FormatUint(ver, 10) {
		wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
		select {
		case <-ch:
		case <-time.After(time.Duration(wait) * time.Second):
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
	}
	env, v := fc.envelope()
	w.Header().Set("ETag", `"`+strconv.FormatUint(v, 10)+`"`)
	json.NewEncoder(w).Encode(env)
}

func (fc *fakeCloud) postFlows(w http.ResponseWriter, r *http.Request) {
	fc.mu.Lock()
	if fc.flowFail > 0 {
		fc.flowFail--
		fc.mu.Unlock()
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	var b api.FlowBatch
	_ = json.NewDecoder(r.Body).Decode(&b)
	fc.flows = append(fc.flows, b.Records...)
	fc.probes = append(fc.probes, b.Probes...)
	fc.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (fc *fakeCloud) putRules(w http.ResponseWriter, r *http.Request) {
	var ur api.UserRules
	if err := json.NewDecoder(r.Body).Decode(&ur); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fc.mu.Lock()
	fc.userPuts++
	fc.mu.Unlock()
	fc.publish(func(s *policy.Snapshot) {
		s.Firewall.AllowUserRules = true
		s.Firewall.Apps = ur.Apps
	})
	env, _ := fc.envelope()
	json.NewEncoder(w).Encode(env)
}

func (fc *fakeCloud) session(w http.ResponseWriter, r *http.Request) {
	var req api.SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientPub, _ := base64.StdEncoding.DecodeString(req.WGPublicKey)
	fc.mu.Lock()
	mode := fc.rotationMode
	if req.Epoch == 0 {
		fc.sessions0++
	}
	n := fc.sessions0
	fc.mu.Unlock()
	if req.Epoch > 0 && mode == "409" {
		http.Error(w, "epoch must be greater", http.StatusConflict)
		return
	}
	sid := req.SessionID
	if sid == "" {
		sid = "sess-" + strconv.Itoa(n)
	}
	psk, err := pqsession.DerivePSK(*r.TLS, clientPub, edgeWGPub(fc.t), sid, req.Epoch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fc.mu.Lock()
	fc.psks[req.Epoch] = psk
	rotate := fc.rotate
	fc.mu.Unlock()
	if req.Epoch > 0 && mode == "lost" {
		// The Edge committed the epoch but the response never reaches the client.
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
				return
			}
		}
	}
	json.NewEncoder(w).Encode(api.SessionResponse{
		SessionID: sid, Epoch: req.Epoch, TunnelIPv4: "100.64.0.7/32", TunnelIPv6: "fd7a:5a5e::7/128",
		DNSServers: []string{"100.64.0.1"}, EdgeWGKey: base64.StdEncoding.EncodeToString(edgeWGPub(fc.t)),
		WGEndpoint: "127.0.0.1:1", RotateAfterSec: rotate, MTU: 1280,
	})
}

func (fc *fakeCloud) edgePSK(epoch uint64) ([32]byte, bool) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	p, ok := fc.psks[epoch]
	return p, ok
}

// recPlatform records events.
type recPlatform struct {
	mu     sync.Mutex
	events []string
}

func (p *recPlatform) ConnectionOwnerUID(protocol int, srcIP string, srcPort int, dstIP string, dstPort int) int {
	return 10123
}
func (p *recPlatform) PackagesForUID(uid int) string { return "com.example.app" }
func (p *recPlatform) Protect(fd int) bool           { return true }
func (p *recPlatform) OnEvent(kind, payload string) {
	p.mu.Lock()
	p.events = append(p.events, kind+" "+payload)
	p.mu.Unlock()
}
func (p *recPlatform) has(prefix string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.events {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func newTestEngine(t *testing.T, fc *fakeCloud) (*Engine, *recPlatform) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/"+fileBootstrapCA, []byte(fc.pki.caPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	pl := &recPlatform{}
	e, err := NewEngine(dir, pl)
	if err != nil {
		t.Fatal(err)
	}
	e.pollWait = 1
	e.flowInterval = 100 * time.Millisecond
	e.statsInterval = 100 * time.Millisecond
	return e, pl
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEnroll(t *testing.T) {
	fc := newFakeCloud(t)
	caSum := sha256.Sum256(fc.pki.ca.Raw)
	wrongSum := sha256.Sum256([]byte("nope"))
	tests := []struct {
		name      string
		bootstrap bool
		urlSuffix string
		key       string
		classic   bool
		wantErr   string
	}{
		{"bootstrap CA file", true, "", "pk-good", false, ""},
		{"sha256 pin of CA", false, "#sha256=" + hex.EncodeToString(caSum[:]), "pk-good", false, ""},
		{"wrong pin", false, "#sha256=" + hex.EncodeToString(wrongSum[:]), "pk-good", false, "pinned"},
		{"no trust anchor", false, "", "pk-good", false, "certificate"},
		{"bad provisioning key", true, "", "pk-bad", false, "403"},
		{"classic-only server refused", true, "", "pk-good", true, "handshake"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fc.cp.URL
			if tt.classic {
				mux := http.NewServeMux()
				mux.HandleFunc("POST /v1/enroll", fc.enroll)
				url = startTLS(t, fc.pki, mux, false, pki.ControlPlaneURI()).URL
			}
			dir := t.TempDir()
			if tt.bootstrap {
				os.WriteFile(dir+"/"+fileBootstrapCA, []byte(fc.pki.caPEM), 0o600)
			}
			e, err := NewEngine(dir, &recPlatform{})
			if err != nil {
				t.Fatal(err)
			}
			err = e.Enroll(url+tt.urlSuffix, tt.key, "pixel")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want %q", err, tt.wantErr)
				}
				if e.IsEnrolled() {
					t.Fatal("enrolled despite error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			if !e.IsEnrolled() {
				t.Fatal("not enrolled")
			}
			for _, f := range []string{fileDeviceKey, fileDeviceCert, fileEnrollment} {
				assertPrivate(t, e.statePath(f))
			}
			// A new Engine on the same dir is enrolled.
			e2, err := NewEngine(dir, &recPlatform{})
			if err != nil || !e2.IsEnrolled() {
				t.Fatalf("reload: %v", err)
			}
			if err := e2.Unenroll(); err != nil || e2.IsEnrolled() {
				t.Fatalf("Unenroll: %v", err)
			}
		})
	}
}

func deviceIPC(t *testing.T, e *Engine) map[string]string {
	t.Helper()
	rs := e.running.Load()
	s, err := rs.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for line := range strings.Lines(s) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		if k == "allowed_ip" {
			m[k] += v + ","
			continue
		}
		m[k] = v
	}
	return m
}

func TestEngineLifecycle(t *testing.T) {
	fc := newFakeCloud(t)
	fc.rotate = 1 // rotate the PSK every second
	e, pl := newTestEngine(t, fc)
	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}

	cfgJSON, err := e.TunnelConfig()
	if err != nil {
		t.Fatalf("TunnelConfig: %v", err)
	}
	var tc tunnelConfigJSON
	json.Unmarshal([]byte(cfgJSON), &tc)
	if tc.IPv4 != "100.64.0.7/32" || tc.MTU != 1280 || len(tc.DNS) != 1 {
		t.Fatalf("tunnel config %s", cfgJSON)
	}

	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatalf("StartDevice: %v", err)
	}
	defer e.Stop()

	var st statusJSON
	json.Unmarshal([]byte(e.Status()), &st)
	if st.State != StateConnected || !st.PQ || st.Kex != "X25519MLKEM768" || st.Edge != "edge-1" || st.Network != "wifi" {
		t.Fatalf("status %+v", st)
	}

	// WireGuard got the PSK the Edge derived on the same TLS connection, and full config.
	ipc := deviceIPC(t, e)
	psk0, _ := fc.edgePSK(0)
	if ipc["preshared_key"] != hex.EncodeToString(psk0[:]) {
		t.Fatal("device PSK differs from the Edge's PSK for epoch 0")
	}
	if ipc["public_key"] != hex.EncodeToString(edgeWGPub(t)) || ipc["endpoint"] != "127.0.0.1:1" ||
		ipc["persistent_keepalive_interval"] != "25" || ipc["allowed_ip"] != "0.0.0.0/0,::/0," {
		t.Fatalf("ipc %v", ipc)
	}

	// The snapshot long-poll installs v1, then v2 when the Control Plane publishes it.
	waitUntil(t, "snapshot v1", func() bool { return e.currentVersion() == 1 })
	fc.publish(func(s *policy.Snapshot) { s.Firewall.Lockdown = false })
	waitUntil(t, "snapshot v2", func() bool { return e.currentVersion() == 2 })
	if !strings.Contains(e.Snapshot(), `"version":2`) {
		t.Fatalf("Snapshot() = %s", e.Snapshot())
	}

	// Rotation: epoch 1 PSK is installed, matching the Edge.
	waitUntil(t, "PSK rotation", func() bool {
		psk1, ok := fc.edgePSK(1)
		return ok && deviceIPC(t, e)["preshared_key"] == hex.EncodeToString(psk1[:])
	})
	if psk0 == ([32]byte{}) {
		t.Fatal("zero PSK")
	}

	// A blocked flow (tenant rule port 8080) is answered with an RST and uploaded.
	syn := tcpSYN(t, "100.64.0.7", 40000, "203.0.113.1", 8080)
	ct.Outbound <- syn
	select {
	case rst := <-ct.Inbound:
		var p packet.Packet
		if err := packet.Parse(rst, &p); err != nil || !p.RST() {
			t.Fatalf("expected RST, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no RST")
	}
	waitUntil(t, "flow upload", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.flows) > 0 && fc.flows[0].Decision.RuleID == "no-8080" && fc.flows[0].Flow.App == "com.example.app"
	})
	if !strings.Contains(e.RecentFlows(10), `"no-8080"`) {
		t.Fatalf("RecentFlows %s", e.RecentFlows(10))
	}
	if !strings.Contains(e.AppStats(), `"app":"com.example.app"`) {
		t.Fatalf("AppStats %s", e.AppStats())
	}

	// User rules round trip through PUT /v1/self/rules and install the returned snapshot.
	if err := e.SetAppPolicy("com.game", "allow", "block", ""); err != nil {
		t.Fatalf("SetAppPolicy: %v", err)
	}
	if !strings.Contains(e.Snapshot(), `"com.game"`) {
		t.Fatal("user rules snapshot not installed")
	}
	if err := e.SetUserRules(`{"rules":[{"id":"x","source":"tenant","action":"allow"}]}`); err == nil {
		t.Fatal("tenant-sourced user rule accepted")
	}

	waitUntil(t, "events", func() bool {
		return pl.has("state ") && pl.has("snapshot ") && pl.has("stats ") && pl.has("flow ")
	})

	e.Stop()
	st = statusJSON{}
	json.Unmarshal([]byte(e.Status()), &st)
	if st.State != StateStopped || st.PQ || st.Kex != "" {
		t.Fatalf("status after stop %+v", st)
	}
	// Restart without TunnelConfig performs its own session setup.
	if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "cellular"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	e.Stop()
}

func TestCachedSnapshotAndRollback(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}
	id := e.en.Load()
	fc.publish(func(*policy.Snapshot) {}) // v2
	env2, _ := fc.envelope()
	if ok, err := e.installEnvelope(id, env2, true); !ok || err != nil {
		t.Fatalf("install v2: %v %v", ok, err)
	}
	// Older version is ignored.
	fc.mu.Lock()
	old := *fc.snap
	old.Version = 1
	fc.mu.Unlock()
	envOld, _ := policy.Sign(&old, testKeyID, fc.signKey)
	if ok, _ := e.installEnvelope(id, envOld, true); ok || e.currentVersion() != 2 {
		t.Fatal("rollback accepted")
	}
	// Tampered payload is rejected.
	bad := *env2
	bad.Payload = append([]byte(nil), env2.Payload...)
	bad.Payload[10] ^= 1
	if _, err := e.installEnvelope(id, &bad, true); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	// Snapshot for another device is rejected.
	other := old
	other.Version, other.DeviceID = 9, "dev-2"
	envOther, _ := policy.Sign(&other, testKeyID, fc.signKey)
	if _, err := e.installEnvelope(id, envOther, true); err == nil {
		t.Fatal("foreign snapshot accepted")
	}
	// A restarted engine loads the persisted v2 offline.
	e2, err := NewEngine(e.stateDir, &recPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	if e2.currentVersion() != 2 {
		t.Fatalf("cached version %d", e2.currentVersion())
	}
}

func tcpSYN(t *testing.T, src string, sport uint16, dst string, dport uint16) []byte {
	t.Helper()
	s, d := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	pkt := make([]byte, 40)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 6
	pkt[3] = 40
	copy(pkt[12:], s)
	copy(pkt[16:], d)
	pkt[20], pkt[21] = byte(sport>>8), byte(sport)
	pkt[22], pkt[23] = byte(dport>>8), byte(dport)
	pkt[32] = 5 << 4
	pkt[33] = packet.FlagSYN
	pkt[34], pkt[35] = 0xff, 0xff
	return pkt
}

func ecdhX25519(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// TestEdgeFailover covers issue #70: a restarted Edge (session lost) gets a new session at
// once; an Edge that stops answering is left for the next one; after a stable period the
// client returns to the preferred Edge.
func TestEdgeFailover(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	e.probeInterval, e.probeIdle, e.probeTimeout = 50*time.Millisecond, 50*time.Millisecond, 500*time.Millisecond
	e.livenessInterval, e.failbackAfter = 50*time.Millisecond, 700*time.Millisecond
	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	edge := func() string {
		var st statusJSON
		_ = json.Unmarshal([]byte(e.Status()), &st)
		return st.Edge
	}
	sessions := func() int {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return fc.sessions0
	}
	if edge() != "edge-1" {
		t.Fatalf("starts on %s", edge())
	}

	// Edge restart: the probe finds no session; the client sets up a new one on edge-1.
	before := sessions()
	fc.mu.Lock()
	fc.forgotten["edge-1"] = true
	fc.mu.Unlock()
	waitUntil(t, "new session after the Edge lost it", func() bool { return sessions() > before && edge() == "edge-1" })

	// Edge down: the client moves to edge-2.
	start := time.Now()
	fc.mu.Lock()
	fc.down["edge-1"] = true
	fc.mu.Unlock()
	waitUntil(t, "failover to edge-2", func() bool { return edge() == "edge-2" })
	t.Logf("failover took %s", time.Since(start).Round(time.Millisecond))

	// edge-1 is back: after failbackAfter the client returns to it.
	fc.mu.Lock()
	fc.down["edge-1"] = false
	fc.mu.Unlock()
	waitUntil(t, "failback to edge-1", func() bool { return edge() == "edge-1" })
}

// TestEdgeListRefresh covers issue #71: the client takes the Control Plane's refreshed list,
// orders it by priority, persists it and uses it for the next sessions.
func TestEdgeListRefresh(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	fc.edgesFn = func() []api.EdgeInfo {
		l := fc.edgeInfos()
		l[0].Priority = 5 // edge-1 becomes the backup
		return l
	}
	fc.mu.Unlock()
	id := e.en.Load()
	if err := e.refreshEdges(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if l := id.edgeList(); len(l) != 2 || l[0].ID != "edge-2" {
		t.Fatalf("order %+v", l)
	}
	// Persisted: a new engine on the same state starts with edge-2.
	e2, err := NewEngine(e.stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l := e2.en.Load().edgeList(); l[0].ID != "edge-2" {
		t.Fatalf("persisted order %+v", l)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	var st statusJSON
	_ = json.Unmarshal([]byte(e.Status()), &st)
	if st.Edge != "edge-2" {
		t.Fatalf("session on %s, want edge-2", st.Edge)
	}
	// An unreachable Edge sorts after reachable ones of the same priority.
	got := e.orderEdges(context.Background(), []api.EdgeInfo{{ID: "dead", SessionURL: "https://127.0.0.1:1"}, {ID: "live", SessionURL: fc.edge.URL}})
	if got[0].ID != "live" {
		t.Fatalf("unreachable first: %+v", got)
	}
}
