package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestMatchApp(t *testing.T) {
	apps := []policy.PrivateApp{
		{ID: "intranet", Domains: []string{"Intranet.Acme.Internal"}, Ports: []policy.PortRange{{From: 80}, {From: 8080, To: 8090}}},
		{ID: "wiki", Domains: []string{"*.wiki.acme.internal"}, Ports: []policy.PortRange{{From: 443}}},
		{ID: "none", Domains: []string{"closed.acme.internal"}},
		{ID: "bad", Domains: []string{"*", "*.", ""}, Ports: []policy.PortRange{{From: 1, To: 65535}}},
	}
	tests := []struct {
		name string
		port uint16
		want string
	}{
		{"intranet.acme.internal", 80, "intranet"},
		{"INTRANET.acme.internal.", 8085, "intranet"},
		{"intranet.acme.internal", 81, ""},
		{"x.intranet.acme.internal", 80, ""},
		{"wiki.acme.internal", 443, "wiki"},
		{"a.b.wiki.acme.internal", 443, "wiki"},
		{"evilwiki.acme.internal", 443, ""},
		{"closed.acme.internal", 80, ""},
		{"anything.example", 22, ""},
		{"intranet.acme.internal", 0, ""},
		{"", 80, ""},
	}
	for _, tc := range tests {
		a, ok := MatchApp(apps, tc.name, tc.port)
		got := ""
		if ok {
			got = a.ID
		}
		if got != tc.want {
			t.Errorf("MatchApp(%q, %d) = %q, want %q", tc.name, tc.port, got, tc.want)
		}
	}
}

type mapResolver map[string][]netip.Addr

func (m mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := m[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func listenEcho(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func TestDialHandlerRefusals(t *testing.T) {
	echo := listenEcho(t)
	closed := func() uint16 { // a port with nothing listening
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return uint16(p)
	}()
	apps := []policy.PrivateApp{{ID: "app", Domains: []string{"*.corp.test"}, Ports: []policy.PortRange{{From: echo}, {From: closed}, {From: 80}}}}
	res := mapResolver{
		"loop.corp.test":  {netip.MustParseAddr("127.0.0.1")},
		"ll.corp.test":    {netip.MustParseAddr("169.254.169.254")},
		"mc.corp.test":    {netip.MustParseAddr("224.0.0.1")},
		"zero.corp.test":  {netip.MustParseAddr("0.0.0.0")},
		"ll6.corp.test":   {netip.MustParseAddr("fe80::1")},
		"mixed.corp.test": {netip.MustParseAddr("169.254.1.1"), netip.MustParseAddr("127.0.0.1")},
	}
	port := func(p uint16) string {
		return strings.TrimPrefix(netip.AddrPortFrom(netip.IPv4Unspecified(), p).String(), "0.0.0.0")
	}
	tests := []struct {
		name          string
		target        string
		allowLoopback bool
		want          int
	}{
		{"not in apps", "other.test" + port(echo), true, http.StatusForbidden},
		{"port not in app", "loop.corp.test:81", true, http.StatusForbidden},
		{"bad target", "loop.corp.test", true, http.StatusBadRequest},
		{"bad port", "loop.corp.test:0", true, http.StatusBadRequest},
		{"loopback refused", "loop.corp.test" + port(echo), false, http.StatusForbidden},
		{"link-local", "ll.corp.test:80", true, http.StatusForbidden},
		{"link-local v6", "ll6.corp.test:80", true, http.StatusForbidden},
		{"multicast", "mc.corp.test:80", true, http.StatusForbidden},
		{"unspecified", "zero.corp.test:80", true, http.StatusForbidden},
		{"unresolvable", "nx.corp.test:80", true, http.StatusBadGateway},
		{"dial fails", "loop.corp.test" + port(closed), true, http.StatusBadGateway},
		{"allowed", "loop.corp.test" + port(echo), true, http.StatusOK},
		{"mixed: forbidden address skipped", "mixed.corp.test" + port(echo), true, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &DialHandler{Apps: func() []policy.PrivateApp { return apps }, Resolver: res, AllowLoopback: tc.allowLoopback, Log: quiet}
			req := httptest.NewRequest(http.MethodPost, "/v1/dial", strings.NewReader(""))
			req.Header.Set(api.BrokerHeaderTarget, tc.target)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status %d, want %d (%s)", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// TestServeBrokerHTTP2 runs the inverted HTTP/2 channel over a pipe: the "edge" is the
// HTTP/2 client, the connector serves /v1/dial and splices to a TCP echo backend.
func TestServeBrokerHTTP2(t *testing.T) {
	echo := listenEcho(t)
	apps := []policy.PrivateApp{{ID: "app", Domains: []string{"echo.corp.test"}, Ports: []policy.PortRange{{From: echo}}}}
	h := &DialHandler{Apps: func() []policy.PrivateApp { return apps }, Resolver: mapResolver{"echo.corp.test": {netip.MustParseAddr("127.0.0.1")}}, AllowLoopback: true, Log: quiet}
	edgeSide, connSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeBroker(ctx, connSide, h)
	cc, err := (&http2.Transport{}).NewClientConn(edgeSide) //nolint:staticcheck // SA1019: mirrors the edge, which wraps an existing conn
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	dial := func(target string) (*http.Response, *io.PipeWriter) {
		pr, pw := io.Pipe()
		req, _ := http.NewRequest(http.MethodPost, "https://connector/v1/dial", pr)
		req.Header.Set(api.BrokerHeaderTarget, target)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp, pw
	}
	resp, pw := dial("echo.corp.test:" + itoa(echo))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// Full duplex: a reply arrives before the request body ends.
	go func() { _, _ = pw.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
	_ = pw.Close() // half-close: the backend sees EOF, closes, the stream ends
	if rest, err := io.ReadAll(resp.Body); err != nil || len(rest) != 0 {
		t.Fatalf("after half-close: %q %v", rest, err)
	}
	resp, pw = dial("echo.corp.test:1")
	_ = pw.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-entitled target: status %d", resp.StatusCode)
	}
}

func itoa(p uint16) string {
	return netip.AddrPortFrom(netip.IPv4Unspecified(), p).String()[len("0.0.0.0:"):]
}

// --- enrollment, config and renewal against a fake Control Plane ---

type fakeCP struct {
	t       *testing.T
	auth    *pki.Authority
	mu      sync.Mutex
	key     string // valid provisioning key (single use)
	renewed int
	srv     *httptest.Server
	cfg     api.ConnectorConfig
}

func newFakeCP(t *testing.T, serverCert string) (*fakeCP, string) {
	t.Helper()
	dir := t.TempDir()
	if err := pki.InitDir(dir, pki.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	auth, err := pki.OpenAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := auth.TenantCA("acme")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCP{t: t, auth: auth, key: "pk-secret",
		cfg: api.ConnectorConfig{Version: 3, Apps: []policy.PrivateApp{{ID: "intranet", Domains: []string{"intranet.acme.internal"}, Ports: []policy.PortRange{{From: 80}}, ConnectorGroup: "default"}}}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/connector/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req api.ConnectorEnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		ok := req.ProvisioningKey == f.key && f.key != ""
		f.key = ""
		f.mu.Unlock()
		if !ok {
			http.Error(w, "bad key", http.StatusForbidden)
			return
		}
		chain, _, err := ca.SignConnectorCSR([]byte(req.CSRPEM), "acme", "c1", 0)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = json.NewEncoder(w).Encode(api.ConnectorEnrollResponse{TenantID: "acme", ConnectorID: "c1", Group: "default",
			CertificatePEM: string(chain), CAPEM: string(append(auth.Root.CertPEM(), ca.CertPEM()...)), ControlURL: f.srv.URL})
	})
	connectorOnly := func(r *http.Request) bool {
		id, err := pki.VerifyPeerChains(r.TLS.VerifiedChains, auth.Root.Cert)
		return err == nil && id.Kind == pki.PeerConnector && id.ConnectorID == "c1"
	}
	mux.HandleFunc("GET /v1/connector/config", func(w http.ResponseWriter, r *http.Request) {
		if !connectorOnly(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		f.mu.Lock()
		cfg := f.cfg
		f.mu.Unlock()
		if r.Header.Get("If-None-Match") == `"`+itoa(uint16(cfg.Version))+`"` {
			select {
			case <-time.After(200 * time.Millisecond):
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"`+itoa(uint16(cfg.Version))+`"`)
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("POST /v1/connector/renew", func(w http.ResponseWriter, r *http.Request) {
		if !connectorOnly(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req api.RenewRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		chain, _, err := ca.SignConnectorCSR([]byte(req.CSRPEM), "acme", "c1", 0)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.mu.Lock()
		f.renewed++
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.RenewResponse{CertificatePEM: string(chain), CAPEM: string(ca.CertPEM())})
	})
	certFile, keyFile := filepath.Join(dir, pki.CPCertFile), filepath.Join(dir, pki.CPKeyFile)
	if serverCert == "edge" {
		certFile, keyFile = filepath.Join(dir, pki.EdgeDir, pki.EdgeCertFile), filepath.Join(dir, pki.EdgeDir, pki.EdgeKeyFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.EnableHTTP2 = true
	f.srv.TLS = pqsession.Harden(&tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: auth.ClientCAPool()})
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	sum := sha256.Sum256(auth.Root.Cert.Raw)
	// httptest listens on 127.0.0.1, which is in the dev SANs.
	return f, f.srv.URL + "#sha256=" + hex.EncodeToString(sum[:])
}

func TestEnrollConfigRenew(t *testing.T) {
	f, control := newFakeCP(t, "")
	state := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(ctx, Config{ControlURL: control, ProvisioningKey: "pk-secret", StateDir: state, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if c.id.info.ConnectorID != "c1" || c.id.info.TenantID != "acme" {
		t.Fatalf("identity %+v", c.id.info)
	}
	// State permissions: dir 0700, files 0600, no certificate PEM duplicated in the json.
	if st, _ := os.Stat(state); st.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v", st.Mode().Perm())
	}
	for _, n := range []string{fileInfo, fileBundle, fileRoot} {
		st, err := os.Stat(filepath.Join(state, n))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", n, err, st)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(state, fileInfo)); strings.Contains(string(b), "PRIVATE KEY") || strings.Contains(string(b), "pk-secret") {
		t.Fatal("connector.json holds a key or the provisioning key")
	}

	// Config long-poll.
	cfg, changed, err := c.pollConfig(ctx)
	if err != nil || !changed || cfg.Version != 3 {
		t.Fatalf("config %+v %v %v", cfg, changed, err)
	}
	c.apply(ctx, cfg)
	if _, ok := MatchApp(c.Apps(), "intranet.acme.internal", 80); !ok {
		t.Fatal("apps not applied")
	}
	if _, changed, err := c.pollConfig(ctx); err != nil || changed {
		t.Fatalf("second poll: changed=%v err=%v", changed, err)
	}

	// Renewal: new key and serial, persisted, hot-swapped, and used on the next request.
	old := c.id.leaf()
	if err := c.renew(ctx); err != nil {
		t.Fatal(err)
	}
	nl := c.id.leaf()
	if nl.SerialNumber.Cmp(old.SerialNumber) == 0 || nl.PublicKey.(*ecdsa.PublicKey).Equal(old.PublicKey) {
		t.Fatal("renewal kept serial or key")
	}
	if _, _, err := c.pollConfig(ctx); err != nil {
		t.Fatalf("config with renewed cert: %v", err)
	}
	// Restart from state: the renewed certificate is loaded, no key needed.
	c2, err := New(ctx, Config{ControlURL: control, StateDir: state, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if c2.id.leaf().SerialNumber.Cmp(nl.SerialNumber) != 0 {
		t.Fatal("restart did not load the renewed certificate")
	}
	_ = f
}

func TestEnrollRefusesWrongServer(t *testing.T) {
	tests := []struct {
		name   string
		server string
		mutate func(string) string
	}{
		{"wrong pin", "", func(u string) string { return u[:strings.Index(u, "#")] + "#sha256=" + strings.Repeat("ab", 32) }},
		{"edge identity", "edge", func(u string) string { return u }},
		{"no pin, not system-trusted", "", func(u string) string { return u[:strings.Index(u, "#")] }},
		{"bad fragment", "", func(u string) string { return u[:strings.Index(u, "#")] + "#x=1" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, control := newFakeCP(t, tc.server)
			_, err := New(context.Background(), Config{ControlURL: tc.mutate(control), ProvisioningKey: "pk-secret", StateDir: t.TempDir(), Logger: quiet})
			if err == nil {
				t.Fatal("enrolled against an untrusted server")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.key == "" {
				t.Fatal("provisioning key was sent to the untrusted server")
			}
		})
	}
}

func TestNotEnrolledNeedsKey(t *testing.T) {
	_, err := New(context.Background(), Config{ControlURL: "https://127.0.0.1:1", StateDir: t.TempDir(), Logger: quiet})
	if err == nil || !strings.Contains(err.Error(), "provisioning key") {
		t.Fatalf("err %v", err)
	}
}
