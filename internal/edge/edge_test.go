package edge

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// --- fakes ---

type fakeCP struct {
	mu       sync.Mutex
	bundle   api.PKIBundle
	peers    api.EdgePeers
	decide   func(string, policy.Flow) (api.DecideResponse, error)
	posted   []api.FlowRecord
	decides  int
	peerGets int
	reported [][]string

	reportedConnectors [][]string
	// serials holds the current cert serial per device/connector ID, as issued by the
	// fixture; Peers fills it into entries that have none (the CP sends it, ST-01/ST-04).
	serials map[string]string
	// inspect answers InspectionCA (ADR-0018); nil refuses.
	inspect func(api.InspectionCARequest) (api.InspectionCAResponse, error)
	// categories is the category list Categories serves (ADR-0022); nil answers 503.
	categories *categories.DB
	catGets    []string
	datasets   map[string][]api.EdgeDataset // tenant -> datasets served by Datasets
}

func (f *fakeCP) Categories(_ context.Context, names []string, etag string) ([]byte, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.categories == nil {
		return nil, "", false, errors.New("503 no category list loaded")
	}
	f.catGets = append(f.catGets, strings.Join(names, ","))
	if etag == "v1" {
		return nil, etag, true, nil
	}
	var b bytes.Buffer
	if err := f.categories.Encode(&b, names); err != nil {
		return nil, "", false, err
	}
	return b.Bytes(), "v1", false, nil
}

func (f *fakeCP) Datasets(_ context.Context, tenant string, names []string) (api.EdgeDatasets, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.datasets == nil {
		return api.EdgeDatasets{}, errors.New("no datasets")
	}
	out := api.EdgeDatasets{}
	for _, d := range f.datasets[tenant] {
		if slices.Contains(names, d.Name) {
			out.Datasets = append(out.Datasets, d)
		}
	}
	return out, nil
}

func (f *fakeCP) InspectionCA(_ context.Context, r api.InspectionCARequest) (api.InspectionCAResponse, error) {
	f.mu.Lock()
	fn := f.inspect
	f.mu.Unlock()
	if fn == nil {
		return api.InspectionCAResponse{}, errors.New("403 inspection is off")
	}
	return fn(r)
}

func (f *fakeCP) ReportSessions(_ context.Context, s api.EdgeSessions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reported = append(f.reported, s.DeviceIDs)
	f.reportedConnectors = append(f.reportedConnectors, s.ConnectorIDs)
	return nil
}

func (f *fakeCP) PKIBundle(context.Context) (api.PKIBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bundle, nil
}

func (f *fakeCP) Peers(context.Context) (api.EdgePeers, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peerGets++
	p := api.EdgePeers{Devices: append([]api.EdgeDevice(nil), f.peers.Devices...), Connectors: append([]api.EdgeConnector(nil), f.peers.Connectors...)}
	for i := range p.Devices {
		if p.Devices[i].CertSerial == "" {
			p.Devices[i].CertSerial = f.serials[p.Devices[i].DeviceID]
		}
	}
	for i := range p.Connectors {
		if p.Connectors[i].CertSerial == "" {
			p.Connectors[i].CertSerial = f.serials["connector:"+p.Connectors[i].ConnectorID]
		}
	}
	return p, nil
}

func (f *fakeCP) Decide(_ context.Context, d string, fl policy.Flow) (api.DecideResponse, error) {
	f.mu.Lock()
	f.decides++
	fn := f.decide
	f.mu.Unlock()
	if fn == nil {
		return api.DecideResponse{}, errors.New("no decider")
	}
	return fn(d, fl)
}

func (f *fakeCP) PostFlows(_ context.Context, r []api.FlowRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posted = append(f.posted, r...)
	return nil
}

type fakeWG struct {
	mu   sync.Mutex
	ops  []string
	peer map[string]string // public key hex -> psk hex
}

func (f *fakeWG) IpcSetOperation(r io.Reader) error {
	b, _ := io.ReadAll(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peer == nil {
		f.peer = map[string]string{}
	}
	f.ops = append(f.ops, string(b))
	var cur string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "public_key":
			cur = v
		case "preshared_key":
			f.peer[cur] = v
		case "remove":
			delete(f.peer, cur)
		}
	}
	return nil
}

func (f *fakeWG) psk(pub []byte) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.peer[hex.EncodeToString(pub)]
	return v, ok
}

// --- fixture ---

type fixture struct {
	t      *testing.T
	dir    string
	auth   *pki.Authority
	sk     ed25519.PrivateKey
	kid    string
	cp     *fakeCP
	wg     *fakeWG
	e      *Edge
	cancel context.CancelFunc
	apps   []policy.PrivateApp     // PrivateApps of the snapshots setPeer publishes
	web    policy.WebPolicy        // Web policy of the snapshots setPeer publishes
	cats   []string                // Categories of the snapshots setPeer publishes
	safe   bool                    // SafeSearch of the snapshots setPeer publishes
	redir  bool                    // dns.redirectQueries of the snapshots setPeer publishes
	dnsMod func(*policy.DNSPolicy) // adjusts the DNS policy setPeer publishes
}

func newFixture(t *testing.T) *fixture { t.Helper(); return newFixtureCfg(t, nil) }

// newFixtureCfg is newFixture with mod applied to the Edge Config.
func newFixtureCfg(t *testing.T, mod func(*Config)) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := pki.InitDir(dir, pki.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	auth, _ := pki.OpenAuthority(dir)
	if _, err := auth.TenantCA(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	sk, kid, _ := pki.LoadOrCreateSigningKey(filepath.Join(dir, pki.SnapshotKeyFile))
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, pki.EdgeDir, pki.EdgeCertFile), filepath.Join(dir, pki.EdgeDir, pki.EdgeKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	wgPriv, _, _ := pki.LoadWireGuardKey(filepath.Join(dir, pki.EdgeDir, pki.EdgeWGKeyFile))
	cp := &fakeCP{bundle: api.PKIBundle{CAPEM: string(auth.BundlePEM()), SnapshotKeys: []api.SigningKey{{KeyID: kid, Algorithm: "ed25519", PublicKey: sk.Public().(ed25519.PublicKey)}}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := Config{Root: auth.Root.Cert, Cert: cert, WGPrivateKey: wgPriv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if mod != nil {
		mod(&cfg)
	}
	e, err := newEdge(ctx, cfg, cp)
	if err != nil {
		t.Fatal(err)
	}
	e.minSync = 50 * time.Millisecond
	wg := &fakeWG{}
	e.wg = wg
	return &fixture{t: t, dir: dir, auth: auth, sk: sk, kid: kid, cp: cp, wg: wg, e: e, cancel: cancel}
}

func (fx *fixture) tenantPolicy() policy.FirewallPolicy {
	return policy.FirewallPolicy{
		DefaultAction: policy.ActionAllow,
		Rules: []policy.Rule{
			{ID: "no-smtp", Source: policy.SourceTenant, Priority: 1, Action: policy.ActionBlock, Match: policy.Match{Protocols: []string{"tcp"}, Ports: []policy.PortRange{{From: 25}}}},
			{ID: "app-only", Source: policy.SourceTenant, Priority: 2, Action: policy.ActionBlock, Match: policy.Match{Apps: []string{"com.x"}}},
			{ID: "no-tracker", Source: policy.SourceTenant, Priority: 3, Action: policy.ActionBlock, Match: policy.Match{Domains: []string{"*.tracker.test"}}},
			{ID: "ask-net", Source: policy.SourceTenant, Priority: 4, Action: policy.ActionAsk, Match: policy.Match{CIDRs: []string{"203.0.113.0/24"}}},
		},
	}
}

// setPeer publishes a signed snapshot for device id with version v.
func (fx *fixture) setPeer(id string, v uint64) {
	fx.t.Helper()
	snap := &policy.Snapshot{
		SchemaVersion: 1, Version: v, TenantID: "acme", UserID: "u1", DeviceID: id,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Firewall: fx.tenantPolicy(),
		DNS: policy.DNSPolicy{BlockResponse: "nxdomain", Blocklists: []policy.Blocklist{
			{ID: "ads", Domains: []string{"*.doubleclick.net"}},
			{ID: "saas:dropbox", Category: "saas:file-sharing", Domains: []string{"*.dropbox.com"}},
		}, RedirectQueries: fx.redir},
		PrivateApps: fx.apps,
		Web:         fx.web,
		Categories:  fx.cats,
		SafeSearch:  fx.safe,
	}
	if fx.dnsMod != nil {
		fx.dnsMod(&snap.DNS)
	}
	env, err := policy.Sign(snap, fx.kid, fx.sk)
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.cp.mu.Lock()
	defer fx.cp.mu.Unlock()
	for i := range fx.cp.peers.Devices {
		if fx.cp.peers.Devices[i].DeviceID == id {
			fx.cp.peers.Devices[i].Snapshot = *env
			return
		}
	}
	fx.cp.peers.Devices = append(fx.cp.peers.Devices, api.EdgeDevice{DeviceID: id, TenantID: "acme", Snapshot: *env})
}

func (fx *fixture) removePeer(id string) {
	fx.cp.mu.Lock()
	defer fx.cp.mu.Unlock()
	out := fx.cp.peers.Devices[:0]
	for _, d := range fx.cp.peers.Devices {
		if d.DeviceID != id {
			out = append(out, d)
		}
	}
	fx.cp.peers.Devices = out
}

func (fx *fixture) deviceCert(tenant, id string) tls.Certificate {
	fx.t.Helper()
	return fx.deviceCertValid(tenant, id, 0)
}

func (fx *fixture) deviceCertValid(tenant, id string, validity time.Duration) tls.Certificate {
	fx.t.Helper()
	ca, err := fx.auth.TenantCA(context.Background(), tenant)
	if err != nil {
		fx.t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	chain, _, err := ca.SignDeviceCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), tenant, id, validity)
	if err != nil {
		fx.t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	c, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.setSerial(id, c)
	return c
}

// setSerial records cert as the current certificate of key in the fake CP feed.
func (fx *fixture) setSerial(key string, cert tls.Certificate) {
	fx.t.Helper()
	fx.cp.mu.Lock()
	defer fx.cp.mu.Unlock()
	if fx.cp.serials == nil {
		fx.cp.serials = map[string]string{}
	}
	fx.cp.serials[key] = cert.Leaf.SerialNumber.String()
}

func (fx *fixture) sessionServer() *httptest.Server {
	srv := httptest.NewUnstartedServer((&sessionServer{e: fx.e}).handler())
	srv.TLS = fx.e.sessionTLSConfig()
	srv.StartTLS()
	fx.t.Cleanup(srv.Close)
	return srv
}

func (fx *fixture) client(cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(fx.auth.Root.Cert)
	cfg := pqsession.Harden(&tls.Config{RootCAs: pool, ServerName: "localhost", VerifyConnection: pki.ExpectServer(pki.ServerEdge, "edge-1")})
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	// No connection reuse: each session request must run on a fresh handshake.
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: 10 * time.Second}
}

func postSession(t *testing.T, c *http.Client, url string, req api.SessionRequest) (int, api.SessionResponse, *tls.ConnectionState) {
	t.Helper()
	b, _ := json.Marshal(req)
	resp, err := c.Post(url+"/v1/session", "application/json", bytes.NewReader(b))
	if err != nil {
		return 0, api.SessionResponse{}, nil
	}
	defer resp.Body.Close()
	var sr api.SessionResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	return resp.StatusCode, sr, resp.TLS
}

func TestSessionSetupAndRotation(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := fx.sessionServer()
	cert := fx.deviceCert("acme", "d1")
	c := fx.client(&cert)
	wgKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := wgKey.PublicKey().Bytes()

	code, sr, cs := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub)})
	if code != 200 {
		t.Fatalf("session: %d", code)
	}
	if sr.TunnelIPv4 != "100.64.0.2/32" || sr.TunnelIPv6 != "fd7a:5a5e::2/128" || sr.DNSServers[0] != "100.64.0.1" || sr.MTU != 1280 || sr.Epoch != 0 {
		t.Fatalf("response %+v", sr)
	}
	if len(cs.PeerCertificates) != 2 || !cs.PeerCertificates[1].IsCA {
		t.Fatalf("edge must send leaf + root, sent %d certs", len(cs.PeerCertificates))
	}
	edgePub, _ := base64.StdEncoding.DecodeString(sr.EdgeWGKey)
	clientPSK, err := pqsession.DerivePSK(*cs, pub, edgePub, sr.SessionID, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := fx.wg.psk(pub)
	if !ok || got != hex.EncodeToString(clientPSK[:]) {
		t.Fatal("edge and client PSKs differ")
	}
	if !strings.Contains(fx.wg.ops[0], "allowed_ip=100.64.0.2/32\nallowed_ip=fd7a:5a5e::2/128") {
		t.Fatalf("uapi: %q", fx.wg.ops[0])
	}

	// Rotation: epoch 1 on a fresh handshake replaces the PSK, same address.
	code, sr2, cs2 := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub), Epoch: 1, SessionID: sr.SessionID})
	if code != 200 || sr2.SessionID != sr.SessionID || sr2.TunnelIPv4 != sr.TunnelIPv4 || sr2.Epoch != 1 {
		t.Fatalf("rotate: %d %+v", code, sr2)
	}
	psk2, _ := pqsession.DerivePSK(*cs2, pub, edgePub, sr.SessionID, 1)
	if got2, _ := fx.wg.psk(pub); got2 != hex.EncodeToString(psk2[:]) || got2 == got {
		t.Fatal("rotation did not install the new PSK")
	}

	// Retry of the same epoch (the response was lost): re-derived on the new connection,
	// replacing the PSK (security review #5).
	code, sr2b, cs2b := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub), Epoch: 1, SessionID: sr.SessionID})
	if code != 200 || sr2b.Epoch != 1 || sr2b.TunnelIPv4 != sr.TunnelIPv4 {
		t.Fatalf("same-epoch retry: %d %+v", code, sr2b)
	}
	psk2b, _ := pqsession.DerivePSK(*cs2b, pub, edgePub, sr.SessionID, 1)
	if got2b, _ := fx.wg.psk(pub); got2b != hex.EncodeToString(psk2b[:]) || bytes.Equal(psk2b[:], psk2[:]) {
		t.Fatal("same-epoch retry did not install the PSK of the new connection")
	}
	if code, _, _ := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub), Epoch: 2, SessionID: sr.SessionID}); code != 200 {
		t.Fatalf("rotate to 2: %d", code)
	}

	tests := []struct {
		name string
		req  api.SessionRequest
		want int
	}{
		{"older epoch", api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub), Epoch: 1, SessionID: sr.SessionID}, 409},
		{"skipped epoch", api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub), Epoch: 4, SessionID: sr.SessionID}, 409},
		{"wrong session", api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub), Epoch: 3, SessionID: "nope"}, 409},
		{"bad key", api.SessionRequest{WGPublicKey: "AAAA"}, 400},
		{"zero key", api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}, 400},
	}
	for _, tc := range tests {
		if code, _, _ := postSession(t, c, srv.URL, tc.req); code != tc.want {
			t.Errorf("%s: %d want %d", tc.name, code, tc.want)
		}
	}

	// A new key for the same device replaces the old peer.
	k2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if code, sr3, _ := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(k2.PublicKey().Bytes())}); code != 200 || sr3.TunnelIPv4 != sr.TunnelIPv4 {
		t.Fatalf("rekey: %d %+v", code, sr3)
	}
	if _, ok := fx.wg.psk(pub); ok {
		t.Fatal("old peer key not removed")
	}

	// Unknown device and no client cert.
	other := fx.deviceCert("acme", "d-unknown")
	if code, _, _ := postSession(t, fx.client(&other), srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub)}); code != 403 {
		t.Fatalf("unknown device: %d", code)
	}
	if code, _, _ := postSession(t, fx.client(nil), srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub)}); code != 0 {
		t.Fatalf("no client cert: %d", code)
	}

	// Revocation: the device disappears from the feed and its peer is removed.
	fx.removePeer("d1")
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := fx.wg.psk(k2.PublicKey().Bytes()); ok {
		t.Fatal("revoked peer still configured")
	}
	if fx.e.reg.byTunnelIP(netip.MustParseAddr("100.64.0.2")) != nil {
		t.Fatal("revoked device still owns its address")
	}
	if code, _, _ := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub)}); code != 403 {
		t.Fatalf("revoked device: %d", code)
	}
}

func TestRegistryRejectsBadSnapshots(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 5)
	_ = fx.e.syncPeers(context.Background())
	// Tampered payload: signature fails, last good snapshot stays.
	fx.cp.mu.Lock()
	env := &fx.cp.peers.Devices[0].Snapshot
	env.Payload = bytes.Replace(env.Payload, []byte(`"version":5`), []byte(`"version":6`), 1)
	fx.cp.mu.Unlock()
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	if d == nil || d.compiled.Load().Version() != 5 {
		t.Fatal("tampered snapshot accepted or device dropped")
	}
	// A snapshot for another device under this ID is rejected.
	fx.setPeer("d1", 7)
	fx.cp.mu.Lock()
	fx.cp.peers.Devices[0].DeviceID = "d2"
	fx.cp.mu.Unlock()
	_ = fx.e.syncPeers(context.Background())
	if fx.e.reg.get("d2") != nil {
		t.Fatal("subject mismatch accepted")
	}
}

// --- filter ---

type fakeTUN struct {
	in     chan []byte
	mu     sync.Mutex
	writes [][]byte
	closed chan struct{}
}

func newFakeTUN() *fakeTUN { return &fakeTUN{in: make(chan []byte, 16), closed: make(chan struct{})} }

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1280, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) BatchSize() int           { return 4 }
func (f *fakeTUN) Close() error             { close(f.closed); return nil }
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, off int) (int, error) {
	select {
	case p := <-f.in:
		sizes[0] = copy(bufs[0][off:], p)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}
func (f *fakeTUN) Write(bufs [][]byte, off int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bufs {
		f.writes = append(f.writes, append([]byte(nil), b[off:]...))
	}
	return len(bufs), nil
}
func (f *fakeTUN) nWrites() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func ipv4(src, dst string, proto uint8, l4 []byte) []byte {
	b := make([]byte, 20+len(l4))
	b[0], b[8], b[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], l4)
	return b
}

func ipv6(src, dst string, next uint8, l4 []byte) []byte {
	b := make([]byte, 40+len(l4))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(l4)))
	b[6] = next
	b[7] = 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], l4)
	return b
}

func icmpMsg(typ, code uint8, id uint16) []byte {
	b := make([]byte, 8)
	b[0], b[1] = typ, code
	binary.BigEndian.PutUint16(b[4:6], id)
	return b
}

func tcpSeg(sport, dport uint16, flags uint8) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], 1000)
	if flags&packet.FlagACK != 0 {
		binary.BigEndian.PutUint32(t[8:], 5000)
	}
	t[12], t[13] = 5<<4, flags
	binary.BigEndian.PutUint16(t[14:], 65535)
	return t
}

func udpDgram(sport, dport uint16) []byte {
	u := make([]byte, 12)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], 12)
	return u
}

// reader drains the filter with one goroutine so timed-out reads never swallow packets.
type reader chan []byte

func startReader(f *Filter) reader {
	ch := make(reader, 16)
	go func() {
		for {
			bufs := [][]byte{make([]byte, 2000)}
			sizes := []int{0}
			n, err := f.Read(bufs, sizes, 0)
			if err != nil {
				close(ch)
				return
			}
			if n > 0 {
				ch <- bufs[0][:sizes[0]]
			}
		}
	}()
	return ch
}

func readOne(t *testing.T, r reader) ([]byte, bool) {
	t.Helper()
	select {
	case b, ok := <-r:
		return b, ok
	case <-time.After(300 * time.Millisecond):
		return nil, false
	}
}

func TestFilter(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()
	me := d.ip4.String() // 100.64.0.2

	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)

	write := func(pkt []byte) bool {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{pkt}, 0); err != nil {
			t.Fatal(err)
		}
		return ft.nWrites() > before
	}

	// Allowed TCP flow; replies pass, unsolicited inbound does not.
	if !write(ipv4(me, "93.184.215.14", packet.ProtoTCP, tcpSeg(40000, 443, packet.FlagSYN))) {
		t.Fatal("SYN to 443 dropped")
	}
	ft.in <- ipv4("93.184.215.14", me, packet.ProtoTCP, tcpSeg(443, 40000, packet.FlagSYN|packet.FlagACK))
	if _, ok := readOne(t, rd); !ok {
		t.Fatal("SYN-ACK reply dropped")
	}
	ft.in <- ipv4("6.6.6.6", me, packet.ProtoTCP, tcpSeg(443, 40001, packet.FlagSYN))
	if _, ok := readOne(t, rd); ok {
		t.Fatal("unsolicited inbound passed")
	}

	tests := []struct {
		name  string
		pkt   []byte
		pass  bool
		reply bool // RST / ICMP injected
	}{
		{"port 25 blocked", ipv4(me, "198.51.100.1", packet.ProtoTCP, tcpSeg(40002, 25, packet.FlagSYN)), false, true},
		{"app rule skipped at edge", ipv4(me, "198.51.100.1", packet.ProtoTCP, tcpSeg(40003, 80, packet.FlagSYN)), true, false},
		{"mid-stream without state", ipv4(me, "198.51.100.1", packet.ProtoTCP, tcpSeg(40004, 80, packet.FlagACK)), false, false},
		{"spoofed source", ipv4("100.64.0.99", "198.51.100.1", packet.ProtoTCP, tcpSeg(40005, 80, packet.FlagSYN)), false, false},
		{"device to device without a mesh rule", ipv4(me, "100.64.0.3", packet.ProtoUDP, udpDgram(5000, 5000)), false, true},
		{"edge dns", ipv4(me, "100.64.0.1", packet.ProtoUDP, udpDgram(5001, 53)), true, false},
		{"edge other port", ipv4(me, "100.64.0.1", packet.ProtoUDP, udpDgram(5002, 22)), false, true},
		{"udp allowed", ipv4(me, "198.51.100.7", packet.ProtoUDP, udpDgram(5003, 443)), true, false},
	}
	for _, tc := range tests {
		if got := write(tc.pkt); got != tc.pass {
			t.Errorf("%s: pass=%v", tc.name, got)
		}
		b, ok := readOne(t, rd)
		if ok != tc.reply {
			t.Errorf("%s: reply=%v", tc.name, ok)
		}
		if ok {
			var p packet.Packet
			if err := packet.Parse(b, &p); err != nil || p.Dst.String() != me {
				t.Errorf("%s: bad reply %v %v", tc.name, p.Dst, err)
			}
			if p.Protocol == packet.ProtoTCP && !p.RST() {
				t.Errorf("%s: not an RST", tc.name)
			}
		}
	}

	// Domain rule via DNS snooping.
	fx.e.snoop.add(d.id, netip.MustParseAddr("192.0.2.10"), "x.tracker.test", time.Minute, time.Now())
	if write(ipv4(me, "192.0.2.10", packet.ProtoTCP, tcpSeg(40010, 443, packet.FlagSYN))) {
		t.Fatal("snooped tracker domain not blocked")
	}
	readOne(t, rd)

	// Ask: first packet dropped, the cloud verdict applies to the retransmission.
	fx.cp.mu.Lock()
	fx.cp.decide = func(dev string, fl policy.Flow) (api.DecideResponse, error) {
		if dev != "d1" || fl.App != "" {
			return api.DecideResponse{}, errors.New("bad request")
		}
		a := policy.ActionAllow
		if fl.DstIP == "203.0.113.66" {
			a = policy.ActionBlock
		}
		return api.DecideResponse{Decision: policy.Decision{Action: a, Layer: "cloud", RuleID: "decide:x"}, TTL: 300}, nil
	}
	fx.cp.mu.Unlock()
	syn := ipv4(me, "203.0.113.5", packet.ProtoTCP, tcpSeg(40020, 443, packet.FlagSYN))
	if write(syn) {
		t.Fatal("undecided first packet passed")
	}
	waitFor(t, func() bool {
		_, ok := fx.e.dec.lookup("d1", policy.Flow{Protocol: "tcp", DstIP: "203.0.113.5", DstPort: 443}, time.Now())
		return ok
	})
	if !write(syn) {
		t.Fatal("retransmission after allow verdict dropped")
	}
	bad := ipv4(me, "203.0.113.66", packet.ProtoTCP, tcpSeg(40021, 443, packet.FlagSYN))
	write(bad)
	waitFor(t, func() bool {
		_, ok := fx.e.dec.lookup("d1", policy.Flow{Protocol: "tcp", DstIP: "203.0.113.66", DstPort: 443}, time.Now())
		return ok
	})
	if write(bad) {
		t.Fatal("cloud-blocked flow passed")
	}
	readOne(t, rd)

	// Close the first flow and sweep: records are produced for allowed flows.
	write(ipv4(me, "93.184.215.14", packet.ProtoTCP, tcpSeg(40000, 443, packet.FlagRST)))
	recs := fx.e.ct.sweep(time.Now().Add(time.Minute), fx.e.owner)
	var found bool
	for _, r := range recs {
		if r.Flow.DstIP == "93.184.215.14" && r.Where == "edge" && r.DeviceID == "d1" && r.BytesOut > 0 && r.BytesIn > 0 {
			found = true
			if r.Flow.SrcIP != me {
				t.Fatalf("allowed record SrcIP: got %q, want %q", r.Flow.SrcIP, me)
			}
		}
	}
	if !found {
		t.Fatalf("no record for closed flow: %+v", recs)
	}
	// Blocked flows were reported immediately.
	var blocked []string
	for _, r := range fx.e.flows.recs {
		blocked = append(blocked, r.Decision.RuleID)
		if r.Flow.SrcIP != me {
			t.Fatalf("blocked record SrcIP: got %q, want %q", r.Flow.SrcIP, me)
		}
	}
	if got := strings.Join(blocked, ","); !strings.Contains(got, "no-smtp") || !strings.Contains(got, "no-tracker") || !strings.Contains(got, "decide:x") {
		t.Fatalf("blocked records: %s", got)
	}
	if err := fx.e.flows.flush(context.Background(), fx.cp); err != nil || fx.e.flows.pending() != 0 || len(fx.cp.posted) == 0 {
		t.Fatalf("flush: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAddrAt(t *testing.T) {
	tests := []struct {
		off    uint32
		v4, v6 string
	}{
		{2, "100.64.0.2", "fd7a:5a5e::2"},
		{256, "100.64.1.0", "fd7a:5a5e::100"},
		{maxOffset, "100.127.255.254", "fd7a:5a5e::3f:fffe"},
	}
	for _, tc := range tests {
		a4, a6 := addrAt(tc.off)
		if a4.String() != tc.v4 || a6.String() != tc.v6 || !TunnelPrefix4.Contains(a4) || !TunnelPrefix6.Contains(a6) {
			t.Errorf("%d: %s %s", tc.off, a4, a6)
		}
	}
}

// TestSessionProbe covers issue #70: the probe answers 204 only for the device's live
// session, so a client notices a lost session (Edge restart) without waiting for WireGuard.
func TestSessionProbe(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := fx.sessionServer()
	cert := fx.deviceCert("acme", "d1")
	c := fx.client(&cert)
	wgKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	code, sr, _ := postSession(t, c, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(wgKey.PublicKey().Bytes())})
	if code != 200 {
		t.Fatalf("session: %d", code)
	}
	probe := func(cl *http.Client, id string) int {
		t.Helper()
		resp, err := cl.Get(srv.URL + "/v1/session/" + id)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := probe(c, sr.SessionID); got != 204 {
		t.Fatalf("live session: %d", got)
	}
	if got := probe(c, "0123"); got != 404 {
		t.Fatalf("other session: %d", got)
	}
	fx.setPeer("d2", 2)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := fx.deviceCert("acme", "d2")
	if got := probe(fx.client(&other), sr.SessionID); got != 404 {
		t.Fatalf("another device probing d1's session: %d", got)
	}
}

// TestControlPlaneTunnelOffset covers issue #70: a new session uses the offset the Control
// Plane assigned, so the device has the same tunnel addresses on every Edge, and a local
// allocation never takes an offset reserved for another device.
func TestControlPlaneTunnelOffset(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	fx.setPeer("d2", 1)
	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		if fx.cp.peers.Devices[i].DeviceID == "d1" {
			fx.cp.peers.Devices[i].TunnelOffset = 2 // the address d2 would get locally
		}
	}
	fx.cp.mu.Unlock()
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := fx.sessionServer()
	session := func(id string) api.SessionResponse {
		t.Helper()
		cert := fx.deviceCert("acme", id)
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		code, sr, _ := postSession(t, fx.client(&cert), srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())})
		if code != 200 {
			t.Fatalf("session %s: %d", id, code)
		}
		return sr
	}
	// d2 (no offset from the Control Plane) comes first but must not take offset 2.
	if sr := session("d2"); sr.TunnelIPv4 == "100.64.0.2/32" {
		t.Fatal("local allocation took an offset reserved by the Control Plane")
	}
	if sr := session("d1"); sr.TunnelIPv4 != "100.64.0.2/32" || sr.TunnelIPv6 != "fd7a:5a5e::2/128" {
		t.Fatalf("d1 did not get its Control Plane offset: %+v", sr)
	}
}

// TestEdgeOps covers issue #73: readiness follows the first peer sync, and /metrics exposes
// the Edge series.
func TestEdgeOps(t *testing.T) {
	fx := newFixture(t)
	srv := httptest.NewServer(fx.e.opsHandler())
	defer srv.Close()
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/readyz"); code != 503 {
		t.Fatalf("ready before the first sync: %d", code)
	}
	fx.setPeer("d1", 1)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, _ := get("/readyz"); code != 200 {
		t.Fatalf("readyz after sync: %d", code)
	}
	fx.e.flows.add(api.FlowRecord{Decision: policy.Decision{Action: policy.ActionBlock, Layer: policy.LayerTenant}})
	code, body := get("/metrics")
	if code != 200 {
		t.Fatalf("metrics %d", code)
	}
	for _, want := range []string{"opensase_edge_devices 1\n", "opensase_edge_sessions 0\n", `opensase_edge_blocks_total{layer="tenant"} 1`, "opensase_edge_peer_sync_age_seconds "} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}

// TestFilterDNSRedirect covers issue #63: with dns.redirectQueries, plain IPv4 DNS to another
// resolver passes the filter (the kernel DNATs it to the Edge resolver); DNS over TLS and
// IPv6 DNS stay blocked.
func TestFilterDNSRedirect(t *testing.T) {
	fx := newFixture(t)
	fx.redir = true
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()
	me := d.ip4.String()
	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)
	write := func(pkt []byte) bool {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{pkt}, 0); err != nil {
			t.Fatal(err)
		}
		return ft.nWrites() > before
	}
	if !write(ipv4(me, "8.8.8.8", packet.ProtoUDP, udpDgram(42000, 53))) {
		t.Fatal("redirected DNS over UDP dropped")
	}
	if !write(ipv4(me, "8.8.4.4", packet.ProtoTCP, tcpSeg(42001, 53, packet.FlagSYN))) {
		t.Fatal("redirected DNS over TCP dropped")
	}
	if write(ipv4(me, "1.1.1.1", packet.ProtoTCP, tcpSeg(42002, 853, packet.FlagSYN))) {
		t.Fatal("DNS over TLS passed")
	}
	readOne(t, rd)
}

// TestFilterMesh covers ADR-0034 on the Edge path: a flow allowed by the target's mesh
// grant passes both ways; other ports, other devices and other tenants do not.
func TestFilterMesh(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	fx.setPeer("d2", 1)
	// d2 accepts TCP 22 from user u1 (setPeer's user).
	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		if fx.cp.peers.Devices[i].DeviceID != "d2" {
			continue
		}
		var env = fx.cp.peers.Devices[i].Snapshot
		snap, err := policy.Verify(&env, map[string]ed25519.PublicKey{fx.kid: fx.sk.Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		snap.Version++
		snap.MeshInbound = []policy.MeshGrant{{RuleID: "ssh", FromUsers: []string{"u1"}, Protocol: "tcp", Ports: []policy.PortRange{{From: 22}}}}
		signed, err := policy.Sign(snap, fx.kid, fx.sk)
		if err != nil {
			t.Fatal(err)
		}
		fx.cp.peers.Devices[i].Snapshot = *signed
	}
	fx.cp.mu.Unlock()
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := fx.e.reg
	r.mu.Lock()
	d1, d2 := r.devices["d1"], r.devices["d2"]
	_ = r.allocateLocked(d1)
	_ = r.allocateLocked(d2)
	d2.hasPeer = true
	r.mu.Unlock()
	a, b := d1.ip4.String(), d2.ip4.String()
	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)
	write := func(pkt []byte) bool {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{pkt}, 0); err != nil {
			t.Fatal(err)
		}
		return ft.nWrites() > before
	}
	if !write(ipv4(a, b, packet.ProtoTCP, tcpSeg(43000, 22, packet.FlagSYN))) {
		t.Fatal("allowed mesh SYN dropped")
	}
	// The kernel hands the packet back toward d2: inbound must pass it.
	ft.in <- ipv4(a, b, packet.ProtoTCP, tcpSeg(43000, 22, packet.FlagSYN))
	if _, ok := readOne(t, rd); !ok {
		t.Fatal("mesh packet toward the target dropped")
	}
	// d2's reply passes outbound and comes back to d1.
	if !write(ipv4(b, a, packet.ProtoTCP, tcpSeg(22, 43000, packet.FlagSYN|packet.FlagACK))) {
		t.Fatal("mesh reply dropped")
	}
	ft.in <- ipv4(b, a, packet.ProtoTCP, tcpSeg(22, 43000, packet.FlagSYN|packet.FlagACK))
	if _, ok := readOne(t, rd); !ok {
		t.Fatal("mesh reply toward the source dropped")
	}
	if write(ipv4(a, b, packet.ProtoTCP, tcpSeg(43001, 80, packet.FlagSYN))) {
		t.Fatal("port without a grant passed")
	}
	readOne(t, rd)
	// d2 opens a flow to d1: d1 grants nothing.
	if write(ipv4(b, a, packet.ProtoTCP, tcpSeg(43002, 22, packet.FlagSYN))) {
		t.Fatal("flow toward a device without grants passed")
	}
	readOne(t, rd)

	t.Run("ipv6", func(t *testing.T) {
		fx6 := newFixture(t)
		fx6.setPeer("d1", 1)
		fx6.setPeer("d2", 1)
		setMesh := func(id string, grants []policy.MeshGrant) {
			fx6.cp.mu.Lock()
			defer fx6.cp.mu.Unlock()
			for i := range fx6.cp.peers.Devices {
				if fx6.cp.peers.Devices[i].DeviceID != id {
					continue
				}
				env := fx6.cp.peers.Devices[i].Snapshot
				snap, err := policy.Verify(&env, map[string]ed25519.PublicKey{fx6.kid: fx6.sk.Public().(ed25519.PublicKey)})
				if err != nil {
					t.Fatal(err)
				}
				snap.Version++
				snap.MeshInbound = grants
				signed, err := policy.Sign(snap, fx6.kid, fx6.sk)
				if err != nil {
					t.Fatal(err)
				}
				fx6.cp.peers.Devices[i].Snapshot = *signed
			}
		}
		// d2 grants TCP 22 and ICMPv6 only; d1 grants "icmp" (which matches ICMPv6 too).
		setMesh("d2", []policy.MeshGrant{
			{RuleID: "ssh", FromUsers: []string{"u1"}, Protocol: "tcp", Ports: []policy.PortRange{{From: 22}}},
			{RuleID: "ping6", FromUsers: []string{"u1"}, Protocol: "icmpv6"},
		})
		setMesh("d1", []policy.MeshGrant{
			{RuleID: "ping-any", FromUsers: []string{"u1"}, Protocol: "icmp"},
		})
		if err := fx6.e.syncPeers(context.Background()); err != nil {
			t.Fatal(err)
		}
		r6 := fx6.e.reg
		r6.mu.Lock()
		dev1, dev2 := r6.devices["d1"], r6.devices["d2"]
		_ = r6.allocateLocked(dev1)
		_ = r6.allocateLocked(dev2)
		dev1.hasPeer, dev2.hasPeer = true, true
		a4, b4 := dev1.ip4.String(), dev2.ip4.String()
		a6, b6 := dev1.ip6.String(), dev2.ip6.String()
		r6.mu.Unlock()

		ft6 := newFakeTUN()
		f6 := newFilter(ft6, fx6.e)
		defer f6.Close()
		rd6 := startReader(f6)
		write6 := func(pkt []byte) bool {
			before := ft6.nWrites()
			if _, err := f6.Write([][]byte{pkt}, 0); err != nil {
				t.Fatal(err)
			}
			return ft6.nWrites() > before
		}

		// Allowed IPv6 TCP 22 passes both ways.
		if !write6(ipv6(a6, b6, packet.ProtoTCP, tcpSeg(43100, 22, packet.FlagSYN))) {
			t.Fatal("allowed ipv6 mesh SYN dropped")
		}
		ft6.in <- ipv6(a6, b6, packet.ProtoTCP, tcpSeg(43100, 22, packet.FlagSYN))
		if _, ok := readOne(t, rd6); !ok {
			t.Fatal("ipv6 mesh SYN toward target dropped")
		}
		if !write6(ipv6(b6, a6, packet.ProtoTCP, tcpSeg(22, 43100, packet.FlagSYN|packet.FlagACK))) {
			t.Fatal("ipv6 mesh TCP reply dropped")
		}
		ft6.in <- ipv6(b6, a6, packet.ProtoTCP, tcpSeg(22, 43100, packet.FlagSYN|packet.FlagACK))
		if _, ok := readOne(t, rd6); !ok {
			t.Fatal("ipv6 mesh TCP reply toward source dropped")
		}

		// Allowed IPv6 ICMPv6 echo (matched by Protocol: "icmpv6") passes both ways.
		if !write6(ipv6(a6, b6, packet.ProtoICMPv6, icmpMsg(128, 0, 42))) {
			t.Fatal("allowed ipv6 mesh echo request dropped")
		}
		ft6.in <- ipv6(a6, b6, packet.ProtoICMPv6, icmpMsg(128, 0, 42))
		if _, ok := readOne(t, rd6); !ok {
			t.Fatal("ipv6 mesh echo request toward target dropped")
		}
		if !write6(ipv6(b6, a6, packet.ProtoICMPv6, icmpMsg(129, 0, 42))) {
			t.Fatal("ipv6 mesh echo reply dropped")
		}
		ft6.in <- ipv6(b6, a6, packet.ProtoICMPv6, icmpMsg(129, 0, 42))
		if _, ok := readOne(t, rd6); !ok {
			t.Fatal("ipv6 mesh echo reply toward source dropped")
		}

		// Table-driven mesh checks: icmp grant allows ICMPv6; icmpv6 grant rejects ICMPv4;
		// ungranted ports and non-echo ICMPv6 are rejected or dropped.
		meshTests := []struct {
			name  string
			pkt   []byte
			pass  bool
			reply bool
		}{
			{"icmp grant allows ipv6 echo", ipv6(b6, a6, packet.ProtoICMPv6, icmpMsg(128, 0, 43)), true, false},
			{"icmpv6 grant denies ipv4 echo", ipv4(a4, b4, packet.ProtoICMP, icmpMsg(8, 0, 44)), false, true},
			{"ungranted ipv6 tcp port", ipv6(a6, b6, packet.ProtoTCP, tcpSeg(43101, 80, packet.FlagSYN)), false, true},
			{"ungranted ipv6 tcp toward d1", ipv6(b6, a6, packet.ProtoTCP, tcpSeg(43102, 22, packet.FlagSYN)), false, true},
			{"non-echo ipv6 icmpv6 dropped silently", ipv6(a6, b6, packet.ProtoICMPv6, icmpMsg(135, 0, 45)), false, false},
		}
		for _, tc := range meshTests {
			if got := write6(tc.pkt); got != tc.pass {
				t.Errorf("%s: pass=%v want %v", tc.name, got, tc.pass)
			}
			_, ok := readOne(t, rd6)
			if ok != tc.reply {
				t.Errorf("%s: reply=%v want %v", tc.name, ok, tc.reply)
			}
		}
	})
}

func TestFilterIPv6(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	// Add UDP and ICMPv6 rules alongside the default fixture rules.
	fx.cp.mu.Lock()
	env := fx.cp.peers.Devices[0].Snapshot
	snap, err := policy.Verify(&env, map[string]ed25519.PublicKey{fx.kid: fx.sk.Public().(ed25519.PublicKey)})
	if err != nil {
		fx.cp.mu.Unlock()
		t.Fatal(err)
	}
	snap.Version++
	snap.Firewall.Rules = append(snap.Firewall.Rules,
		policy.Rule{ID: "no-udp-9999", Source: policy.SourceTenant, Priority: 5, Action: policy.ActionBlock, Match: policy.Match{Protocols: []string{"udp"}, Ports: []policy.PortRange{{From: 9999}}}},
		policy.Rule{ID: "no-icmpv6-net", Source: policy.SourceTenant, Priority: 6, Action: policy.ActionBlock, Match: policy.Match{Protocols: []string{"icmpv6"}, CIDRs: []string{"2001:db8:dead::/48"}}},
	)
	signed, err := policy.Sign(snap, fx.kid, fx.sk)
	if err != nil {
		fx.cp.mu.Unlock()
		t.Fatal(err)
	}
	fx.cp.peers.Devices[0].Snapshot = *signed
	fx.cp.mu.Unlock()

	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	me6 := d.ip6.String() // fd7a:5a5e::2
	fx.e.reg.mu.Unlock()

	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)
	write := func(pkt []byte) bool {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{pkt}, 0); err != nil {
			t.Fatal(err)
		}
		return ft.nWrites() > before
	}

	// Stateful IPv6 TCP: outbound SYN passes, matching SYN-ACK passes, unsolicited inbound drops.
	if !write(ipv6(me6, "2001:db8::10", packet.ProtoTCP, tcpSeg(40000, 443, packet.FlagSYN))) {
		t.Fatal("IPv6 SYN to 443 dropped")
	}
	ft.in <- ipv6("2001:db8::10", me6, packet.ProtoTCP, tcpSeg(443, 40000, packet.FlagSYN|packet.FlagACK))
	if _, ok := readOne(t, rd); !ok {
		t.Fatal("IPv6 SYN-ACK reply dropped")
	}
	ft.in <- ipv6("2001:db8::99", me6, packet.ProtoTCP, tcpSeg(443, 40001, packet.FlagSYN))
	if _, ok := readOne(t, rd); ok {
		t.Fatal("unsolicited IPv6 inbound passed")
	}

	tests := []struct {
		name  string
		pkt   []byte
		pass  bool
		reply bool
		rule  string
	}{
		{"tcp allowed", ipv6(me6, "2001:db8::1", packet.ProtoTCP, tcpSeg(40002, 443, packet.FlagSYN)), true, false, ""},
		{"tcp port 25 blocked", ipv6(me6, "2001:db8::1", packet.ProtoTCP, tcpSeg(40003, 25, packet.FlagSYN)), false, true, "no-smtp"},
		{"udp allowed", ipv6(me6, "2001:db8::2", packet.ProtoUDP, udpDgram(5001, 443)), true, false, ""},
		{"udp port 9999 blocked", ipv6(me6, "2001:db8::2", packet.ProtoUDP, udpDgram(5002, 9999)), false, true, "no-udp-9999"},
		{"icmpv6 echo allowed", ipv6(me6, "2001:db8::3", packet.ProtoICMPv6, icmpMsg(128, 0, 7)), true, false, ""},
		{"icmpv6 echo blocked by icmpv6 rule", ipv6(me6, "2001:db8:dead::1", packet.ProtoICMPv6, icmpMsg(128, 0, 8)), false, true, "no-icmpv6-net"},
		{"icmpv6 non-echo dropped silently", ipv6(me6, "2001:db8::3", packet.ProtoICMPv6, icmpMsg(135, 0, 9)), false, false, ""},
		{"edge ipv6 dns allowed", ipv6(me6, EdgeIPv6.String(), packet.ProtoUDP, udpDgram(5003, 53)), true, false, ""},
		{"edge ipv6 ping allowed", ipv6(me6, EdgeIPv6.String(), packet.ProtoICMPv6, icmpMsg(128, 0, 10)), true, false, ""},
		{"edge ipv6 other port blocked", ipv6(me6, EdgeIPv6.String(), packet.ProtoUDP, udpDgram(5004, 22)), false, true, ""},
		{"nat64 well-known denied", ipv6(me6, "64:ff9b::a9fe:a9fe", packet.ProtoTCP, tcpSeg(40010, 80, packet.FlagSYN)), false, true, RuleBuiltinDeny},
		{"nat64 local-use denied", ipv6(me6, "64:ff9b:1::1", packet.ProtoTCP, tcpSeg(40011, 80, packet.FlagSYN)), false, true, RuleBuiltinDeny},
		{"discard-only denied", ipv6(me6, "100::1", packet.ProtoTCP, tcpSeg(40012, 80, packet.FlagSYN)), false, true, RuleBuiltinDeny},
		{"ipv6 benchmarking denied", ipv6(me6, "2001:2::1", packet.ProtoTCP, tcpSeg(40013, 80, packet.FlagSYN)), false, true, RuleBuiltinDeny},
		{"device to device ipv6 without mesh rule", ipv6(me6, "fd7a:5a5e::3", packet.ProtoUDP, udpDgram(5005, 5005)), false, true, RuleMeshDenied},
	}
	for _, tc := range tests {
		fx.e.flows.mu.Lock()
		recStart := len(fx.e.flows.recs)
		fx.e.flows.mu.Unlock()
		if got := write(tc.pkt); got != tc.pass {
			t.Errorf("%s: pass=%v want %v", tc.name, got, tc.pass)
		}
		b, ok := readOne(t, rd)
		if ok != tc.reply {
			t.Errorf("%s: reply=%v want %v", tc.name, ok, tc.reply)
		}
		if ok {
			var p packet.Packet
			if err := packet.Parse(b, &p); err != nil || p.Version != 6 || p.Dst.String() != me6 {
				t.Errorf("%s: bad reply version=%d dst=%v err=%v", tc.name, p.Version, p.Dst, err)
			}
			switch p.Protocol {
			case packet.ProtoTCP:
				if !p.RST() {
					t.Errorf("%s: TCP reply is not RST", tc.name)
				}
			case packet.ProtoICMPv6:
				if p.ICMPType != 1 || p.ICMPCode != 1 {
					t.Errorf("%s: ICMPv6 reply type=%d code=%d, want 1/1", tc.name, p.ICMPType, p.ICMPCode)
				}
			}
		}
		if tc.rule != "" {
			fx.e.flows.mu.Lock()
			var gotRule string
			if len(fx.e.flows.recs) > recStart {
				gotRule = fx.e.flows.recs[len(fx.e.flows.recs)-1].Decision.RuleID
			}
			fx.e.flows.mu.Unlock()
			if gotRule != tc.rule {
				t.Errorf("%s: rule=%q want %q", tc.name, gotRule, tc.rule)
			}
		}
	}

	// Stateful inbound ICMPv6 echo reply passes for the allowed echo request.
	ft.in <- ipv6("2001:db8::3", me6, packet.ProtoICMPv6, icmpMsg(129, 0, 7))
	if _, ok := readOne(t, rd); !ok {
		t.Fatal("ICMPv6 echo reply dropped")
	}

	// Verify flow records include Protocol "icmpv6" (DstPort 0) and the expected block rules.
	fx.e.flows.mu.Lock()
	recs := append([]api.FlowRecord(nil), fx.e.flows.recs...)
	fx.e.flows.mu.Unlock()
	var sawICMPv6, sawNAT64 bool
	for _, r := range recs {
		if r.Decision.RuleID == "no-icmpv6-net" {
			sawICMPv6 = true
			if r.Flow.Protocol != "icmpv6" || r.Flow.DstPort != 0 || r.Flow.SrcIP != me6 {
				t.Errorf("icmpv6 block record = %+v", r.Flow)
			}
		}
		if r.Decision.RuleID == RuleBuiltinDeny && r.Flow.DstIP == "64:ff9b::a9fe:a9fe" {
			sawNAT64 = true
		}
	}
	if !sawICMPv6 || !sawNAT64 {
		t.Fatalf("missing expected flow records: sawICMPv6=%v sawNAT64=%v recs=%+v", sawICMPv6, sawNAT64, recs)
	}

	t.Run("protocols icmpv6 excludes icmpv4", func(t *testing.T) {
		fx2 := newFixture(t)
		fx2.setPeer("d1", 1)
		fx2.cp.mu.Lock()
		env := fx2.cp.peers.Devices[0].Snapshot
		s2, err := policy.Verify(&env, map[string]ed25519.PublicKey{fx2.kid: fx2.sk.Public().(ed25519.PublicKey)})
		if err != nil {
			fx2.cp.mu.Unlock()
			t.Fatal(err)
		}
		s2.Version++
		s2.Firewall.Rules = []policy.Rule{
			{ID: "no-icmpv6", Source: policy.SourceTenant, Priority: 1, Action: policy.ActionBlock, Match: policy.Match{Protocols: []string{"icmpv6"}}},
		}
		signed2, err := policy.Sign(s2, fx2.kid, fx2.sk)
		if err != nil {
			fx2.cp.mu.Unlock()
			t.Fatal(err)
		}
		fx2.cp.peers.Devices[0].Snapshot = *signed2
		fx2.cp.mu.Unlock()
		if err := fx2.e.syncPeers(context.Background()); err != nil {
			t.Fatal(err)
		}
		dev := fx2.e.reg.get("d1")
		fx2.e.reg.mu.Lock()
		_ = fx2.e.reg.allocateLocked(dev)
		v4, v6 := dev.ip4.String(), dev.ip6.String()
		fx2.e.reg.mu.Unlock()

		ft2 := newFakeTUN()
		f2 := newFilter(ft2, fx2.e)
		defer f2.Close()
		rd2 := startReader(f2)
		write2 := func(pkt []byte) bool {
			before := ft2.nWrites()
			if _, err := f2.Write([][]byte{pkt}, 0); err != nil {
				t.Fatal(err)
			}
			return ft2.nWrites() > before
		}

		if write2(ipv6(v6, "2001:db8::5", packet.ProtoICMPv6, icmpMsg(128, 0, 11))) {
			t.Fatal("ICMPv6 echo passed despite protocols:[icmpv6] block rule")
		}
		if _, ok := readOne(t, rd2); !ok {
			t.Fatal("no ICMPv6 unreachable for blocked ICMPv6 echo")
		}
		if !write2(ipv4(v4, "198.51.100.5", packet.ProtoICMP, icmpMsg(8, 0, 12))) {
			t.Fatal("ICMPv4 echo wrongly blocked by protocols:[icmpv6] rule")
		}
	})

	t.Run("cross-family snoop AAAA over ipv4 blocks tcp over ipv6", func(t *testing.T) {
		fx3 := newFixture(t)
		fx3.setPeer("d1", 1)
		if err := fx3.e.syncPeers(context.Background()); err != nil {
			t.Fatal(err)
		}
		r3 := fx3.e.reg
		r3.mu.Lock()
		dev := r3.devices["d1"]
		dev.offset, dev.ip4, dev.ip6 = 2, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd7a:5a5e::2")
		r3.reindexLocked()
		r3.mu.Unlock()

		upstream := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			q := req.Question[0]
			if q.Qtype == dns.TypeAAAA {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::cafe"),
				})
			}
			_ = w.WriteMsg(m)
		}))
		edgeDNS := startDNS(t, newResolver(fx3.e, upstream))

		// Resolve AAAA over IPv4 (127.0.0.1).
		q := new(dns.Msg)
		q.SetQuestion("x.tracker.test.", dns.TypeAAAA)
		resp, _, err := new(dns.Client).Exchange(q, edgeDNS)
		if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("AAAA over IPv4: resp=%v err=%v", resp, err)
		}

		// Connect over IPv6 from fd7a:5a5e::2 to the resolved AAAA address.
		ft3 := newFakeTUN()
		f3 := newFilter(ft3, fx3.e)
		defer f3.Close()
		rd3 := startReader(f3)
		before := ft3.nWrites()
		if _, err := f3.Write([][]byte{ipv6("fd7a:5a5e::2", "2001:db8::cafe", packet.ProtoTCP, tcpSeg(41000, 443, packet.FlagSYN))}, 0); err != nil {
			t.Fatal(err)
		}
		if ft3.nWrites() > before {
			t.Fatal("cross-family snooped tracker domain passed over IPv6")
		}
		b, ok := readOne(t, rd3)
		if !ok {
			t.Fatal("no IPv6 TCP RST for cross-family blocked flow")
		}
		var rp packet.Packet
		if err := packet.Parse(b, &rp); err != nil || rp.Version != 6 || rp.Protocol != packet.ProtoTCP || !rp.RST() || rp.Dst.String() != "fd7a:5a5e::2" {
			t.Fatalf("unexpected reply %+v err=%v", rp, err)
		}
		fx3.e.flows.mu.Lock()
		var matched bool
		for _, rec := range fx3.e.flows.recs {
			if rec.DeviceID == "d1" && rec.Decision.RuleID == "no-tracker" && rec.Flow.Domain == "x.tracker.test" && rec.Flow.DstIP == "2001:db8::cafe" {
				matched = true
				break
			}
		}
		fx3.e.flows.mu.Unlock()
		if !matched {
			t.Fatal("cross-family domain block not recorded with domain")
		}

		// Snoop sweep retains live device IDs and drops removed device IDs.
		fx3.e.snoop.add("d-gone", netip.MustParseAddr("2001:db8::beef"), "gone.test", time.Minute, time.Now())
		fx3.e.snoop.sweep(time.Now(), func(id string) bool { return fx3.e.reg.get(id) != nil })
		if got := fx3.e.snoop.lookup("d1", netip.MustParseAddr("2001:db8::cafe")); got != "x.tracker.test" {
			t.Errorf("live device snoop entry evicted: got %q", got)
		}
		if got := fx3.e.snoop.lookup("d-gone", netip.MustParseAddr("2001:db8::beef")); got != "" {
			t.Errorf("removed device snoop entry kept: got %q", got)
		}
	})
}
