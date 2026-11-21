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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/api"
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
	apps   []policy.PrivateApp // PrivateApps of the snapshots setPeer publishes
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
	if _, err := auth.TenantCA("acme"); err != nil {
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
		}},
		PrivateApps: fx.apps,
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
	ca, err := fx.auth.TenantCA(tenant)
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
		{"device to device", ipv4(me, "100.64.0.3", packet.ProtoUDP, udpDgram(5000, 5000)), false, false},
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
	fx.e.snoop.add(d.ip4, netip.MustParseAddr("192.0.2.10"), "x.tracker.test", time.Minute, time.Now())
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
		}
	}
	if !found {
		t.Fatalf("no record for closed flow: %+v", recs)
	}
	// Blocked flows were reported immediately.
	var blocked []string
	for _, r := range fx.e.flows.recs {
		blocked = append(blocked, r.Decision.RuleID)
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
