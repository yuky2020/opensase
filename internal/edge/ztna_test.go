package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/yuky2020/opensase/internal/connector"
	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// stubResolver resolves every name to 127.0.0.1 (the test backend).
type stubResolver struct{}

func (stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// echoServer accepts connections, echoes until EOF, then closes.
func echoServer(t *testing.T) uint16 {
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
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func (fx *fixture) connectorCert(tenant, id string) tls.Certificate {
	fx.t.Helper()
	ca, err := fx.auth.TenantCA(context.Background(), tenant)
	if err != nil {
		fx.t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	chain, _, err := ca.SignConnectorCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), tenant, id, 0)
	if err != nil {
		fx.t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	c, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.setSerial("connector:"+id, c)
	return c
}

type ztnaFixture struct {
	*fixture
	ctx        context.Context
	brokerAddr string
	backend    uint16
	synthIP    netip.Addr
	dev        *device
	rootPool   *x509.CertPool
}

// newZTNAFixture: device d1 entitled to intranet.acme.internal on the backend port and the
// next one; connector c1 (group default) whose own config allows only the backend port.
func newZTNAFixture(t *testing.T) *ztnaFixture {
	fx := newFixture(t)
	backend := echoServer(t)
	fx.apps = []policy.PrivateApp{{ID: "intranet", Name: "Intranet", Domains: []string{"intranet.acme.internal"},
		Ports: []policy.PortRange{{From: backend, To: backend + 1}}, ConnectorGroup: "default"}}
	fx.setPeer("d1", 1)
	fx.cp.mu.Lock()
	fx.cp.peers.Connectors = []api.EdgeConnector{{ConnectorID: "c1", TenantID: "acme", Group: "default"}}
	fx.cp.mu.Unlock()
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go fx.e.serveConnectors(ctx, ln)
	synthIP, _ := fx.e.synth.assign("acme", "intranet.acme.internal", time.Now())
	pool := x509.NewCertPool()
	pool.AddCert(fx.auth.Root.Cert)
	return &ztnaFixture{fixture: fx, ctx: ctx, brokerAddr: ln.Addr().String(), backend: backend, synthIP: synthIP, dev: d, rootPool: pool}
}

// startConnector runs a connector broker link with the given identity.
func (z *ztnaFixture) startConnector(tenant, id string) context.CancelFunc {
	cert := z.connectorCert(tenant, id)
	ctx, cancel := context.WithCancel(z.ctx)
	z.t.Cleanup(cancel)
	apps := []policy.PrivateApp{{ID: "intranet", Domains: []string{"intranet.acme.internal"}, Ports: []policy.PortRange{{From: z.backend}}, ConnectorGroup: "default"}}
	l := &connector.Link{
		Edge:    api.EdgeInfo{ID: "edge-1", BrokerAddr: z.brokerAddr},
		TLS:     connector.EdgeTLSConfig(z.rootPool, func() *tls.Certificate { return &cert }, "edge-1", "localhost"),
		Handler: &connector.DialHandler{Apps: func() []policy.PrivateApp { return apps }, Resolver: stubResolver{}, AllowLoopback: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	go l.Run(ctx)
	return cancel
}

// dial opens a client connection as if the kernel had redirected the device's connection
// to synthetic address:port to the broker listener.
func (z *ztnaFixture) dial(port uint16) *net.TCPConn {
	z.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		z.t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		z.t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		z.t.Fatal(err)
	}
	z.t.Cleanup(func() { _ = c.Close() })
	go z.e.brokerConn(z.ctx, s, netip.AddrPortFrom(z.dev.ip4, 40000), netip.AddrPortFrom(z.synthIP, port))
	return c.(*net.TCPConn)
}

// roundTrip sends msg, half-closes and reads everything back.
func roundTrip(t *testing.T, c *net.TCPConn, msg string) (string, error) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	_ = c.CloseWrite()
	b, err := io.ReadAll(c)
	return string(b), err
}

func (z *ztnaFixture) records() []api.FlowRecord {
	z.e.flows.mu.Lock()
	defer z.e.flows.mu.Unlock()
	var out []api.FlowRecord
	for _, r := range z.e.flows.recs {
		if r.Decision.Layer == LayerZTNA {
			out = append(out, r)
		}
	}
	return out
}

func (z *ztnaFixture) waitRecord(rule string, action policy.Action) api.FlowRecord {
	z.t.Helper()
	var got api.FlowRecord
	waitFor(z.t, func() bool {
		for _, r := range z.records() {
			if r.Decision.RuleID == rule && r.Decision.Action == action {
				got = r
				return true
			}
		}
		return false
	})
	return got
}

func TestBrokerEndToEnd(t *testing.T) {
	z := newZTNAFixture(t)
	z.startConnector("acme", "c1")
	waitFor(t, func() bool { return slices.Equal(z.e.hub.liveIDs(), []string{"c1"}) })

	// Entitled name and port: bytes flow both ways through the connector (PQ TLS + HTTP/2).
	got, err := roundTrip(t, z.dial(z.backend), "hello from device")
	if err != nil || got != "hello from device" {
		t.Fatalf("echo %q %v", got, err)
	}
	rec := z.waitRecord("ztna:intranet", policy.ActionAllow)
	if rec.Where != "edge" || rec.DeviceID != "d1" || rec.Flow.Domain != "intranet.acme.internal" || rec.BytesOut != 17 || rec.BytesIn != 17 {
		t.Fatalf("allow record %+v", rec)
	}

	// A larger transfer, to cross HTTP/2 flow-control windows.
	big := make([]byte, 1<<20)
	_, _ = rand.Read(big)
	if got, err := roundTrip(t, z.dial(z.backend), string(big)); err != nil || got != string(big) {
		t.Fatalf("1 MiB echo: %d bytes, %v", len(got), err)
	}

	// Several concurrent streams over the one connector connection.
	errc := make(chan error, 8)
	for i := range 8 {
		go func() {
			msg := string(rune('a' + i))
			got, err := roundTrip(t, z.dial(z.backend), msg)
			if err == nil && got != msg {
				err = io.ErrUnexpectedEOF
			}
			errc <- err
		}()
	}
	for range 8 {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
}

func TestBrokerRefusals(t *testing.T) {
	z := newZTNAFixture(t)
	z.startConnector("acme", "c1")
	waitFor(t, func() bool { return len(z.e.hub.liveIDs()) == 1 })

	tests := []struct {
		name string
		port uint16
		rule string
	}{
		// The device snapshot entitles backend+1, but the connector's own config does not:
		// the connector answers 403 (second enforcement point).
		{"connector 403", z.backend + 1, "ztna:intranet:connector-403"},
		// Not entitled in the device snapshot: refused at the Edge.
		{"edge port check", z.backend + 2, "ztna:intranet:port"},
	}
	for _, tc := range tests {
		got, _ := roundTrip(t, z.dial(tc.port), "x")
		if got != "" {
			t.Errorf("%s: got data %q", tc.name, got)
		}
		z.waitRecord(tc.rule, policy.ActionBlock)
	}

	// Unknown synthetic address and a source that is not a device.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	c, _ := net.Dial("tcp", ln.Addr().String())
	s, _ := ln.Accept()
	z.e.brokerConn(z.ctx, s, netip.AddrPortFrom(netip.MustParseAddr("100.64.9.9"), 1), netip.AddrPortFrom(z.synthIP, z.backend))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("non-device source got data")
	}
	_ = c.Close()
	z.synthIP = netip.MustParseAddr("100.96.77.77")
	if got, _ := roundTrip(t, z.dial(z.backend), "x"); got != "" {
		t.Fatal("unknown address got data")
	}
	z.waitRecord("ztna:unknown-address", policy.ActionBlock)
}

func TestBrokerConnectorAdmission(t *testing.T) {
	z := newZTNAFixture(t)
	// A connector absent from the peer feed, and one of another tenant claiming c1's ID,
	// are refused after the handshake.
	z.cp.mu.Lock()
	z.cp.peers.Connectors = append(z.cp.peers.Connectors, api.EdgeConnector{ConnectorID: "c3", TenantID: "acme", Group: "default"})
	z.cp.mu.Unlock()
	_ = z.e.syncPeers(context.Background())
	if _, err := z.auth.TenantCA(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	_ = z.e.syncPeers(context.Background()) // reload the bundle with the globex CA
	for _, tc := range []struct{ tenant, id string }{{"acme", "c2"}, {"globex", "c3"}} {
		cert := z.connectorCert(tc.tenant, tc.id)
		cfg := connector.EdgeTLSConfig(z.rootPool, func() *tls.Certificate { return &cert }, "edge-1", "localhost")
		tc2, err := connector.DialEdge(z.ctx, z.brokerAddr, cfg)
		if err != nil {
			continue // refused in the handshake is fine too
		}
		_ = tc2.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := tc2.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s/%s: connection stayed open", tc.tenant, tc.id)
		}
		_ = tc2.Close()
	}
	if ids := z.e.hub.liveIDs(); len(ids) != 0 {
		t.Fatalf("live connectors %v", ids)
	}
	// A device certificate is not a connector certificate.
	dcert := z.deviceCert("acme", "d1")
	cfg := connector.EdgeTLSConfig(z.rootPool, func() *tls.Certificate { return &dcert }, "edge-1", "localhost")
	if tc2, err := connector.DialEdge(z.ctx, z.brokerAddr, cfg); err == nil {
		_ = tc2.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := tc2.Read(make([]byte, 1)); err == nil {
			t.Error("device certificate admitted as connector")
		}
		_ = tc2.Close()
	}
	// The connector checks the Edge identity: a link expecting another edge ID fails.
	cert := z.connectorCert("acme", "c1")
	if _, err := connector.DialEdge(z.ctx, z.brokerAddr, connector.EdgeTLSConfig(z.rootPool, func() *tls.Certificate { return &cert }, "edge-2", "localhost")); err == nil {
		t.Fatal("connector accepted the wrong edge identity")
	}
}

func TestBrokerRevokedConnectorDropped(t *testing.T) {
	z := newZTNAFixture(t)
	z.startConnector("acme", "c1")
	waitFor(t, func() bool { return len(z.e.hub.liveIDs()) == 1 })

	// The live connector is reported to the Control Plane.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go z.e.reportLoop(ctx)
	z.e.triggerReport()
	waitFor(t, func() bool {
		z.cp.mu.Lock()
		defer z.cp.mu.Unlock()
		for _, ids := range z.cp.reportedConnectors {
			if slices.Equal(ids, []string{"c1"}) {
				return true
			}
		}
		return false
	})

	// An open brokered stream.
	open := z.dial(z.backend)
	_ = open.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := open.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(open, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("open stream: %q %v", buf, err)
	}

	// Revocation: the next peer sync drops the connector and cuts its streams.
	z.cp.mu.Lock()
	z.cp.peers.Connectors = nil
	z.cp.mu.Unlock()
	if err := z.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(z.e.hub.liveIDs()) == 0 })
	if _, err := io.ReadAll(open); err != nil {
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
			t.Fatal("brokered stream survived the revocation")
		}
	}
	if got, _ := roundTrip(t, z.dial(z.backend), "x"); got != "" {
		t.Fatal("revoked connector still brokers")
	}
	z.waitRecord("ztna:intranet:no-connector", policy.ActionBlock)
	// The link keeps retrying but stays refused.
	time.Sleep(1500 * time.Millisecond)
	if ids := z.e.hub.liveIDs(); len(ids) != 0 {
		t.Fatalf("revoked connector re-admitted: %v", ids)
	}
}

// A connector enrolled after the last peer sync is admitted through an on-demand sync, not
// only after the next periodic one.
func TestBrokerConnectorOnDemandSync(t *testing.T) {
	z := newZTNAFixture(t)
	z.cp.mu.Lock()
	z.cp.peers.Connectors = append(z.cp.peers.Connectors, api.EdgeConnector{ConnectorID: "c5", TenantID: "acme", Group: "default"})
	z.cp.mu.Unlock()
	z.startConnector("acme", "c5") // no syncPeers call here
	waitFor(t, func() bool { return slices.Contains(z.e.hub.liveIDs(), "c5") })
}
