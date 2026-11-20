package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func serverCert(t *testing.T, root *CA, o ServerCertOptions) tls.Certificate {
	t.Helper()
	o.DNSNames = []string{"localhost"} // shared on purpose: only the URI tells them apart
	c, k, err := root.IssueServerCert(o)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(append(c, root.CertPEM()...), k)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// handshake runs a TLS handshake over a pipe and returns the client-side error.
func handshake(t *testing.T, srvCfg, cliCfg *tls.Config) error {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		s := tls.Server(a, srvCfg)
		_ = s.HandshakeContext(ctx)
		s.Close()
	}()
	c := tls.Client(b, cliCfg)
	defer c.Close()
	return c.HandshakeContext(ctx)
}

func TestExpectServer(t *testing.T) {
	root, _ := NewRootCA("r")
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	cp := serverCert(t, root, ServerCertOptions{Kind: KindControlPlane})
	edge1 := serverCert(t, root, ServerCertOptions{Kind: KindEdge, ID: "edge-1"})

	pq := func(c tls.Certificate) *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	}
	classic := func(c tls.Certificate) *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	}
	tests := []struct {
		name     string
		srv      *tls.Config
		kind, id string
		ok       bool
	}{
		{"control plane", pq(cp), ServerControlPlane, "", true},
		{"edge cert impersonating the control plane", pq(edge1), ServerControlPlane, "", false},
		{"edge", pq(edge1), ServerEdge, "edge-1", true},
		{"other edge id", pq(edge1), ServerEdge, "edge-2", false},
		{"control plane cert for an edge URL", pq(cp), ServerEdge, "edge-1", false},
		{"classic key exchange", classic(cp), ServerControlPlane, "", false},
		{"invalid kind", pq(cp), "device", "", false},
		{"control plane with id", pq(cp), ServerControlPlane, "x", false},
		{"edge without id", pq(edge1), ServerEdge, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The client deliberately allows the classic curve too, so only ExpectServer can
			// reject the classic case.
			cli := &tls.Config{
				RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
				VerifyConnection: ExpectServer(tc.kind, tc.id),
			}
			err := handshake(t, tc.srv, cli)
			if (err == nil) != tc.ok {
				t.Fatalf("handshake err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestParseURIConnector(t *testing.T) {
	id, err := ParseURI(ConnectorURI("acme", "dc1").String())
	if err != nil || id.Kind != PeerConnector || id.TenantID != "acme" || id.ConnectorID != "dc1" || id.DeviceID != "" {
		t.Fatalf("got %+v, %v", id, err)
	}
	if _, err := ParseURI("spiffe://opensase/tenant/acme/connector/"); err == nil {
		t.Fatal("empty connector id accepted")
	}
}
