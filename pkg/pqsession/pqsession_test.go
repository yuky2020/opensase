package pqsession

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge"},
		DNSNames: []string{"edge"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs a TLS handshake over a pipe and returns both connection states.
func handshake(t *testing.T, srv, cli *tls.Config) (tls.ConnectionState, tls.ConnectionState, error) {
	t.Helper()
	a, b := net.Pipe()
	s, c := tls.Server(a, srv), tls.Client(b, cli)
	errc := make(chan error, 1)
	go func() { errc <- s.Handshake() }()
	cerr := c.Handshake()
	serr := <-errc
	if cerr != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, cerr
	}
	if serr != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, serr
	}
	return s.ConnectionState(), c.ConnectionState(), nil
}

func TestDerivePSKMatchesOnBothSides(t *testing.T) {
	cert := selfSigned(t)
	srv := Harden(&tls.Config{Certificates: []tls.Certificate{cert}})
	cli := Harden(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test only
	ss, cs, err := handshake(t, srv, cli)
	if err != nil {
		t.Fatal(err)
	}
	ck, ek := make([]byte, 32), make([]byte, 32)
	ck[0], ek[0] = 1, 2
	p1, err := DerivePSK(ss, ck, ek, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := DerivePSK(cs, ck, ek, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatal("PSK differs between client and server")
	}
	p3, _ := DerivePSK(cs, ck, ek, "s1", 1)
	if p3 == p1 {
		t.Fatal("PSK must change with epoch")
	}
	p4, _ := DerivePSK(cs, ek, ck, "s1", 0)
	if p4 == p1 {
		t.Fatal("PSK must be bound to key order")
	}
}

func TestClassicClientRefused(t *testing.T) {
	cert := selfSigned(t)
	srv := Harden(&tls.Config{Certificates: []tls.Certificate{cert}})
	cli := &tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}} //nolint:gosec // test only
	if _, _, err := handshake(t, srv, cli); err == nil {
		t.Fatal("handshake with classic-only client must fail")
	}
}

func TestDeriveRejectsClassicState(t *testing.T) {
	_, err := DerivePSK(tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, CurveID: tls.X25519},
		make([]byte, 32), make([]byte, 32), "s", 0)
	if !errors.Is(err, ErrNotPostQuantum) {
		t.Fatalf("want ErrNotPostQuantum, got %v", err)
	}
}
