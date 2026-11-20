package securitytest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// Unit checks: no running stack. They pin the security properties the stack checks rely
// on, so a regression is caught in CI before it reaches the dev stack.

func chainOf(c tls.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, d := range c.Certificate {
		x, _ := x509.ParseCertificate(d)
		out = append(out, x)
	}
	return out
}

func TestUnitPKI(t *testing.T) {
	root, err := pki.NewRootCA("sectest root")
	if err != nil {
		t.Fatal(err)
	}
	ta, _ := root.NewTenantCA("ta")
	tb, _ := root.NewTenantCA("tb")
	const sp = "spiffe://opensase"

	// Chain-shape and identity rules of pki.VerifyPeer (used by CP and Edge).
	check(t, "SEC-UNIT-001", "pki.VerifyPeer rejects forged chains and identities", "", func(t *testing.T) error {
		ok, _ := mint(ta, uris(sp+"/tenant/ta/device/d1"))
		if _, err := pki.VerifyPeer(append(chainOf(ok), root.Cert), root.Cert); err != nil {
			return fmt.Errorf("control: valid device chain rejected: %w", err)
		}
		other, _ := foreignTenantCA("ta")
		cases := map[string][]*x509.Certificate{}
		add := func(name string, ca *pki.CA, top *x509.Certificate, mod func(*x509.Certificate)) {
			c, err := mint(ca, mod)
			if err != nil {
				t.Fatal(err)
			}
			cases[name] = append(chainOf(c), top)
		}
		add("tenant B device signed by tenant A CA", ta, root.Cert, uris(sp+"/tenant/tb/device/d1"))
		add("edge URI under a tenant CA", ta, root.Cert, uris(sp+"/edge/e1"))
		add("controlplane URI under a tenant CA", tb, root.Cert, uris(sp+"/controlplane"))
		add("two URIs", ta, root.Cert, uris(sp+"/tenant/ta/device/d1", sp+"/tenant/ta/device/d2"))
		add("no URI", ta, root.Cert, nil)
		add("foreign trust domain", ta, root.Cert, uris("spiffe://evil/tenant/ta/device/d1"))
		add("connector without ClientAuth", ta, root.Cert, func(c *x509.Certificate) {
			uris(sp + "/tenant/ta/connector/c1")(c)
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		})
		add("device directly under root", root, root.Cert, uris(sp+"/tenant/ta/device/d1"))
		fc, _ := mint(other, uris(sp+"/tenant/ta/device/d1"))
		cases["chain ends at a foreign root"] = chainOf(fc)
		var errs []error
		for name, ch := range cases {
			if id, err := pki.VerifyPeer(ch, root.Cert); err == nil {
				errs = append(errs, fmt.Errorf("%s accepted as %+v", name, id))
			}
		}
		return errors.Join(errs...)
	})

	// ID and URI parsing: nothing that could escape a path segment or file name.
	check(t, "SEC-UNIT-002", "pki.ValidID / ParseURI refuse traversal and malformed identities", "", func(t *testing.T) error {
		for _, id := range []string{"", ".", "..", "../x", "a/b", `a\b`, "x\x00", "-x", ".x", strings.Repeat("a", 129), "a b", "ü", "a%2fb"} {
			if pki.ValidID(id) {
				return fmt.Errorf("ValidID(%q) = true", id)
			}
		}
		for _, u := range []string{sp + "/tenant/ta/device/../d", sp + "/tenant/ta/device/d/x", sp + "/tenant//device/d", sp + "/edge/", sp + "/edge/a/b", "spiffe://opensase.evil/edge/e", sp + "//edge/e", sp + "/controlplane/x"} {
			if id, err := pki.ParseURI(u); err == nil {
				return fmt.Errorf("ParseURI(%q) = %+v", u, id)
			}
		}
		return nil
	})

	// Clients tell servers apart by SPIFFE URI and refuse non-PQ connections.
	check(t, "SEC-UNIT-003", "pki.ExpectServer refuses wrong server identity and non-PQ state", "", func(t *testing.T) error {
		ep, _, _ := root.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindEdge, ID: "e1", DNSNames: []string{"localhost"}})
		cpp, _, _ := root.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindControlPlane, DNSNames: []string{"localhost"}})
		edge, _ := pki.ParseCertsPEM(ep)
		cp, _ := pki.ParseCertsPEM(cpp)
		cs := func(c *x509.Certificate, curve tls.CurveID) tls.ConnectionState {
			return tls.ConnectionState{Version: tls.VersionTLS13, CurveID: curve, PeerCertificates: []*x509.Certificate{c}}
		}
		if err := pki.ExpectServer("controlplane", "")(cs(cp[0], tls.X25519MLKEM768)); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		for name, c := range map[string]error{
			"edge as CP":       pki.ExpectServer("controlplane", "")(cs(edge[0], tls.X25519MLKEM768)),
			"CP as edge":       pki.ExpectServer("edge", "e1")(cs(cp[0], tls.X25519MLKEM768)),
			"other edge ID":    pki.ExpectServer("edge", "e2")(cs(edge[0], tls.X25519MLKEM768)),
			"classic X25519":   pki.ExpectServer("controlplane", "")(cs(cp[0], tls.X25519)),
			"invalid expected": pki.ExpectServer("edge", "../x")(cs(edge[0], tls.X25519MLKEM768)),
		} {
			if c == nil {
				return fmt.Errorf("%s accepted", name)
			}
		}
		return nil
	})
}

// tlsPair runs one handshake between a Harden-ed server and a client config over a pipe.
func tlsPair(t *testing.T, client *tls.Config) (tls.ConnectionState, tls.ConnectionState, error) {
	t.Helper()
	root, _ := pki.NewRootCA("sectest root")
	cp, kp, _ := root.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindControlPlane, DNSNames: []string{"localhost"}})
	cert, _ := tls.X509KeyPair(cp, kp)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	client.RootCAs, client.ServerName = pool, "localhost"
	a, b := net.Pipe()
	srv := tls.Server(a, pqsession.Harden(&tls.Config{Certificates: []tls.Certificate{cert}}))
	cli := tls.Client(b, client)
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	errc := make(chan error, 1)
	go func() { errc <- srv.Handshake(); _ = a.Close() }()
	cerr := cli.Handshake()
	_ = b.Close()
	serr := <-errc
	if cerr != nil || serr != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, errors.Join(cerr, serr)
	}
	return srv.ConnectionState(), cli.ConnectionState(), nil
}

func TestUnitPQSession(t *testing.T) {
	// The hardened server accepts only TLS 1.3 + X25519MLKEM768.
	check(t, "SEC-UNIT-010", "pqsession.Harden server refuses classic groups and TLS 1.2", "", func(t *testing.T) error {
		if _, c, err := tlsPair(t, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}); err != nil || c.CurveID != tls.X25519MLKEM768 {
			return fmt.Errorf("control: PQ handshake: %w", err)
		}
		for name, c := range map[string]*tls.Config{
			"X25519":  {CurvePreferences: []tls.CurveID{tls.X25519}},
			"P-256":   {CurvePreferences: []tls.CurveID{tls.CurveP256}},
			"TLS 1.2": {MaxVersion: tls.VersionTLS12},
		} {
			if _, _, err := tlsPair(t, c); err == nil {
				return fmt.Errorf("%s handshake succeeded", name)
			}
		}
		return nil
	})

	// The PSK is bound to both WG keys, the session and the epoch; a classic connection
	// state never yields a PSK; the exporter context is unambiguous (length-prefixed).
	check(t, "SEC-UNIT-011", "PSK derivation bound to keys/session/epoch, refused without PQ", "", func(t *testing.T) error {
		s, c, err := tlsPair(t, pqsession.Harden(&tls.Config{}))
		if err != nil {
			return err
		}
		k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
		ps, err := pqsession.DerivePSK(s, k1, k2, "sess", 0)
		if err != nil {
			return err
		}
		pc, _ := pqsession.DerivePSK(c, k1, k2, "sess", 0)
		if ps != pc {
			return errors.New("control: both ends derive different PSKs")
		}
		for name, v := range map[string]func() ([32]byte, error){
			"epoch+1":      func() ([32]byte, error) { return pqsession.DerivePSK(c, k1, k2, "sess", 1) },
			"other sess":   func() ([32]byte, error) { return pqsession.DerivePSK(c, k1, k2, "sesS", 0) },
			"swapped keys": func() ([32]byte, error) { return pqsession.DerivePSK(c, k2, k1, "sess", 0) },
		} {
			p, err := v()
			if err != nil || p == ps {
				return fmt.Errorf("%s: same PSK or error %w", name, err)
			}
		}
		classic := c
		classic.CurveID = tls.X25519
		if _, err := pqsession.DerivePSK(classic, k1, k2, "sess", 0); err == nil {
			return errors.New("PSK derived from a non-PQ connection state")
		}
		if bytes.Equal(pqsession.Context([]byte("ab"), []byte("c"), "", 0), pqsession.Context([]byte("a"), []byte("bc"), "", 0)) {
			return errors.New("exporter context is ambiguous")
		}
		return nil
	})
}
