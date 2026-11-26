package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCSR(t *testing.T, curve elliptic.Curve, uris ...*url.URL) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "evil"}, URIs: uris,
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func verify(t *testing.T, leafPEM []byte, root *CA, extra ...*x509.Certificate) [][]*x509.Certificate {
	t.Helper()
	certs, err := ParseCertsPEM(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	inter := x509.NewCertPool()
	for _, c := range append(certs[1:], extra...) {
		inter.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return chains
}

func TestDeviceCertificate(t *testing.T) {
	root, err := NewRootCA("test root")
	if err != nil {
		t.Fatal(err)
	}
	ten, err := root.NewTenantCA("acme")
	if err != nil {
		t.Fatal(err)
	}
	other, err := root.NewTenantCA("other")
	if err != nil {
		t.Fatal(err)
	}
	// The CSR tries to smuggle in an edge identity; it must be ignored.
	csr := newCSR(t, elliptic.P256(), EdgeURI("edge-1"))
	chainPEM, leaf, err := ten.SignDeviceCSR(csr, "acme", "dev1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.URIs[0].String(); got != "spiffe://opensase/tenant/acme/device/dev1" {
		t.Fatalf("URI = %s", got)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > DeviceValidity+clockSkew+time.Second {
		t.Fatalf("validity %v", d)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU = %v", leaf.ExtKeyUsage)
	}
	chains := verify(t, chainPEM, root)
	id, err := VerifyPeer(chains[0], root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if id.Kind != PeerDevice || id.TenantID != "acme" || id.DeviceID != "dev1" {
		t.Fatalf("identity = %+v", id)
	}

	// A device cert claiming tenant acme but chained via another tenant's CA is rejected.
	fake := []*x509.Certificate{leaf, other.Cert, root.Cert}
	if _, err := VerifyPeer(fake, root.Cert); err == nil {
		t.Fatal("cross-tenant chain accepted")
	}
	// Wrong root.
	root2, _ := NewRootCA("other root")
	if _, err := VerifyPeer(chains[0], root2.Cert); err == nil {
		t.Fatal("foreign root accepted")
	}
}

func TestSignDeviceCSRRejects(t *testing.T) {
	root, _ := NewRootCA("r")
	ten, _ := root.NewTenantCA("acme")
	tests := []struct {
		name           string
		ca             *CA
		csr            []byte
		tenant, device string
	}{
		{"wrong curve", ten, newCSR(t, elliptic.P384()), "acme", "d"},
		{"bad device id", ten, newCSR(t, elliptic.P256()), "acme", "../x"},
		{"tenant mismatch", ten, newCSR(t, elliptic.P256()), "other", "d"},
		{"root is not tenant CA", root, newCSR(t, elliptic.P256()), "acme", "d"},
		{"garbage", ten, []byte("nope"), "acme", "d"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := tc.ca.SignDeviceCSR(tc.csr, tc.tenant, tc.device, 0); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestServerCertificates(t *testing.T) {
	root, _ := NewRootCA("r")
	cpDNS, cpIPs := DevServerSANs(KindControlPlane)
	edDNS, edIPs := DevServerSANs(KindEdge)
	tests := []struct {
		name      string
		opts      ServerCertOptions
		kind      PeerKind
		clientEKU bool
		host      string // own service name
		notHost   string // the other server's name must not be in the cert
	}{
		{"controlplane", ServerCertOptions{Kind: KindControlPlane, DNSNames: cpDNS, IPs: cpIPs}, PeerControlPlane, false, "controlplane", "edge"},
		{"edge", ServerCertOptions{Kind: KindEdge, ID: "edge-1", DNSNames: edDNS, IPs: edIPs}, PeerEdge, true, "edge", "controlplane"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, kp, err := root.IssueServerCert(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseKeyPEM(kp); err != nil {
				t.Fatal(err)
			}
			chains := verify(t, cp, root)
			leaf := chains[0][0]
			if err := leaf.VerifyHostname(tc.notHost); err == nil {
				t.Errorf("%s cert is valid for %q", tc.name, tc.notHost)
			}
			for _, ip := range []string{tc.host, "localhost", "127.0.0.1", "::1", "10.0.2.2"} {
				if err := leaf.VerifyHostname(ip); err != nil {
					t.Errorf("%s: %v", ip, err)
				}
			}
			id, err := VerifyPeer(chains[0], root.Cert)
			if err != nil || id.Kind != tc.kind {
				t.Fatalf("identity %+v err %v", id, err)
			}
			if hasEKU(leaf, x509.ExtKeyUsageClientAuth) != tc.clientEKU {
				t.Fatalf("ClientAuth EKU = %v", !tc.clientEKU)
			}
		})
	}
	if _, _, err := root.IssueServerCert(ServerCertOptions{Kind: KindEdge, ID: "a/b", IPs: []net.IP{net.IPv4zero}}); err == nil {
		t.Fatal("invalid edge id accepted")
	}
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		in   string
		kind PeerKind
		ok   bool
	}{
		{"spiffe://opensase/tenant/t/device/d", PeerDevice, true},
		{"spiffe://opensase/edge/e1", PeerEdge, true},
		{"spiffe://opensase/controlplane", PeerControlPlane, true},
		{"spiffe://other/edge/e1", 0, false},
		{"spiffe://opensase/tenant/t", 0, false},
		{"spiffe://opensase/tenant/t/device/d/x", 0, false},
		{"spiffe://opensase/tenant/../device/d", 0, false},
	}
	for _, tc := range tests {
		id, err := ParseURI(tc.in)
		if (err == nil) != tc.ok || (tc.ok && id.Kind != tc.kind) {
			t.Errorf("%s: id=%+v err=%v", tc.in, id, err)
		}
	}
}

func TestInitDirAndAuthority(t *testing.T) {
	dir := t.TempDir()
	if err := InitDir(dir, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(dir, RootCertFile))
	if err := InitDir(dir, InitOptions{}); err != nil { // idempotent
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(dir, RootCertFile))
	if string(first) != string(second) {
		t.Fatal("InitDir regenerated the root")
	}
	for _, f := range []string{RootKeyFile, CPKeyFile, SnapshotKeyFile, filepath.Join(EdgeDir, EdgeKeyFile), filepath.Join(EdgeDir, EdgeWGKeyFile)} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode().Perm())
		}
	}
	a, err := OpenAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca1, err := a.TenantCA(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := OpenAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := a2.TenantCA(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !ca1.Cert.Equal(ca2.Cert) {
		t.Fatal("tenant CA not persisted")
	}
	if certs, _ := ParseCertsPEM(a2.BundlePEM()); len(certs) != 2 {
		t.Fatalf("bundle has %d certs", len(certs))
	}
	k1, id1, err := LoadOrCreateSigningKey(filepath.Join(dir, SnapshotKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	_, id2, _ := LoadOrCreateSigningKey(filepath.Join(dir, SnapshotKeyFile))
	if id1 != id2 || len(k1) == 0 {
		t.Fatal("signing key not stable")
	}
	priv, pub, err := LoadWireGuardKey(filepath.Join(dir, EdgeDir, EdgeWGKeyFile))
	if err != nil || len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("wg key: %v", err)
	}
	// The Edge directory holds exactly what an Edge needs; the top level holds no Edge key.
	ents, _ := os.ReadDir(filepath.Join(dir, EdgeDir))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, ","); got != "edge-wg.key,edge.crt,edge.key,root.crt" {
		t.Fatalf("edge dir: %s", got)
	}
	for _, f := range []string{EdgeKeyFile, EdgeWGKeyFile, EdgeCertFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s at the top level", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, EdgeDir, RootCertFile)); string(b) != string(first) {
		t.Fatal("edge root.crt differs from the root")
	}
}

func TestInitDirMovesLegacyEdgeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := InitDir(dir, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	// Simulate the old layout: Edge files at the top level.
	for _, f := range []string{EdgeCertFile, EdgeKeyFile, EdgeWGKeyFile} {
		if err := os.Rename(filepath.Join(dir, EdgeDir, f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	old, _ := os.ReadFile(filepath.Join(dir, EdgeWGKeyFile))
	if err := InitDir(dir, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, EdgeKeyFile)); err == nil {
		t.Fatal("legacy edge.key left at the top level")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, EdgeDir, EdgeWGKeyFile)); string(b) != string(old) {
		t.Fatal("legacy WireGuard key not kept")
	}
}

func TestVerifyPeerChainsLeafOnly(t *testing.T) {
	root, _ := NewRootCA("r")
	ten, _ := root.NewTenantCA("acme")
	_, leaf, err := ten.SignDeviceCSR(newCSR(t, elliptic.P256()), "acme", "d1", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Chain as crypto/tls builds it when the tenant CA is an anchor in ClientCAs.
	id, err := VerifyPeerChains([][]*x509.Certificate{{leaf, ten.Cert}}, root.Cert)
	if err != nil || id.DeviceID != "d1" {
		t.Fatalf("%+v %v", id, err)
	}
	// A self-made "tenant CA" not signed by root is rejected.
	rogueRoot, _ := NewRootCA("rogue")
	rogue, _ := rogueRoot.NewTenantCA("acme")
	_, rleaf, _ := rogue.SignDeviceCSR(newCSR(t, elliptic.P256()), "acme", "d1", 0)
	if _, err := VerifyPeerChains([][]*x509.Certificate{{rleaf, rogue.Cert}}, root.Cert); err == nil {
		t.Fatal("rogue CA accepted")
	}
}
