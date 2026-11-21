package pki

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"
)

func TestInspectionCAPersistsAndIsSeparate(t *testing.T) {
	dir := t.TempDir()
	if err := InitDir(dir, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	a, _ := OpenAuthority(dir)
	ca, err := a.InspectionCA("acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.InspectionCA("../x"); err == nil {
		t.Fatal("invalid tenant accepted")
	}
	b, err := OpenAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := b.InspectionCA("acme")
	if err != nil || !again.Cert.Equal(ca.Cert) {
		t.Fatalf("not persisted: %v", err)
	}
	// Not under the provider root, and not usable for OpenSASE client identities.
	if ca.Cert.CheckSignatureFrom(a.Root.Cert) == nil {
		t.Fatal("inspection root signed by the provider root")
	}
	if len(ca.Cert.ExtKeyUsage) != 1 || ca.Cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("EKU %v", ca.Cert.ExtKeyUsage)
	}
	if _, _, err := a.SignInspectionCSR(newCSR(t, elliptic.P256()), "acme", "../e", 0); err == nil {
		t.Fatal("invalid edge id accepted")
	}
}
