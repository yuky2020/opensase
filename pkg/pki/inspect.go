package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// TLS inspection CAs (ADR-0018).
//
// Each tenant that turns on TLS inspection gets its own inspection root. It is separate from
// the provider root and the tenant CA: its devices install it as a web trust anchor, so it
// must not be able to vouch for OpenSASE identities, and the mTLS PKI must not be able to
// mint web certificates. Both CAs carry only the ServerAuth extended key usage.
//
// The Control Plane keeps the inspection root key. Each Edge generates its own key and gets
// a short-lived intermediate for it (SignInspectionCSR), so a compromised Edge can mint
// certificates for at most InspectionIntermediateValidity.

// Inspection CA validities and file names.
const (
	InspectionRootValidity         = 5 * 365 * 24 * time.Hour
	InspectionIntermediateValidity = 7 * 24 * time.Hour
	inspectCertFile                = "inspect-ca.crt"
	inspectKeyFile                 = "inspect-ca.key"
)

// InspectionURI returns spiffe://opensase/tenant/<t>/inspection/<edge>, the identity of an
// Edge's inspection intermediate.
func InspectionURI(tenantID, edgeID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/tenant/" + tenantID + "/inspection/" + edgeID}
}

// newInspectionRoot creates the self-signed inspection root of a tenant.
func newInspectionRoot(tenantID string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate inspection key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "OpenSASE web inspection " + tenantID, Organization: []string{"OpenSASE"}, OrganizationalUnit: []string{tenantID}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(InspectionRootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert, err := sign(tmpl, key.Public(), nil, key)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

func (a *Authority) inspectPaths(t string) (string, string) {
	d := filepath.Join(a.dir, TenantsDir, t)
	return filepath.Join(d, inspectCertFile), filepath.Join(d, inspectKeyFile)
}

// InspectionCA returns the inspection root of tenantID, creating and persisting it on first
// use.
func (a *Authority) InspectionCA(tenantID string) (*CA, error) {
	// The tenant directory is created with (and identified by) the tenant CA.
	if _, err := a.TenantCA(tenantID); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ca, ok := a.inspect[tenantID]; ok {
		return ca, nil
	}
	c, k := a.inspectPaths(tenantID)
	ca, err := LoadCA(c, k)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		if ca, err = newInspectionRoot(tenantID); err != nil {
			return nil, err
		}
		if err := SaveCA(ca, c, k); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("pki: load inspection CA %q: %w", tenantID, err)
	}
	if a.inspect == nil {
		a.inspect = map[string]*CA{}
	}
	a.inspect[tenantID] = ca
	return ca, nil
}

// SignInspectionCSR issues the inspection intermediate of edgeID for tenantID from the
// Edge's CSR. The intermediate may sign only leaf server certificates (path length 0,
// ServerAuth only). The returned PEM holds the intermediate followed by the root.
func (a *Authority) SignInspectionCSR(csrPEM []byte, tenantID, edgeID string, validity time.Duration) ([]byte, *x509.Certificate, error) {
	if !ValidID(tenantID) || !ValidID(edgeID) {
		return nil, nil, errors.New("pki: invalid tenant or edge id")
	}
	root, err := a.InspectionCA(tenantID)
	if err != nil {
		return nil, nil, err
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("pki: inspection key must be ECDSA P-256")
	}
	if validity <= 0 || validity > InspectionIntermediateValidity {
		validity = InspectionIntermediateValidity
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "OpenSASE web inspection " + tenantID + " (edge " + edgeID + ")", Organization: []string{"OpenSASE"}, OrganizationalUnit: []string{tenantID}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              minTime(now.Add(validity), root.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		URIs:                  []*url.URL{InspectionURI(tenantID, edgeID)},
	}
	cert, err := sign(tmpl, pub, root.Cert, root.Key)
	if err != nil {
		return nil, nil, err
	}
	return append(EncodeCertPEM(cert), root.CertPEM()...), cert, nil
}
