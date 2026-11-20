// Package pki implements the OpenSASE dev PKI: a provider root CA, one intermediate CA per
// tenant, device certificates signed from CSRs, and server certificates for the Control Plane
// and Edges. All keys are ECDSA P-256.
//
// Identities are SPIFFE-style URI SANs:
//
//	spiffe://opensase/tenant/<t>                  tenant intermediate CA
//	spiffe://opensase/tenant/<t>/device/<id>      device (ClientAuth)
//	spiffe://opensase/edge/<id>                   Edge (ServerAuth + ClientAuth)
//	spiffe://opensase/controlplane                Control Plane (ServerAuth)
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// TrustDomain is the SPIFFE trust domain used in every URI SAN.
const TrustDomain = "opensase"

// Default validities.
const (
	RootValidity         = 10 * 365 * 24 * time.Hour
	IntermediateValidity = 5 * 365 * 24 * time.Hour
	DeviceValidity       = 24 * time.Hour
	ServerValidity       = 365 * 24 * time.Hour
)

// clockSkew backdates NotBefore so freshly issued certs verify on peers with a slow clock.
const clockSkew = 5 * time.Minute

// idPattern restricts tenant, device and edge IDs to characters that are safe inside a URI
// path segment and a file name.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// ValidID reports whether id can be used as a tenant, device or edge identifier.
func ValidID(id string) bool { return idPattern.MatchString(id) && id != "." && id != ".." }

// CA is a certificate authority with its private key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// CertPEM returns the CA certificate in PEM form.
func (ca *CA) CertPEM() []byte { return EncodeCertPEM(ca.Cert) }

// NewRootCA creates a self-signed provider root CA.
func NewRootCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate root key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"OpenSASE"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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

// NewTenantCA creates the intermediate CA of a tenant, signed by the root.
func (ca *CA) NewTenantCA(tenantID string) (*CA, error) {
	if !ValidID(tenantID) {
		return nil, fmt.Errorf("pki: invalid tenant id %q", tenantID)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate tenant key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "OpenSASE tenant " + tenantID, Organization: []string{"OpenSASE"}, OrganizationalUnit: []string{tenantID}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              minTime(now.Add(IntermediateValidity), ca.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		URIs:                  []*url.URL{TenantURI(tenantID)},
	}
	cert, err := sign(tmpl, key.Public(), ca.Cert, ca.Key)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// SignDeviceCSR issues a device certificate for the public key in csrPEM. Every name in the
// CSR is ignored: the identity comes only from tenantID and deviceID. ca must be the tenant CA.
// The returned PEM holds the leaf followed by the tenant CA certificate.
func (ca *CA) SignDeviceCSR(csrPEM []byte, tenantID, deviceID string, validity time.Duration) ([]byte, *x509.Certificate, error) {
	if !ValidID(tenantID) || !ValidID(deviceID) {
		return nil, nil, errors.New("pki: invalid tenant or device id")
	}
	return ca.signTenantLeaf(csrPEM, tenantID, deviceID, DeviceURI(tenantID, deviceID), validity)
}

// SignConnectorCSR issues a Connector certificate (ADR-0013), same rules as SignDeviceCSR,
// with URI spiffe://opensase/tenant/<t>/connector/<id>.
func (ca *CA) SignConnectorCSR(csrPEM []byte, tenantID, connectorID string, validity time.Duration) ([]byte, *x509.Certificate, error) {
	if !ValidID(tenantID) || !ValidID(connectorID) {
		return nil, nil, errors.New("pki: invalid tenant or connector id")
	}
	return ca.signTenantLeaf(csrPEM, tenantID, "connector-"+connectorID, ConnectorURI(tenantID, connectorID), validity)
}

func (ca *CA) signTenantLeaf(csrPEM []byte, tenantID, cn string, uri *url.URL, validity time.Duration) ([]byte, *x509.Certificate, error) {
	if t, err := TenantOfCA(ca.Cert); err != nil || t != tenantID {
		return nil, nil, fmt.Errorf("pki: CA is not the CA of tenant %q", tenantID)
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("pki: device key must be ECDSA P-256")
	}
	if validity <= 0 {
		validity = DeviceValidity
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn, OrganizationalUnit: []string{tenantID}},
		NotBefore:   now.Add(-clockSkew),
		NotAfter:    minTime(now.Add(validity), ca.Cert.NotAfter),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{uri},
	}
	cert, err := sign(tmpl, pub, ca.Cert, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	out := append(EncodeCertPEM(cert), ca.CertPEM()...)
	return out, cert, nil
}

// ServerKind is the role a server certificate is issued for.
type ServerKind int

// Server kinds.
const (
	KindControlPlane ServerKind = iota + 1
	KindEdge
)

// ServerCertOptions configures IssueServerCert.
type ServerCertOptions struct {
	Kind     ServerKind
	ID       string // edge ID; ignored for the Control Plane
	DNSNames []string
	IPs      []net.IP
	Validity time.Duration
}

// DevServerSANs returns the default dev SANs of a server certificate: its own service name
// ("controlplane" or "edge"), localhost, 127.0.0.1, ::1 and 10.0.2.2 (the Android emulator's
// host alias). The host names overlap between the two kinds on purpose (one dev host); clients
// tell the servers apart by the SPIFFE URI (ExpectServer), never by the DNS name.
func DevServerSANs(kind ServerKind) ([]string, []net.IP) {
	name := "controlplane"
	if kind == KindEdge {
		name = "edge"
	}
	return []string{name, "localhost"},
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv4(10, 0, 2, 2)}
}

// ParseSANs splits a comma-separated list of DNS names and IP addresses.
func ParseSANs(list string) ([]string, []net.IP) {
	var dns []string
	var ips []net.IP
	for _, s := range strings.Split(list, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, s)
		}
	}
	return dns, ips
}

// IssueServerCert issues a server certificate signed by the root CA. Edge certificates also
// carry ClientAuth, because the Edge authenticates to the Control Plane with the same cert.
// It returns the certificate PEM and the PKCS#8 private key PEM.
func (ca *CA) IssueServerCert(o ServerCertOptions) (certPEM, keyPEM []byte, err error) {
	var uri *url.URL
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cn := ""
	switch o.Kind {
	case KindControlPlane:
		uri, cn = ControlPlaneURI(), "OpenSASE Control Plane"
	case KindEdge:
		if !ValidID(o.ID) {
			return nil, nil, fmt.Errorf("pki: invalid edge id %q", o.ID)
		}
		uri, cn = EdgeURI(o.ID), "OpenSASE Edge "+o.ID
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	default:
		return nil, nil, errors.New("pki: unknown server kind")
	}
	if o.Validity <= 0 {
		o.Validity = ServerValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate server key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn, Organization: []string{"OpenSASE"}},
		NotBefore:   now.Add(-clockSkew),
		NotAfter:    minTime(now.Add(o.Validity), ca.Cert.NotAfter),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: eku,
		DNSNames:    o.DNSNames,
		IPAddresses: o.IPs,
		URIs:        []*url.URL{uri},
	}
	cert, err := sign(tmpl, key.Public(), ca.Cert, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = EncodeKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return EncodeCertPEM(cert), keyPEM, nil
}

func sign(tmpl *x509.Certificate, pub crypto.PublicKey, parent *x509.Certificate, priv *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	tmpl.SerialNumber = serial
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal public key: %w", err)
	}
	ski := sha256.Sum256(spki)
	tmpl.SubjectKeyId = ski[:20]
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("pki: create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// TenantURI returns spiffe://opensase/tenant/<t>.
func TenantURI(tenantID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/tenant/" + tenantID}
}

// DeviceURI returns spiffe://opensase/tenant/<t>/device/<id>.
func DeviceURI(tenantID, deviceID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/tenant/" + tenantID + "/device/" + deviceID}
}

// ConnectorURI returns spiffe://opensase/tenant/<t>/connector/<id>.
func ConnectorURI(tenantID, connectorID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/tenant/" + tenantID + "/connector/" + connectorID}
}

// EdgeURI returns spiffe://opensase/edge/<id>.
func EdgeURI(edgeID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/edge/" + edgeID}
}

// ControlPlaneURI returns spiffe://opensase/controlplane.
func ControlPlaneURI() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/controlplane"}
}
