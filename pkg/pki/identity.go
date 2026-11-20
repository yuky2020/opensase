package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// PeerKind is the role encoded in a peer certificate.
type PeerKind int

const (
	PeerUnknown PeerKind = iota
	PeerDevice
	PeerEdge
	PeerControlPlane
	PeerConnector // Connector, ADR-0013
)

func (k PeerKind) String() string {
	switch k {
	case PeerDevice:
		return "device"
	case PeerEdge:
		return "edge"
	case PeerControlPlane:
		return "controlplane"
	case PeerConnector:
		return "connector"
	default:
		return "unknown"
	}
}

// Identity is the identity extracted from a verified peer certificate.
type Identity struct {
	Kind        PeerKind
	TenantID    string // devices and connectors
	DeviceID    string // devices only
	EdgeID      string // edges only
	ConnectorID string // connectors only
}

// ErrNoIdentity is returned when a certificate carries no usable OpenSASE identity.
var ErrNoIdentity = errors.New("pki: certificate has no OpenSASE identity")

// ParseURI parses an OpenSASE SPIFFE URI SAN of a leaf certificate.
func ParseURI(raw string) (Identity, error) {
	const prefix = "spiffe://" + TrustDomain + "/"
	if !strings.HasPrefix(raw, prefix) {
		return Identity{}, ErrNoIdentity
	}
	parts := strings.Split(strings.TrimPrefix(raw, prefix), "/")
	switch {
	case len(parts) == 4 && parts[0] == "tenant" && parts[2] == "device" && ValidID(parts[1]) && ValidID(parts[3]):
		return Identity{Kind: PeerDevice, TenantID: parts[1], DeviceID: parts[3]}, nil
	case len(parts) == 4 && parts[0] == "tenant" && parts[2] == "connector" && ValidID(parts[1]) && ValidID(parts[3]):
		return Identity{Kind: PeerConnector, TenantID: parts[1], ConnectorID: parts[3]}, nil
	case len(parts) == 2 && parts[0] == "edge" && ValidID(parts[1]):
		return Identity{Kind: PeerEdge, EdgeID: parts[1]}, nil
	case len(parts) == 1 && parts[0] == "controlplane":
		return Identity{Kind: PeerControlPlane}, nil
	}
	return Identity{}, ErrNoIdentity
}

// TenantOfCA returns the tenant ID of a tenant intermediate CA certificate.
func TenantOfCA(c *x509.Certificate) (string, error) {
	if !c.IsCA || len(c.URIs) != 1 {
		return "", errors.New("pki: not a tenant CA")
	}
	const prefix = "spiffe://" + TrustDomain + "/tenant/"
	s := c.URIs[0].String()
	t, ok := strings.CutPrefix(s, prefix)
	if !ok || !ValidID(t) {
		return "", errors.New("pki: not a tenant CA")
	}
	return t, nil
}

// VerifyPeer extracts the identity from a verified chain (leaf first, as in
// tls.ConnectionState.VerifiedChains) and checks that the chain shape matches the role:
//
//   - a device leaf must be issued by the intermediate CA of the same tenant, which must be
//     issued by root;
//   - an edge or Control Plane leaf must be issued directly by root.
//
// root is the provider root CA. The chain must already be cryptographically verified
// (crypto/tls does that for VerifyClientCertIfGiven); this function only checks semantics.
func VerifyPeer(chain []*x509.Certificate, root *x509.Certificate) (Identity, error) {
	if len(chain) < 2 {
		return Identity{}, errors.New("pki: chain too short")
	}
	leaf := chain[0]
	if len(leaf.URIs) != 1 {
		return Identity{}, ErrNoIdentity
	}
	id, err := ParseURI(leaf.URIs[0].String())
	if err != nil {
		return Identity{}, err
	}
	top := chain[len(chain)-1]
	if !bytes.Equal(top.Raw, root.Raw) {
		return Identity{}, errors.New("pki: chain does not end at the provider root")
	}
	switch id.Kind {
	case PeerDevice, PeerConnector:
		if len(chain) != 3 {
			return Identity{}, fmt.Errorf("pki: %s chain must be leaf, tenant CA, root", id.Kind)
		}
		t, err := TenantOfCA(chain[1])
		if err != nil {
			return Identity{}, err
		}
		if t != id.TenantID {
			return Identity{}, fmt.Errorf("pki: %s cert for tenant %q issued by CA of tenant %q", id.Kind, id.TenantID, t)
		}
		if !hasEKU(leaf, x509.ExtKeyUsageClientAuth) {
			return Identity{}, fmt.Errorf("pki: %s cert lacks ClientAuth", id.Kind)
		}
	case PeerEdge, PeerControlPlane:
		if len(chain) != 2 {
			return Identity{}, errors.New("pki: server cert must be issued by root")
		}
	default:
		return Identity{}, ErrNoIdentity
	}
	return id, nil
}

// VerifyPeerChains runs VerifyPeer on every verified chain and returns the first identity
// that satisfies it. Tenant CAs sit in server client-CA pools as anchors so that a client that
// sends only its leaf still verifies; such a chain ends at a tenant CA, which is accepted only
// if that CA is signed by root (root is then appended).
func VerifyPeerChains(chains [][]*x509.Certificate, root *x509.Certificate) (Identity, error) {
	err := error(ErrNoIdentity)
	for _, ch := range chains {
		if len(ch) == 0 {
			continue
		}
		top := ch[len(ch)-1]
		if !bytes.Equal(top.Raw, root.Raw) {
			if !top.IsCA || top.CheckSignatureFrom(root) != nil {
				err = errors.New("pki: chain does not lead to the provider root")
				continue
			}
			ch = append(ch[:len(ch):len(ch)], root)
		}
		var id Identity
		if id, err = VerifyPeer(ch, root); err == nil {
			return id, nil
		}
	}
	return Identity{}, err
}

func hasEKU(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, e := range c.ExtKeyUsage {
		if e == want {
			return true
		}
	}
	return false
}

// EncodeCertPEM encodes a certificate as PEM.
func EncodeCertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// EncodeKeyPEM encodes an ECDSA key as a PKCS#8 PEM block.
func EncodeKeyPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCertsPEM parses every CERTIFICATE block in data.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("pki: no certificate in PEM")
	}
	return out, nil
}

// ParseKeyPEM parses a PKCS#8 or SEC1 ECDSA private key.
func ParseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("pki: no PEM key")
	}
	switch b.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse key: %w", err)
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("pki: key is not ECDSA")
		}
		return ek, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse key: %w", err)
		}
		return k, nil
	}
	return nil, fmt.Errorf("pki: unexpected PEM type %q", b.Type)
}

// ParseCSR parses and verifies the self-signature of a PEM PKCS#10 request.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("pki: no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	return csr, nil
}
