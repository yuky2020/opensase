package connector

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
)

// State directory layout (0700; every file 0600).
const (
	fileInfo     = "connector.json" // api.ConnectorEnrollResponse without the certificate
	fileBundle   = "connector.pem"  // PKCS#8 key + certificate chain, replaced atomically
	fileRoot     = "root.pem"       // provider root CA, anchored by the enrollment pin
	stateDirMode = 0o700
	fileMode     = 0o600
	maxStateFile = 1 << 20
)

// identity is the persisted connector identity.
type identity struct {
	info     api.ConnectorEnrollResponse // CertificatePEM cleared
	root     *x509.Certificate
	rootPool *x509.CertPool
	cert     atomic.Pointer[tls.Certificate] // Leaf set; swapped on renewal
}

func (id *identity) leaf() *x509.Certificate { return id.cert.Load().Leaf }

func ensureStateDir(dir string) error {
	if dir == "" {
		return errors.New("connector: state directory required")
	}
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		return err
	}
	return os.Chmod(dir, stateDirMode)
}

func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

func readStateFile(dir, name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxStateFile {
		return nil, fmt.Errorf("connector: %s too large", name)
	}
	b := make([]byte, st.Size())
	_, err = f.ReadAt(b, 0)
	return b, err
}

// bundlePEM encodes key and chain as one PEM blob (key first). The caller wipes it.
func bundlePEM(key *ecdsa.PrivateKey, chain [][]byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	var certs []byte
	for _, c := range chain {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	buf := make([]byte, 0, len(keyPEM)+len(certs))
	buf = append(append(buf, keyPEM...), certs...)
	clear(keyPEM)
	return buf, nil
}

func saveCert(dir string, key *ecdsa.PrivateKey, chain [][]byte) error {
	b, err := bundlePEM(key, chain)
	if err != nil {
		return err
	}
	defer clear(b)
	return writeFileAtomic(dir, fileBundle, b)
}

// saveIdentity persists a fresh enrollment: root, key+certificate, then connector.json last
// (its presence means "enrolled").
func saveIdentity(dir string, info api.ConnectorEnrollResponse, root *x509.Certificate, key *ecdsa.PrivateKey, chain [][]byte) error {
	info.CertificatePEM = ""
	if err := writeFileAtomic(dir, fileRoot, pki.EncodeCertPEM(root)); err != nil {
		return err
	}
	if err := saveCert(dir, key, chain); err != nil {
		return err
	}
	js, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, fileInfo, js)
}

// loadIdentity returns the persisted identity, or os.ErrNotExist if not enrolled.
func loadIdentity(dir string) (*identity, error) {
	js, err := readStateFile(dir, fileInfo)
	if err != nil {
		return nil, err
	}
	var info api.ConnectorEnrollResponse
	if err := json.Unmarshal(js, &info); err != nil {
		return nil, fmt.Errorf("connector: corrupt %s: %w", fileInfo, err)
	}
	rootPEM, err := readStateFile(dir, fileRoot)
	if err != nil {
		return nil, err
	}
	roots, err := pki.ParseCertsPEM(rootPEM)
	if err != nil || len(roots) != 1 {
		return nil, fmt.Errorf("connector: %s must hold exactly the root CA", fileRoot)
	}
	b, err := readStateFile(dir, fileBundle)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	cert, err := tls.X509KeyPair(b, b) // X509KeyPair skips blocks of the other kind
	if err != nil {
		return nil, fmt.Errorf("connector: key pair: %w", err)
	}
	id := &identity{info: info, root: roots[0], rootPool: x509.NewCertPool()}
	id.rootPool.AddCert(roots[0])
	if err := checkIdentity(cert.Leaf, info.TenantID, info.ConnectorID); err != nil {
		return nil, err
	}
	id.cert.Store(&cert)
	return id, nil
}

// checkIdentity verifies that leaf carries exactly the connector SPIFFE URI of
// (tenant, connector).
func checkIdentity(leaf *x509.Certificate, tenant, connector string) error {
	if len(leaf.URIs) != 1 {
		return pki.ErrNoIdentity
	}
	got, err := pki.ParseURI(leaf.URIs[0].String())
	if err != nil {
		return err
	}
	if got.Kind != pki.PeerConnector || got.TenantID != tenant || got.ConnectorID != connector {
		return fmt.Errorf("connector: certificate identity %s %s/%s, want connector %s/%s", got.Kind, got.TenantID, got.ConnectorID, tenant, connector)
	}
	return nil
}

// selfSignedCAs returns the self-signed CA certificates in certs (the provider root).
func selfSignedCAs(certs []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range certs {
		if c.IsCA && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
			out = append(out, c)
		}
	}
	return out
}
