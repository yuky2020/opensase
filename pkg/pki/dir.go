package pki

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// File names inside a PKI directory.
const (
	RootCertFile    = "root.crt"
	RootKeyFile     = "root.key"
	CPCertFile      = "controlplane.crt"
	CPKeyFile       = "controlplane.key"
	EdgeCertFile    = "edge.crt"
	EdgeKeyFile     = "edge.key"
	EdgeWGKeyFile   = "edge-wg.key" // base64 Curve25519 private key
	SnapshotKeyFile = "snapshot.key"
	TenantsDir      = "tenants"
	// EdgeDir holds everything a Edge needs and nothing else (root.crt, edge.crt,
	// edge.key, edge-wg.key). Mount only this directory into the Edge; the Control Plane never
	// needs it (edges.json carries the WireGuard public key).
	EdgeDir          = "edge"
	tenantCertSuffix = "ca.crt"
	tenantKeySuffix  = "ca.key"
)

// InitOptions configures InitDir.
type InitOptions struct {
	EdgeID   string // default "edge-1"
	CPSANs   ServerCertOptions
	EdgeSANs ServerCertOptions
}

// InitDir creates a dev PKI in dir: root CA, Control Plane cert and the snapshot signing key
// at the top level, and in dir/edge (EdgeDir) a copy of the root certificate, the Edge cert
// and key and the Edge WireGuard key. Server certs without explicit SANs get
// DevServerSANs. Existing files are kept (idempotent); Edge files left at the top level by
// older versions are moved into dir/edge. Keys are written with mode 0600 (encryption at rest
// is out of scope for dev).
func InitDir(dir string, o InitOptions) error {
	if o.EdgeID == "" {
		o.EdgeID = "edge-1"
	}
	edgeDir := filepath.Join(dir, EdgeDir)
	for _, d := range []string{filepath.Join(dir, TenantsDir), edgeDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("pki: mkdir: %w", err)
		}
	}
	for _, f := range []string{EdgeCertFile, EdgeKeyFile, EdgeWGKeyFile} {
		legacy := filepath.Join(dir, f)
		if exists(legacy) && !exists(filepath.Join(edgeDir, f)) {
			if err := os.Rename(legacy, filepath.Join(edgeDir, f)); err != nil {
				return fmt.Errorf("pki: move %s into %s: %w", f, EdgeDir, err)
			}
		}
	}
	root, err := LoadCA(filepath.Join(dir, RootCertFile), filepath.Join(dir, RootKeyFile))
	if errors.Is(err, fs.ErrNotExist) {
		if root, err = NewRootCA("OpenSASE Dev Root CA"); err != nil {
			return err
		}
		if err = SaveCA(root, filepath.Join(dir, RootCertFile), filepath.Join(dir, RootKeyFile)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(edgeDir, RootCertFile), root.CertPEM(), 0o644); err != nil {
		return err
	}
	for _, s := range []struct {
		dir, cert, key string
		opts           ServerCertOptions
		kind           ServerKind
	}{
		{dir, CPCertFile, CPKeyFile, o.CPSANs, KindControlPlane},
		{edgeDir, EdgeCertFile, EdgeKeyFile, o.EdgeSANs, KindEdge},
	} {
		if exists(filepath.Join(s.dir, s.cert)) {
			continue
		}
		opts := s.opts
		opts.Kind = s.kind
		opts.ID = o.EdgeID
		if len(opts.DNSNames) == 0 && len(opts.IPs) == 0 {
			opts.DNSNames, opts.IPs = DevServerSANs(s.kind)
		}
		c, k, err := root.IssueServerCert(opts)
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(s.dir, s.key), k, 0o600); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(s.dir, s.cert), append(c, root.CertPEM()...), 0o644); err != nil {
			return err
		}
	}
	if !exists(filepath.Join(edgeDir, EdgeWGKeyFile)) {
		priv, _, err := NewWireGuardKey()
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(edgeDir, EdgeWGKeyFile), []byte(priv+"\n"), 0o600); err != nil {
			return err
		}
	}
	if _, _, err := LoadOrCreateSigningKey(filepath.Join(dir, SnapshotKeyFile)); err != nil {
		return err
	}
	return nil
}

// LoadCA loads a CA certificate and key from PEM files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	cb, err := os.ReadFile(certPath) //nolint:gosec // G304: path is chosen by the caller (operator flag); reading it is this function's job
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyPath) //nolint:gosec // G304: path is chosen by the caller (operator flag); reading it is this function's job
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertsPEM(cb)
	if err != nil {
		return nil, err
	}
	key, err := ParseKeyPEM(kb)
	if err != nil {
		return nil, err
	}
	if !certs[0].IsCA {
		return nil, errors.New("pki: certificate is not a CA")
	}
	return &CA{Cert: certs[0], Key: key}, nil
}

// SaveCA writes a CA certificate (0644) and key (0600).
func SaveCA(ca *CA, certPath, keyPath string) error {
	kp, err := EncodeKeyPEM(ca.Key)
	if err != nil {
		return err
	}
	if err := writeFile(keyPath, kp, 0o600); err != nil {
		return err
	}
	return writeFile(certPath, ca.CertPEM(), 0o644)
}

// Authority holds the root CA and lazily created tenant CAs from a PKI directory.
// It is safe for concurrent use.
type Authority struct {
	dir  string
	Root *CA

	mu      sync.Mutex
	tenants map[string]*CA
	inspect map[string]*CA // tenant inspection roots (ADR-0018), loaded on first use
}

// OpenAuthority loads the root CA from dir and every tenant CA under dir/tenants.
func OpenAuthority(dir string) (*Authority, error) {
	root, err := LoadCA(filepath.Join(dir, RootCertFile), filepath.Join(dir, RootKeyFile))
	if err != nil {
		return nil, fmt.Errorf("pki: load root CA: %w", err)
	}
	a := &Authority{dir: dir, Root: root, tenants: map[string]*CA{}}
	entries, err := os.ReadDir(filepath.Join(dir, TenantsDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("pki: read tenants: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		ca, err := a.loadTenant(e.Name())
		if err != nil {
			return nil, err
		}
		a.tenants[e.Name()] = ca
	}
	return a, nil
}

func (a *Authority) tenantPaths(t string) (string, string) {
	d := filepath.Join(a.dir, TenantsDir, t)
	return filepath.Join(d, tenantCertSuffix), filepath.Join(d, tenantKeySuffix)
}

func (a *Authority) loadTenant(t string) (*CA, error) {
	c, k := a.tenantPaths(t)
	ca, err := LoadCA(c, k)
	if err != nil {
		return nil, fmt.Errorf("pki: load tenant CA %q: %w", t, err)
	}
	if got, err := TenantOfCA(ca.Cert); err != nil || got != t {
		return nil, fmt.Errorf("pki: tenant CA %q has wrong identity", t)
	}
	return ca, nil
}

// TenantCA returns the CA of tenantID, creating and persisting it on first use.
func (a *Authority) TenantCA(tenantID string) (*CA, error) {
	if !ValidID(tenantID) {
		return nil, fmt.Errorf("pki: invalid tenant id %q", tenantID)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ca, ok := a.tenants[tenantID]; ok {
		return ca, nil
	}
	ca, err := a.Root.NewTenantCA(tenantID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(a.dir, TenantsDir, tenantID), 0o700); err != nil {
		return nil, fmt.Errorf("pki: mkdir tenant: %w", err)
	}
	c, k := a.tenantPaths(tenantID)
	if err := SaveCA(ca, c, k); err != nil {
		return nil, err
	}
	a.tenants[tenantID] = ca
	return ca, nil
}

// BundlePEM returns root CA followed by every tenant CA, in PEM form.
func (a *Authority) BundlePEM() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.Root.CertPEM()
	for _, ca := range a.tenants {
		out = append(out, ca.CertPEM()...)
	}
	return out
}

// ClientCAPool returns a pool with the root and all tenant CAs. Tenant CAs are added as
// anchors so that clients presenting only their leaf still verify; VerifyPeer then checks
// the chain shape against the root.
func (a *Authority) ClientCAPool() *x509.CertPool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := x509.NewCertPool()
	p.AddCert(a.Root.Cert)
	for _, ca := range a.tenants {
		p.AddCert(ca.Cert)
	}
	return p
}

// LoadOrCreateSigningKey loads the Ed25519 snapshot signing key at path or creates it.
// It returns the key and its key ID.
func LoadOrCreateSigningKey(path string) (ed25519.PrivateKey, string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is chosen by the caller (operator flag); reading it is this function's job
	if errors.Is(err, fs.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("pki: generate signing key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, "", fmt.Errorf("pki: marshal signing key: %w", err)
		}
		if err := writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, "", err
		}
		return priv, SigningKeyID(priv.Public().(ed25519.PublicKey)), nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("pki: read signing key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, "", errors.New("pki: signing key is not a PKCS#8 PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("pki: parse signing key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, "", errors.New("pki: signing key is not Ed25519")
	}
	return priv, SigningKeyID(priv.Public().(ed25519.PublicKey)), nil
}

// SigningKeyID derives a stable key ID from an Ed25519 public key.
func SigningKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(h[:8])
}

// NewWireGuardKey generates a Curve25519 key pair, base64 encoded (wg genkey format).
func NewWireGuardKey() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("pki: generate wireguard key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// LoadWireGuardKey reads a base64 Curve25519 private key file and returns the raw private
// and public keys.
func LoadWireGuardKey(path string) (priv, pub []byte, err error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is chosen by the caller (operator flag); reading it is this function's job
	if err != nil {
		return nil, nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	clear(b)
	if err != nil {
		return nil, nil, errors.New("pki: wireguard key is not base64")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: wireguard key: %w", err)
	}
	return raw, k.PublicKey().Bytes(), nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("pki: write %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("pki: chmod: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("pki: rename: %w", err)
	}
	return nil
}
