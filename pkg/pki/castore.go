package pki

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CA kinds kept in a CAStore.
const (
	CAKindTenant     = "tenant"
	CAKindInspection = "inspection"
)

// CAKeyEncryptionKeyFile is the default name, inside the PKI directory, of the key that
// seals CA private keys in the database. Every Control Plane replica must use the same file.
const CAKeyEncryptionKeyFile = "ca-kek.key"

// ErrCANotFound is wrapped by CAStore.GetCA when no CA is stored.
var ErrCANotFound = errors.New("pki: CA not stored")

// StoredCA is one row of a CAStore.
type StoredCA struct {
	TenantID  string
	Kind      string
	CertPEM   []byte
	SealedKey []byte
}

// CAStore keeps tenant and inspection CAs in the shared database, so every Control Plane
// replica uses the same CA for a tenant (issue #66). Private keys are sealed with the key
// encryption key before they reach the store.
type CAStore interface {
	// GetCA returns the stored CA, or an error wrapping ErrCANotFound.
	GetCA(ctx context.Context, tenantID, kind string) (StoredCA, error)
	// InsertCA stores the CA unless one already exists for tenantID and kind; then it
	// returns nil and keeps the existing row, so concurrent creators converge on the first.
	InsertCA(ctx context.Context, c StoredCA) error
	// ListCAs returns every stored CA of kind.
	ListCAs(ctx context.Context, kind string) ([]StoredCA, error)
}

// LoadOrCreateKEK loads the 32-byte key encryption key at path, creating it (mode 0600) if
// it does not exist.
func LoadOrCreateKEK(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-configured path
	switch {
	case err == nil:
		if len(b) != 32 {
			return nil, fmt.Errorf("pki: %s: key encryption key must be 32 bytes, got %d", filepath.Base(path), len(b))
		}
		return b, nil
	case errors.Is(err, os.ErrNotExist):
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := writeFile(path, k, 0o600); err != nil {
			return nil, err
		}
		return k, nil
	default:
		return nil, fmt.Errorf("pki: read key encryption key: %w", err)
	}
}

func caAAD(tenantID, kind string) []byte {
	return []byte("opensase-ca-key:" + kind + ":" + tenantID)
}

// sealKey encrypts a CA key with AES-256-GCM; the output is nonce || ciphertext. The tenant
// and kind are bound as additional data, so a sealed key cannot be moved to another row.
func sealKey(kek []byte, tenantID, kind string, ca *CA) ([]byte, error) {
	pt, err := EncodeKeyPEM(ca.Key)
	if err != nil {
		return nil, err
	}
	g, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, pt, caAAD(tenantID, kind)), nil
}

// openCA decrypts a stored CA and checks that it is a CA.
func openCA(kek []byte, c StoredCA) (*CA, error) {
	g, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(c.SealedKey) < g.NonceSize() {
		return nil, errors.New("pki: sealed CA key too short")
	}
	n := g.NonceSize()
	pt, err := g.Open(nil, c.SealedKey[:n], c.SealedKey[n:], caAAD(c.TenantID, c.Kind))
	if err != nil {
		return nil, fmt.Errorf("pki: open %s CA key of %q: wrong key encryption key or tampered row", c.Kind, c.TenantID)
	}
	key, err := ParseKeyPEM(pt)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertsPEM(c.CertPEM)
	if err != nil {
		return nil, err
	}
	if !certs[0].IsCA {
		return nil, errors.New("pki: stored certificate is not a CA")
	}
	return &CA{Cert: certs[0], Key: key}, nil
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	if len(kek) != 32 {
		return nil, errors.New("pki: key encryption key must be 32 bytes")
	}
	b, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// UseStore makes the Authority keep its tenant and inspection CAs in st (issue #66). CAs
// already in the PKI directory are imported (idempotent), and CAs created by other replicas
// are loaded. Files are still written, so the directory stays a readable copy.
func (a *Authority) UseStore(ctx context.Context, st CAStore, kek []byte) error {
	if _, err := newGCM(kek); err != nil {
		return err
	}
	a.mu.Lock()
	a.store, a.kek = st, kek
	tenants := make(map[string]*CA, len(a.tenants))
	for id, ca := range a.tenants {
		tenants[id] = ca
	}
	a.mu.Unlock()
	for id, ca := range tenants {
		if err := a.insertCA(ctx, id, CAKindTenant, ca); err != nil {
			return err
		}
		c, k := a.inspectPaths(id)
		ica, err := LoadCA(c, k)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("pki: load inspection CA %q: %w", id, err)
		}
		if err := a.insertCA(ctx, id, CAKindInspection, ica); err != nil {
			return err
		}
	}
	// The stored row wins over the local file: if another replica stored a different CA
	// for a tenant first, every replica must issue and trust that one.
	for id := range tenants {
		r, err := st.GetCA(ctx, id, CAKindTenant)
		if err != nil {
			return err
		}
		ca, err := a.fromStoreRow(r)
		if err != nil {
			return err
		}
		a.mu.Lock()
		a.tenants[id] = ca
		a.mu.Unlock()
	}
	a.mu.Lock()
	a.inspect = nil // reloaded from the store on first use
	a.mu.Unlock()
	return a.Refresh(ctx)
}

func (a *Authority) insertCA(ctx context.Context, tenantID, kind string, ca *CA) error {
	sk, err := sealKey(a.kek, tenantID, kind, ca)
	if err != nil {
		return err
	}
	return a.store.InsertCA(ctx, StoredCA{TenantID: tenantID, Kind: kind, CertPEM: ca.CertPEM(), SealedKey: sk})
}

// Refresh loads every tenant CA in the store that this Authority does not know yet, so the
// client CA pool includes tenants created by other replicas. Without a store it does nothing.
func (a *Authority) Refresh(ctx context.Context) error {
	a.mu.Lock()
	st := a.store
	a.mu.Unlock()
	if st == nil {
		return nil
	}
	rows, err := st.ListCAs(ctx, CAKindTenant)
	if err != nil {
		return err
	}
	for _, r := range rows {
		a.mu.Lock()
		_, known := a.tenants[r.TenantID]
		a.mu.Unlock()
		if known || !ValidID(r.TenantID) {
			continue
		}
		ca, err := a.fromStoreRow(r)
		if err != nil {
			return err
		}
		a.mu.Lock()
		a.tenants[r.TenantID] = ca
		a.mu.Unlock()
	}
	return nil
}

func (a *Authority) fromStoreRow(r StoredCA) (*CA, error) {
	ca, err := openCA(a.kek, r)
	if err != nil {
		return nil, err
	}
	if r.Kind == CAKindTenant {
		if got, err := TenantOfCA(ca.Cert); err != nil || got != r.TenantID {
			return nil, fmt.Errorf("pki: stored tenant CA %q has wrong identity", r.TenantID)
		}
	}
	return ca, nil
}

// storedCA returns the CA of tenantID and kind from the store, creating it with create and
// inserting it if absent. The row read back after the insert wins, so replicas racing to
// create the same CA all end up with the first one written. Callers hold a.mu.
func (a *Authority) storedCA(ctx context.Context, tenantID, kind string, create func() (*CA, error)) (*CA, error) {
	r, err := a.store.GetCA(ctx, tenantID, kind)
	if errors.Is(err, ErrCANotFound) {
		ca, cerr := create()
		if cerr != nil {
			return nil, cerr
		}
		if err := a.insertCA(ctx, tenantID, kind, ca); err != nil {
			return nil, err
		}
		r, err = a.store.GetCA(ctx, tenantID, kind)
	}
	if err != nil {
		return nil, err
	}
	return a.fromStoreRow(r)
}
