package pki

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// memCAStore is an in-memory CAStore.
type memCAStore struct {
	mu   sync.Mutex
	rows map[string]StoredCA
}

func (m *memCAStore) GetCA(_ context.Context, tenantID, kind string) (StoredCA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[kind+"/"+tenantID]
	if !ok {
		return StoredCA{}, ErrCANotFound
	}
	return r, nil
}

func (m *memCAStore) InsertCA(_ context.Context, c StoredCA) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]StoredCA{}
	}
	if _, ok := m.rows[c.Kind+"/"+c.TenantID]; !ok {
		m.rows[c.Kind+"/"+c.TenantID] = c
	}
	return nil
}

func (m *memCAStore) ListCAs(_ context.Context, kind string) ([]StoredCA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredCA
	for _, r := range m.rows {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out, nil
}

// replicaDirs returns two PKI directories with the same root CA, as two Control Plane
// replicas sharing a PKI Secret would have.
func replicaDirs(t *testing.T) (string, string) {
	t.Helper()
	a := t.TempDir()
	if err := InitDir(a, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	b := t.TempDir()
	for _, f := range []string{RootCertFile, RootKeyFile} {
		data, err := os.ReadFile(filepath.Join(a, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(b, f), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestSealedCAKey(t *testing.T) {
	ca, err := newInspectionRoot("acme")
	if err != nil {
		t.Fatal(err)
	}
	kek := bytes.Repeat([]byte{7}, 32)
	sk, err := sealKey(kek, "acme", CAKindInspection, ca)
	if err != nil {
		t.Fatal(err)
	}
	row := StoredCA{TenantID: "acme", Kind: CAKindInspection, CertPEM: ca.CertPEM(), SealedKey: sk}
	got, err := openCA(kek, row)
	if err != nil || !got.Key.Equal(ca.Key) {
		t.Fatalf("round trip: %v", err)
	}
	if bytes.Contains(sk, []byte("PRIVATE KEY")) {
		t.Fatal("sealed key holds the PEM in clear")
	}
	flipped := bytes.Clone(sk)
	flipped[len(flipped)-1] ^= 1
	moved := row
	moved.TenantID = "beta"
	for name, r := range map[string]StoredCA{"tampered": {TenantID: "acme", Kind: CAKindInspection, CertPEM: row.CertPEM, SealedKey: flipped}, "other tenant": moved} {
		if _, err := openCA(kek, r); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
	if _, err := openCA(bytes.Repeat([]byte{8}, 32), row); err == nil {
		t.Fatal("wrong key encryption key: opened")
	}
}

// TestAuthorityStoreReplicas covers issue #66: two replicas sharing a store use one tenant
// CA and one inspection CA, and a replica learns tenants created elsewhere on Refresh.
func TestAuthorityStoreReplicas(t *testing.T) {
	ctx := context.Background()
	da, db := replicaDirs(t)
	st := &memCAStore{}
	kek, err := LoadOrCreateKEK(filepath.Join(da, CAKeyEncryptionKeyFile))
	if err != nil || len(kek) != 32 {
		t.Fatalf("kek %d %v", len(kek), err)
	}
	if again, _ := LoadOrCreateKEK(filepath.Join(da, CAKeyEncryptionKeyFile)); !bytes.Equal(again, kek) {
		t.Fatal("key encryption key not reloaded")
	}
	a, err := OpenAuthority(da)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenAuthority(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UseStore(ctx, st, kek); err != nil {
		t.Fatal(err)
	}
	if err := b.UseStore(ctx, st, kek); err != nil {
		t.Fatal(err)
	}
	caA, err := a.TenantCA(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	caB, err := b.TenantCA(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !caA.Cert.Equal(caB.Cert) || !caA.Key.Equal(caB.Key) {
		t.Fatal("replicas created different tenant CAs")
	}
	iA, err := a.InspectionCA(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	iB, err := b.InspectionCA(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !iA.Cert.Equal(iB.Cert) {
		t.Fatal("replicas created different inspection CAs")
	}
	if _, err := a.TenantCA(context.Background(), "beta"); err != nil {
		t.Fatal(err)
	}
	if err := b.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b.BundlePEM(), mustTenant(t, a, "beta").CertPEM()) {
		t.Fatal("refresh did not load the tenant created on the other replica")
	}
}

// TestAuthorityStoreImport: CAs that exist only as files are imported, and the stored row
// wins over a different local file.
func TestAuthorityStoreImport(t *testing.T) {
	ctx := context.Background()
	da, db := replicaDirs(t)
	kek := bytes.Repeat([]byte{1}, 32)
	a, _ := OpenAuthority(da)
	fileCA, err := a.TenantCA(context.Background(), "acme") // file-only mode
	if err != nil {
		t.Fatal(err)
	}
	st := &memCAStore{}
	a2, _ := OpenAuthority(da)
	if err := a2.UseStore(ctx, st, kek); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetCA(ctx, "acme", CAKindTenant); err != nil {
		t.Fatalf("file CA not imported: %v", err)
	}
	// Replica b had its own file CA for acme before it joined the store.
	b, _ := OpenAuthority(db)
	if _, err := b.TenantCA(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	b2, _ := OpenAuthority(db)
	if err := b2.UseStore(ctx, st, kek); err != nil {
		t.Fatal(err)
	}
	if got := mustTenant(t, b2, "acme"); !got.Cert.Equal(fileCA.Cert) {
		t.Fatal("local file won over the stored CA")
	}
	if _, err := st.GetCA(ctx, "nobody", CAKindTenant); !errors.Is(err, ErrCANotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func mustTenant(t *testing.T, a *Authority, id string) *CA {
	t.Helper()
	ca, err := a.TenantCA(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
