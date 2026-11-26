package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// TestBackupRestore covers issue #67: a backup taken while the store is open restores to a
// database with the same tenants, users, policy and audit chain.
func TestBackupRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s)
	if err := s.PutTenantPolicy(ctx, "acme", api.TenantPolicy{Categories: []string{"malware"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAudit(ctx, AuditEntry{At: time.Now(), Actor: "super", Method: "PUT", Path: "/p", Status: 204}); err != nil {
		t.Fatal(err)
	}
	bk := filepath.Join(dir, "backup.db")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, bk); err == nil {
		t.Fatal("backup over an existing file")
	}
	if fi, err := os.Stat(bk); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v %v", fi.Mode(), err)
	}
	// Changes after the backup are not in it.
	if err := s.CreateTenant(ctx, Tenant{ID: "late", Name: "Late"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	to := filepath.Join(dir, "restored.db")
	if err := Restore(ctx, bk, to); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, bk, to); err == nil {
		t.Fatal("restore over an existing database")
	}
	r, err := Open(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p, err := r.GetTenantPolicy(ctx, "acme")
	if err != nil || len(p.Categories) != 1 {
		t.Fatalf("policy %+v %v", p, err)
	}
	if _, err := r.GetTenant(ctx, "late"); err == nil {
		t.Fatal("restored database has a change made after the backup")
	}
	if v, err := r.VerifyAudit(ctx); err != nil || v.BadID != 0 || v.Entries != 1 {
		t.Fatalf("audit %+v %v", v, err)
	}

	bad := filepath.Join(dir, "bad.db")
	if err := os.WriteFile(bad, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, bad, filepath.Join(dir, "x.db")); err == nil {
		t.Fatal("restored a corrupt backup")
	}
	if _, err := os.Stat(filepath.Join(dir, "x.db")); err == nil {
		t.Fatal("corrupt restore left a database")
	}
}
