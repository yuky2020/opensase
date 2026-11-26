package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/store"
)

// TestScheduledBackup covers issue #67: a backup holds the database and the PKI directory,
// old backups are pruned, and a backup restores to a working database.
func TestScheduledBackup(t *testing.T) {
	bdir := t.TempDir()
	clock := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	e := newEnvCfg(t, func(c *Config) {
		c.BackupDir, c.BackupKeep = bdir, 2
		c.Now = func() time.Time { return clock }
	})
	e.s.cfg.PKIDir = e.dir
	e.setupTenant(1)
	ctx := context.Background()
	for i := range 3 {
		clock = clock.Add(time.Duration(i+1) * time.Hour)
		if err := e.s.backupOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(bdir)
	var dbs, pkis []string
	for _, en := range entries {
		switch {
		case strings.HasPrefix(en.Name(), "controlplane-"):
			dbs = append(dbs, en.Name())
		case strings.HasPrefix(en.Name(), "pki-"):
			pkis = append(pkis, en.Name())
		}
		if fi, _ := en.Info(); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", en.Name(), fi.Mode())
		}
	}
	if len(dbs) != 2 || len(pkis) != 2 {
		t.Fatalf("kept %v %v", dbs, pkis)
	}
	to := filepath.Join(t.TempDir(), "restored.db")
	if err := store.Restore(ctx, filepath.Join(bdir, dbs[1]), to); err != nil {
		t.Fatal(err)
	}
	r, err := store.Open(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.GetTenantPolicy(ctx, "acme"); err != nil {
		t.Fatalf("restored policy: %v", err)
	}
}
