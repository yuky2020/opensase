package edge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// restart builds a second Edge with the same configuration (same key, same state dir), as
// after a process restart.
func restart(t *testing.T, e *Edge, cp controlPlane) *Edge {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e2, err := newEdge(ctx, e.cfg, cp)
	if err != nil {
		t.Fatal(err)
	}
	return e2
}

// TestCategoryCache covers issue #23 for web categories: saved after a fetch, loaded on
// restart without the Control Plane, refused when tampered or written by another Edge.
func TestCategoryCache(t *testing.T) {
	dir := t.TempDir()
	fx := newFixtureCfg(t, func(c *Config) { c.StateDir = dir })
	fx.cats = []string{"gambling"}
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	fx.cp.mu.Lock()
	fx.cp.categories = testCategories(t)
	fx.cp.mu.Unlock()
	if err := fx.e.syncCategories(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, categoriesCacheFile)
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache file %v %v", st, err)
	}

	// Restart with the Control Plane down.
	down := &fakeCP{}
	e2 := restart(t, fx.e, down)
	if err := e2.loadCategories(); err != nil {
		t.Fatal(err)
	}
	c := fx.e.reg.get("d1").compiled.Load()
	if cat, ok := e2.category(c, "www.casino.example"); !ok || cat != "gambling" {
		t.Fatalf("cached category not enforced: %q %v", cat, ok)
	}

	// Tampered: one byte changed.
	b, _ := os.ReadFile(path)
	bad := append([]byte(nil), b...)
	bad[len(bad)/2] ^= 0x01
	_ = os.WriteFile(path, bad, 0o600)
	if err := restart(t, fx.e, down).loadCategories(); err == nil {
		t.Fatal("tampered cache loaded")
	}
	// Written by another Edge (another certificate key).
	_ = os.WriteFile(path, b, 0o600)
	other := newFixtureCfg(t, func(c *Config) { c.StateDir = dir })
	if err := other.e.loadCategories(); err == nil {
		t.Fatal("cache of another edge loaded")
	}
}

// TestInspectionCache covers issue #23 for TLS inspection: the intermediate is cached when
// issued and used after a restart with the Control Plane down.
func TestInspectionCache(t *testing.T) {
	z := newInspectFixture(t, testWeb)
	dir := t.TempDir()
	z.e.cfg.StateDir = dir
	if _, err := z.e.insp.ca(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, inspectCacheFile("acme"))
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("inspection cache %v %v", st, err)
	}

	// Restart, Control Plane refuses (down): the cached intermediate serves.
	down := &fakeCP{inspect: nil}
	e2 := restart(t, z.e, down)
	e2.loadInspection()
	ca, err := e2.insp.ca(context.Background(), "acme")
	if err != nil {
		t.Fatalf("cached intermediate not used: %v", err)
	}
	if _, err := e2.insp.leaf(ca, "example.com"); err != nil {
		t.Fatal(err)
	}

	// A Private Edge of another tenant ignores it; a renamed file is refused.
	e3 := restart(t, z.e, down)
	e3.cfg.TenantID = "beta"
	e3.loadInspection()
	if e3.insp.cas["acme"] != nil {
		t.Fatal("private edge of beta loaded acme's intermediate")
	}
	_ = os.Rename(path, filepath.Join(dir, inspectCacheFile("beta")))
	e4 := restart(t, z.e, down)
	e4.loadInspection()
	if len(e4.insp.cas) != 0 {
		t.Fatal("renamed cache loaded")
	}
}
