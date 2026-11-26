package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestAuditListAndRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	for _, e := range []AuditEntry{
		{At: now.Add(-400 * 24 * time.Hour), Actor: "super", Method: "POST", Path: "/v1/admin/tenants", Status: 201},
		{At: now.Add(-time.Hour), Actor: "token:a", TenantID: "acme", Method: "PUT", Path: "/v1/admin/tenants/acme/policy", Status: 204},
		{At: now, Actor: "token:b", TenantID: "beta", Method: "POST", Path: "/v1/admin/tenants/beta/users", Status: 201},
	} {
		if err := s.AddAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	acme, err := s.ListAudit(ctx, AuditFilter{TenantID: "acme"})
	if err != nil || len(acme) != 1 || acme[0].Actor != "token:a" {
		t.Fatalf("acme %+v %v", acme, err)
	}
	all, _ := s.ListAudit(ctx, AuditFilter{AllTenants: true, Limit: 2})
	if len(all) != 2 || all[0].Actor != "token:b" {
		t.Fatalf("all newest first, limited: %+v", all)
	}
	n, err := s.DeleteAuditBefore(ctx, now.Add(-365*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("retention deleted %d %v", n, err)
	}
}

// TestAuditChain covers issue #18: the chain verifies, and any change, removal or insertion
// is found; retention keeps the remainder verifiable through the anchor.
func TestAuditChain(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	base := time.Unix(1_800_000_000, 0)
	for i := range 6 {
		if err := s.AddAudit(ctx, AuditEntry{At: base.Add(time.Duration(i) * time.Hour), Actor: "super", Method: "PUT", Path: "/v1/admin/x", Status: 204}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.VerifyAudit(ctx)
	if err != nil || v.BadID != 0 || v.Entries != 6 || v.HeadID != 6 || len(v.Head) != 32 {
		t.Fatalf("verify %+v %v", v, err)
	}
	head3, _ := s.AuditHashAt(ctx, 3)

	// Retention: the first two go, the rest still verifies.
	if n, err := s.DeleteAuditBefore(ctx, base.Add(90*time.Minute)); err != nil || n != 2 {
		t.Fatalf("prune %d %v", n, err)
	}
	if v, _ := s.VerifyAudit(ctx); v.BadID != 0 || v.Entries != 4 || v.AnchorID != 2 {
		t.Fatalf("after prune %+v", v)
	}
	if h, _ := s.AuditHashAt(ctx, 3); !bytes.Equal(h, head3) {
		t.Fatal("published hash of entry 3 changed")
	}

	tamper := func(name, q string, want int64) {
		t.Helper()
		snap, anchor := snapshotAudit(t, s)
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
		if v, _ := s.VerifyAudit(ctx); v.BadID != want {
			t.Errorf("%s: bad id %d (%s), want %d", name, v.BadID, v.Reason, want)
		}
		restoreAudit(t, s, snap, anchor)
	}
	tamper("changed actor", `UPDATE admin_audit SET actor = 'token:x' WHERE id = 4`, 4)
	tamper("removed entry", `DELETE FROM admin_audit WHERE id = 4`, 5)
	tamper("forged entry", `INSERT INTO admin_audit(id, at, actor, tenant_id, method, path, status, prev_hash, hash) SELECT 7, at, actor, tenant_id, method, path, status, hash, hash FROM admin_audit WHERE id = 6`, 7)
	tamper("rewritten anchor", `UPDATE audit_anchor SET hash = zeroblob(32)`, 3)
	if v, _ := s.VerifyAudit(ctx); v.BadID != 0 {
		t.Fatalf("restore: %+v", v)
	}

	// Rows written before the chain existed are chained at start.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO admin_audit(at, actor, tenant_id, method, path, status) VALUES (?, 'super', '', 'POST', '/legacy', 201)`, base.Add(7*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := s.chainLegacyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.VerifyAudit(ctx); v.BadID != 0 || v.Entries != 5 {
		t.Fatalf("legacy %+v", v)
	}
}

type auditRow struct {
	id, at, status      int64
	actor, tenant, m, p string
	prev, hash          []byte
}

func snapshotAudit(t *testing.T, s *Store) ([]auditRow, []byte) {
	t.Helper()
	rows, err := s.db.Query(`SELECT id, at, actor, tenant_id, method, path, status, prev_hash, hash FROM admin_audit ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		_ = rows.Scan(&r.id, &r.at, &r.actor, &r.tenant, &r.m, &r.p, &r.status, &r.prev, &r.hash)
		out = append(out, r)
	}
	var anchor []byte
	_ = s.db.QueryRow(`SELECT hash FROM audit_anchor WHERE id = 1`).Scan(&anchor)
	return out, anchor
}

func restoreAudit(t *testing.T, s *Store, snap []auditRow, anchor []byte) {
	t.Helper()
	if _, err := s.db.Exec(`DELETE FROM admin_audit`); err != nil {
		t.Fatal(err)
	}
	for _, r := range snap {
		if _, err := s.db.Exec(`INSERT INTO admin_audit(id, at, actor, tenant_id, method, path, status, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.id, r.at, r.actor, r.tenant, r.m, r.p, r.status, r.prev, r.hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE audit_anchor SET hash = ?`, anchor); err != nil {
		t.Fatal(err)
	}
}

// TestAuditPrevHashUnique covers issue #66: a second entry chained to the same head (what
// two replicas appending at once would write) is rejected, so the chain cannot fork.
func TestAuditPrevHashUnique(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := range 3 {
		if err := s.AddAudit(ctx, AuditEntry{At: time.Now(), Actor: "super", Method: "POST", Path: "/v1/admin/tenants", Status: 200 + i}); err != nil {
			t.Fatal(err)
		}
	}
	var prev []byte
	if err := s.db.QueryRowContext(ctx, `SELECT prev_hash FROM admin_audit ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_audit(at, actor, tenant_id, method, path, status, prev_hash) VALUES (?, 'x', '', 'GET', '/', 200, ?)`, time.Now().Unix(), prev)
	if !isUniqueViolation(err) {
		t.Fatalf("forked insert: want unique violation, got %v", err)
	}
	v, err := s.VerifyAudit(ctx)
	if err != nil || v.BadID != 0 || v.Entries != 3 {
		t.Fatalf("verify %+v %v", v, err)
	}
}
