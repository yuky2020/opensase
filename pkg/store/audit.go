package store

import (
	"context"
	"time"
)

// AuditEntry is a row of admin_audit: one admin write and who made it.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Actor    string // "super" or "token:<id>"
	TenantID string // "" for global routes
	Method   string
	Path     string
	Status   int
}

// AddAudit appends an entry.
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_audit(at, actor, tenant_id, method, path, status) VALUES (?, ?, ?, ?, ?, ?)`,
		e.At.Unix(), e.Actor, e.TenantID, e.Method, e.Path, e.Status)
	return err
}

// AuditFilter selects audit entries, newest first. AllTenants ignores TenantID.
type AuditFilter struct {
	TenantID   string
	AllTenants bool
	Limit      int // default and maximum 1000
}

// ListAudit returns audit entries, newest first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 1000
	}
	q := `SELECT id, at, actor, tenant_id, method, path, status FROM admin_audit`
	args := []any{}
	if !f.AllTenants {
		q += ` WHERE tenant_id = ?`
		args = append(args, f.TenantID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.TenantID, &e.Method, &e.Path, &e.Status); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteAuditBefore deletes entries older than t and returns how many.
func (s *Store) DeleteAuditBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM admin_audit WHERE at < ?`, t.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
