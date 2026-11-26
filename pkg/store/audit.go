package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"strings"
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

// The audit log is a hash chain (issue #18, ADR-0028):
//
//	hash = SHA-256(prev_hash || id || at || actor || tenant_id || method || path || status)
//
// with every field length-prefixed. The first entry's prev_hash is 32 zero bytes, or the
// anchor left by retention. Changing, inserting or removing any entry breaks every later hash,
// so a published head hash pins the whole history before it.

// auditHash computes the chained hash of e after prev.
func auditHash(prev []byte, e AuditEntry) []byte {
	h := sha256.New()
	h.Write(prev)
	var n [binary.MaxVarintLen64]byte
	put := func(b []byte) {
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(b)))])
		h.Write(b)
	}
	num := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v)) //nolint:gosec // G115: two's complement bytes, hashed only
		put(b[:])
	}
	num(e.ID)
	num(e.At.Unix())
	put([]byte(e.Actor))
	put([]byte(e.TenantID))
	put([]byte(e.Method))
	put([]byte(e.Path))
	num(int64(e.Status))
	return h.Sum(nil)
}

var zeroHash = make([]byte, sha256.Size)

// auditHead returns the hash the next entry chains to.
func auditHead(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) ([]byte, error) {
	var h []byte
	err := q.QueryRowContext(ctx, `SELECT hash FROM admin_audit WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		err = q.QueryRowContext(ctx, `SELECT hash FROM audit_anchor WHERE id = 1`).Scan(&h)
		if errors.Is(err, sql.ErrNoRows) {
			return zeroHash, nil
		}
	}
	return h, err
}

// AddAudit appends an entry to the chain. If another Control Plane replica appended to the
// same head at the same time, the unique index on prev_hash rejects this insert and the
// append is retried on the new head (issue #66).
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	s.auditMu.Lock() // avoids pointless retries inside one process
	defer s.auditMu.Unlock()
	var err error
	for range 5 {
		if err = s.addAudit(ctx, &e); !isUniqueViolation(err) {
			return err
		}
	}
	return err
}

func (s *Store) addAudit(ctx context.Context, e *AuditEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	prev, err := auditHead(ctx, tx)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO admin_audit(at, actor, tenant_id, method, path, status, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.At.Unix(), e.Actor, e.TenantID, e.Method, e.Path, e.Status, prev)
	if err != nil {
		return err
	}
	if e.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE admin_audit SET hash = ? WHERE id = ?`, auditHash(prev, *e), e.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// isUniqueViolation reports whether err is a unique constraint violation (SQLite text; the
// PostgreSQL backend matches its error code 23505).
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// chainLegacyAudit hashes the entries written before the chain existed (migration 0008),
// in order, continuing from the last chained one. It is a no-op once every row has a hash.
func (s *Store) chainLegacyAudit(ctx context.Context) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id, at, actor, tenant_id, method, path, status FROM admin_audit WHERE hash IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	var todo []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.TenantID, &e.Method, &e.Path, &e.Status); err != nil {
			_ = rows.Close()
			return err
		}
		e.At = time.Unix(at, 0)
		todo = append(todo, e)
	}
	_ = rows.Close()
	if len(todo) == 0 {
		return nil
	}
	prev, err := auditHead(ctx, tx)
	if err != nil {
		return err
	}
	for _, e := range todo {
		h := auditHash(prev, e)
		if _, err := tx.ExecContext(ctx, `UPDATE admin_audit SET prev_hash = ?, hash = ? WHERE id = ?`, prev, h, e.ID); err != nil {
			return err
		}
		prev = h
	}
	return tx.Commit()
}

// AuditVerification is the result of checking the audit chain.
type AuditVerification struct {
	Entries  int    // entries checked
	Head     []byte // hash of the newest entry (or of the anchor when empty)
	HeadID   int64
	BadID    int64 // first entry that does not verify, 0 if none
	Reason   string
	AnchorID int64 // last entry removed by retention, 0 if none
}

// VerifyAudit recomputes the chain from the retention anchor to the newest entry.
func (s *Store) VerifyAudit(ctx context.Context) (AuditVerification, error) {
	var v AuditVerification
	prev := zeroHash
	var anchorHash []byte
	err := s.db.QueryRowContext(ctx, `SELECT last_id, hash FROM audit_anchor WHERE id = 1`).Scan(&v.AnchorID, &anchorHash)
	switch {
	case err == nil:
		prev = anchorHash
	case !errors.Is(err, sql.ErrNoRows):
		return v, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, tenant_id, method, path, status, prev_hash, hash FROM admin_audit ORDER BY id`)
	if err != nil {
		return v, err
	}
	defer func() { _ = rows.Close() }()
	v.Head = prev
	for rows.Next() {
		var e AuditEntry
		var at int64
		var p, h []byte
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.TenantID, &e.Method, &e.Path, &e.Status, &p, &h); err != nil {
			return v, err
		}
		e.At = time.Unix(at, 0)
		v.Entries++
		switch {
		case e.ID <= v.AnchorID:
			v.BadID, v.Reason = e.ID, "entry older than the retention anchor"
		case !bytes.Equal(p, prev):
			v.BadID, v.Reason = e.ID, "previous hash does not match (an entry was removed, inserted or changed before it)"
		case !bytes.Equal(h, auditHash(prev, e)):
			v.BadID, v.Reason = e.ID, "hash does not match the entry (the entry was changed)"
		}
		if v.BadID != 0 {
			return v, nil
		}
		prev, v.Head, v.HeadID = h, h, e.ID
	}
	return v, rows.Err()
}

// AuditHashAt returns the stored hash of entry id (to check a previously published head).
func (s *Store) AuditHashAt(ctx context.Context, id int64) ([]byte, error) {
	var h []byte
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM admin_audit WHERE id = ?`, id).Scan(&h)
	return h, mapErr(err)
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

// DeleteAuditBefore deletes entries older than t and returns how many. The hash of the last
// deleted entry becomes the anchor the oldest remaining entry chains to.
func (s *Store) DeleteAuditBefore(ctx context.Context, t time.Time) (int64, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var lastID int64
	var h []byte
	err = tx.QueryRowContext(ctx, `SELECT id, hash FROM admin_audit WHERE at < ? ORDER BY id DESC LIMIT 1`, t.Unix()).Scan(&lastID, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	// Only a prefix of the chain may go: entries up to the newest one older than t.
	res, err := tx.ExecContext(ctx, `DELETE FROM admin_audit WHERE id <= ?`, lastID)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_anchor(id, last_id, hash) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET last_id = excluded.last_id, hash = excluded.hash`, lastID, h); err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
