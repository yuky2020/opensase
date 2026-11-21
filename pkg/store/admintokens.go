package store

import (
	"context"
	"errors"
	"time"
)

// AdminToken is a row of admin_tokens: a credential that administers one tenant (ST-03).
// Hash is the SHA-256 of the secret token; the token itself is never stored.
type AdminToken struct {
	ID        string
	TenantID  string
	Name      string
	Hash      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
	LastUsed  time.Time // zero if never used
}

const adminTokenCols = `id, tenant_id, name, created_at, expires_at, revoked, last_used` //nolint:gosec // G101: column list, not a credential

func scanAdminToken(sc interface{ Scan(...any) error }) (AdminToken, error) {
	var t AdminToken
	var created, expires, used int64
	err := sc.Scan(&t.ID, &t.TenantID, &t.Name, &created, &expires, &t.Revoked, &used)
	t.CreatedAt, t.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	if used > 0 {
		t.LastUsed = time.Unix(used, 0)
	}
	return t, err
}

// CreateAdminToken stores a tenant admin token. ErrNotFound if the tenant does not exist,
// ErrConflict if the ID is taken.
func (s *Store) CreateAdminToken(ctx context.Context, t AdminToken) error {
	if len(t.Hash) != 32 {
		return errors.New("store: admin token hash must be 32 bytes")
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO admin_tokens(id, tenant_id, name, token_hash, created_at, expires_at)
		SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM tenants WHERE id = ?)`,
		t.ID, t.TenantID, t.Name, t.Hash, t.CreatedAt.Unix(), t.ExpiresAt.Unix(), t.TenantID)
	return affected(res, err)
}

// AuthAdminToken returns the live (not revoked, not expired) admin token with the given hash
// and records its use. ErrNotFound otherwise.
func (s *Store) AuthAdminToken(ctx context.Context, hash []byte, now time.Time) (AdminToken, error) {
	t, err := scanAdminToken(s.db.QueryRowContext(ctx, `SELECT `+adminTokenCols+` FROM admin_tokens
		WHERE token_hash = ? AND revoked = 0 AND expires_at > ?`, hash, now.Unix()))
	if err != nil {
		return AdminToken{}, mapErr(err)
	}
	// Coarse last-use tracking: one write per minute at most.
	if now.Sub(t.LastUsed) >= time.Minute {
		if _, err := s.db.ExecContext(ctx, `UPDATE admin_tokens SET last_used = ? WHERE id = ?`, now.Unix(), t.ID); err != nil {
			return AdminToken{}, err
		}
		t.LastUsed = time.Unix(now.Unix(), 0)
	}
	return t, nil
}

// ListAdminTokens returns the tenant's admin tokens, newest first.
func (s *Store) ListAdminTokens(ctx context.Context, tenantID string) ([]AdminToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+adminTokenCols+` FROM admin_tokens WHERE tenant_id = ? ORDER BY created_at DESC, id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AdminToken{}
	for rows.Next() {
		t, err := scanAdminToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAdminToken revokes one of the tenant's admin tokens. ErrNotFound if it does not exist.
func (s *Store) RevokeAdminToken(ctx context.Context, tenantID, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admin_tokens SET revoked = 1 WHERE tenant_id = ? AND id = ?`, tenantID, id)
	return affected(res, err)
}
