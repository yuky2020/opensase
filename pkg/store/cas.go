package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yuky2020/opensase/pkg/pki"
)

var _ pki.CAStore = (*Store)(nil)

// GetCA returns a stored CA (issue #66). The error wraps pki.ErrCANotFound when absent.
func (s *Store) GetCA(ctx context.Context, tenantID, kind string) (pki.StoredCA, error) {
	c := pki.StoredCA{TenantID: tenantID, Kind: kind}
	err := s.db.QueryRowContext(ctx, `SELECT cert_pem, sealed_key FROM cas WHERE tenant_id = ? AND kind = ?`, tenantID, kind).
		Scan(&c.CertPEM, &c.SealedKey)
	if errors.Is(err, sql.ErrNoRows) {
		return c, fmt.Errorf("store: %s CA of %q: %w", kind, tenantID, pki.ErrCANotFound)
	}
	return c, err
}

// InsertCA stores c unless a CA of the same tenant and kind exists; the first row wins.
func (s *Store) InsertCA(ctx context.Context, c pki.StoredCA) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cas(tenant_id, kind, cert_pem, sealed_key, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, kind) DO NOTHING`, c.TenantID, c.Kind, c.CertPEM, c.SealedKey, time.Now().Unix())
	return err
}

// ListCAs returns every stored CA of kind.
func (s *Store) ListCAs(ctx context.Context, kind string) ([]pki.StoredCA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id, cert_pem, sealed_key FROM cas WHERE kind = ? ORDER BY tenant_id`, kind)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []pki.StoredCA
	for rows.Next() {
		c := pki.StoredCA{Kind: kind}
		if err := rows.Scan(&c.TenantID, &c.CertPEM, &c.SealedKey); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
