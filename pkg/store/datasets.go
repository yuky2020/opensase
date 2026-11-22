package store

import (
	"context"
	"encoding/binary"
	"errors"
	"time"
)

// Dataset is a DLP dataset (ADR-0029): keyed hashes of protected values or documents.
type Dataset struct {
	TenantID  string
	Name      string
	Kind      string
	Key       []byte
	Hashes    []uint64 // sorted; empty in listings
	Count     int
	UpdatedAt time.Time
}

func packHashes(h []uint64) []byte {
	b := make([]byte, 8*len(h))
	for i, v := range h {
		binary.BigEndian.PutUint64(b[8*i:], v)
	}
	return b
}

func unpackHashes(b []byte) ([]uint64, error) {
	if len(b)%8 != 0 {
		return nil, errors.New("store: damaged dataset hashes")
	}
	out := make([]uint64, len(b)/8)
	for i := range out {
		out[i] = binary.BigEndian.Uint64(b[8*i:])
	}
	return out, nil
}

// PutDataset creates or replaces a dataset. ErrNotFound if the tenant does not exist.
func (s *Store) PutDataset(ctx context.Context, d Dataset) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO dlp_datasets(tenant_id, name, kind, hkey, hashes, count, updated_at)
		SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM tenants WHERE id = ?)
		ON CONFLICT(tenant_id, name) DO UPDATE SET kind = excluded.kind, hkey = excluded.hkey, hashes = excluded.hashes,
		count = excluded.count, updated_at = excluded.updated_at`,
		d.TenantID, d.Name, d.Kind, d.Key, packHashes(d.Hashes), len(d.Hashes), d.UpdatedAt.Unix(), d.TenantID)
	return affected(res, err)
}

// ListDatasets returns the tenant's datasets without keys or hashes.
func (s *Store) ListDatasets(ctx context.Context, tenantID string) ([]Dataset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, kind, count, updated_at FROM dlp_datasets WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Dataset{}
	for rows.Next() {
		d := Dataset{TenantID: tenantID}
		var at int64
		if err := rows.Scan(&d.Name, &d.Kind, &d.Count, &at); err != nil {
			return nil, err
		}
		d.UpdatedAt = time.Unix(at, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDatasets returns the named datasets of the tenant with keys and hashes (unknown names
// are skipped).
func (s *Store) GetDatasets(ctx context.Context, tenantID string, names []string) ([]Dataset, error) {
	out := []Dataset{}
	for _, n := range names {
		d := Dataset{TenantID: tenantID, Name: n}
		var b []byte
		var at int64
		err := s.db.QueryRowContext(ctx, `SELECT kind, hkey, hashes, count, updated_at FROM dlp_datasets WHERE tenant_id = ? AND name = ?`, tenantID, n).
			Scan(&d.Kind, &d.Key, &b, &d.Count, &at)
		if errors.Is(mapErr(err), ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if d.Hashes, err = unpackHashes(b); err != nil {
			return nil, err
		}
		d.UpdatedAt = time.Unix(at, 0)
		out = append(out, d)
	}
	return out, nil
}

// DeleteDataset removes a dataset. ErrNotFound if it does not exist.
func (s *Store) DeleteDataset(ctx context.Context, tenantID, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dlp_datasets WHERE tenant_id = ? AND name = ?`, tenantID, name)
	return affected(res, err)
}
