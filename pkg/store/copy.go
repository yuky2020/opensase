package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// copyTables lists every table in foreign key order, with the identity column PostgreSQL
// must continue after the copied ids ("" if none).
var copyTables = []struct{ name, identity, order string }{
	{"tenants", "", "id"},
	{"users", "", "id"},
	{"devices", "", "id"},
	{"provisioning_keys", "", "key_hash"},
	{"tenant_policy", "", "tenant_id"},
	{"user_rules", "", "user_id"},
	{"snapshot_versions", "version", "version"},
	{"flows", "id", "id"},
	{"edges", "", "id"},
	{"edge_sessions", "", "edge_id, device_id"},
	{"connectors", "", "rowid"},
	{"connector_provisioning_keys", "", "key_hash"},
	{"admin_tokens", "", "id"},
	{"admin_audit", "id", "id"},
	{"audit_anchor", "", "id"},
	{"dlp_datasets", "", "tenant_id, name"},
	{"tenant_oidc", "", "tenant_id"},
	{"device_routes", "", "device_id, cidr"},
	{"oidc_pending", "", "state"},
	{"cas", "", "tenant_id, kind"},
	{"edge_reports", "", "edge_id"},
	{"user_groups", "", "user_id, grp"},
	{"scim_groups", "", "id"},
	{"scim_tokens", "", "tenant_id"},
	{"experience_samples", "id", "id"},
}

// CopyCount is the number of rows copied for one table.
type CopyCount struct {
	Table string
	Rows  int
}

// CopyTo copies every row of s (SQLite) into dst (PostgreSQL, migrated and empty) in one
// destination transaction, then checks the row counts and the audit chain (ADR-0033). The
// source must not change during the copy: stop the Control Plane first.
func (s *Store) CopyTo(ctx context.Context, dst *Store) ([]CopyCount, error) {
	if s.db.pg || !dst.db.pg {
		return nil, errors.New("store: copy goes from SQLite to PostgreSQL")
	}
	if err := s.checkCopyTables(ctx); err != nil {
		return nil, err
	}
	var n int
	if err := dst.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, errors.New("store: the PostgreSQL database already has data")
	}
	var out []CopyCount
	err := dst.tx(ctx, func(tx *txh) error {
		for _, t := range copyTables {
			c, err := s.copyTable(ctx, tx, t.name, t.order)
			if err != nil {
				return fmt.Errorf("copy %s: %w", t.name, err)
			}
			if t.identity != "" {
				if _, err := tx.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence('`+t.name+`', '`+t.identity+`'), COALESCE((SELECT MAX(`+t.identity+`) FROM `+t.name+`), 0) + 1, false)`); err != nil {
					return fmt.Errorf("identity of %s: %w", t.name, err)
				}
			}
			out = append(out, CopyCount{Table: t.name, Rows: c})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, c := range out {
		var got int
		if err := dst.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.Table).Scan(&got); err != nil {
			return nil, err
		}
		if got != c.Rows {
			return nil, fmt.Errorf("store: %s has %d rows after the copy, want %d", c.Table, got, c.Rows)
		}
	}
	v, err := dst.VerifyAudit(ctx)
	if err != nil {
		return nil, err
	}
	if v.BadID != 0 {
		return nil, fmt.Errorf("store: audit chain does not verify after the copy at entry %d: %s", v.BadID, v.Reason)
	}
	return out, nil
}

func (s *Store) copyTable(ctx context.Context, tx *txh, table, order string) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT * FROM `+table+` ORDER BY `+order)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	q := `INSERT INTO ` + table + `(` + strings.Join(cols, ", ") + `) VALUES (?` + strings.Repeat(", ?", len(cols)-1) + `)`
	st, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return 0, err
	}
	defer func() { _ = st.Close() }()
	n := 0
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		if _, err := st.ExecContext(ctx, vals...); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// checkCopyTables fails if the SQLite schema has a table copyTables does not list, so a new
// migration cannot be forgotten here.
func (s *Store) checkCopyTables(ctx context.Context) error {
	known := map[string]bool{"schema_migrations": true, "sqlite_sequence": true}
	for _, t := range copyTables {
		known[t.name] = true
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if !known[name] {
			return fmt.Errorf("store: table %s is not in the copy list", name)
		}
	}
	return rows.Err()
}
