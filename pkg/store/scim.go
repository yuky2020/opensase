package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SCIM provisioning storage (issue #68).

// SCIMUser is a user with the SCIM attributes.
type SCIMUser struct {
	User
	ExternalID string
	Active     bool
}

// SCIMGroup is a named set of users.
type SCIMGroup struct {
	ID          string
	TenantID    string
	DisplayName string
	ExternalID  string
	Members     []string // user IDs
}

// SetSCIMToken stores (replaces) the hash of the tenant's SCIM bearer token.
func (s *Store) SetSCIMToken(ctx context.Context, tenantID string, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO scim_tokens(tenant_id, token_hash, created_at) VALUES (?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET token_hash = excluded.token_hash, created_at = excluded.created_at`, tenantID, hash, time.Now().Unix())
	return mapErr(err)
}

// TenantBySCIMToken returns the tenant whose SCIM token has this hash. ErrNotFound if none.
func (s *Store) TenantBySCIMToken(ctx context.Context, hash []byte) (string, error) {
	var t string
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id FROM scim_tokens WHERE token_hash = ?`, hash).Scan(&t)
	return t, mapErr(err)
}

const scimUserCols = `id, tenant_id, email, name, external_id, active`

func scanSCIMUser(sc interface{ Scan(...any) error }) (SCIMUser, error) {
	var u SCIMUser
	var active int64
	err := sc.Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.ExternalID, &active)
	u.Active = active != 0
	return u, err
}

// GetSCIMUser returns a user with its SCIM attributes.
func (s *Store) GetSCIMUser(ctx context.Context, tenantID, id string) (SCIMUser, error) {
	u, err := scanSCIMUser(s.db.QueryRowContext(ctx, `SELECT `+scimUserCols+` FROM users WHERE tenant_id = ? AND id = ?`, tenantID, id))
	return u, mapErr(err)
}

// ListSCIMUsers lists the tenant's users, optionally only those whose email (userName) or
// external ID equals the filter value.
func (s *Store) ListSCIMUsers(ctx context.Context, tenantID, attr, value string) ([]SCIMUser, error) {
	q := `SELECT ` + scimUserCols + ` FROM users WHERE tenant_id = ?`
	args := []any{tenantID}
	switch attr {
	case "userName":
		q += ` AND lower(email) = lower(?)`
		args = append(args, value)
	case "externalId":
		q += ` AND external_id = ?`
		args = append(args, value)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY email, id`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SCIMUser
	for rows.Next() {
		u, err := scanSCIMUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PutSCIMUser creates or updates a user.
func (s *Store) PutSCIMUser(ctx context.Context, u SCIMUser) error {
	active := 0
	if u.Active {
		active = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id, tenant_id, email, name, created_at, external_id, active) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET email = excluded.email, name = excluded.name, external_id = excluded.external_id, active = excluded.active`,
		u.ID, u.TenantID, u.Email, u.Name, time.Now().Unix(), u.ExternalID, active)
	return mapErr(err)
}

// UserActive reports whether a user may enrol and keep devices.
func (s *Store) UserActive(ctx context.Context, tenantID, userID string) (bool, error) {
	var a int64
	err := s.db.QueryRowContext(ctx, `SELECT active FROM users WHERE tenant_id = ? AND id = ?`, tenantID, userID).Scan(&a)
	return a != 0, mapErr(err)
}

// RevokeUserDevices revokes every device of a user and returns their IDs.
func (s *Store) RevokeUserDevices(ctx context.Context, tenantID, userID string) ([]string, error) {
	var ids []string
	err := s.tx(ctx, func(tx *txh) error {
		rows, err := tx.QueryContext(ctx, `UPDATE devices SET revoked = 1 WHERE tenant_id = ? AND user_id = ? AND revoked = 0 RETURNING id`, tenantID, userID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// DeleteUser deletes a user, their devices and group memberships.
func (s *Store) DeleteUser(ctx context.Context, tenantID, userID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE tenant_id = ? AND id = ?`, tenantID, userID)
	return affected(res, err)
}

func (s *Store) groupMembers(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, tenantID, name string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT user_id FROM user_groups WHERE tenant_id = ? AND grp = ? ORDER BY user_id`, tenantID, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// GetSCIMGroup returns a group with its members.
func (s *Store) GetSCIMGroup(ctx context.Context, tenantID, id string) (SCIMGroup, error) {
	g := SCIMGroup{TenantID: tenantID}
	err := s.db.QueryRowContext(ctx, `SELECT id, display_name, external_id FROM scim_groups WHERE tenant_id = ? AND id = ?`, tenantID, id).
		Scan(&g.ID, &g.DisplayName, &g.ExternalID)
	if err != nil {
		return g, mapErr(err)
	}
	g.Members, err = s.groupMembers(ctx, s.db, tenantID, g.DisplayName)
	return g, err
}

// ListSCIMGroups lists the tenant's groups, optionally only the one with this display name.
func (s *Store) ListSCIMGroups(ctx context.Context, tenantID, displayName string) ([]SCIMGroup, error) {
	q := `SELECT id FROM scim_groups WHERE tenant_id = ?`
	args := []any{tenantID}
	if displayName != "" {
		q += ` AND display_name = ?`
		args = append(args, displayName)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY display_name`, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	out := make([]SCIMGroup, 0, len(ids))
	for _, id := range ids {
		g, err := s.GetSCIMGroup(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// PutSCIMGroup creates or replaces a group and its members. It returns the user IDs whose
// membership changed (their snapshots must be recompiled).
func (s *Store) PutSCIMGroup(ctx context.Context, g SCIMGroup) ([]string, error) {
	changed := map[string]bool{}
	err := s.tx(ctx, func(tx *txh) error {
		var oldName string
		err := tx.QueryRowContext(ctx, `SELECT display_name FROM scim_groups WHERE tenant_id = ? AND id = ?`, g.TenantID, g.ID).Scan(&oldName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if oldName != "" {
			old, err := s.groupMembers(ctx, tx, g.TenantID, oldName)
			if err != nil {
				return err
			}
			for _, u := range old {
				changed[u] = true
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE tenant_id = ? AND grp = ?`, g.TenantID, oldName); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO scim_groups(id, tenant_id, display_name, external_id) VALUES (?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, external_id = excluded.external_id`,
			g.ID, g.TenantID, g.DisplayName, g.ExternalID); err != nil {
			return mapErr(err)
		}
		for _, u := range g.Members {
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_groups(tenant_id, user_id, grp)
				SELECT tenant_id, id, ? FROM users WHERE tenant_id = ? AND id = ? ON CONFLICT DO NOTHING`, g.DisplayName, g.TenantID, u); err != nil {
				return mapErr(err)
			}
			changed[u] = !changed[u] || oldName != g.DisplayName
		}
		return nil
	})
	var out []string
	for u, c := range changed {
		if c {
			out = append(out, u)
		}
	}
	return out, err
}

// DeleteSCIMGroup deletes a group and returns its former members.
func (s *Store) DeleteSCIMGroup(ctx context.Context, tenantID, id string) ([]string, error) {
	var members []string
	err := s.tx(ctx, func(tx *txh) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT display_name FROM scim_groups WHERE tenant_id = ? AND id = ?`, tenantID, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		var err error
		if members, err = s.groupMembers(ctx, tx, tenantID, name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE tenant_id = ? AND grp = ?`, tenantID, name); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM scim_groups WHERE tenant_id = ? AND id = ?`, tenantID, id)
		return err
	})
	return members, err
}
