package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// TenantOIDC is the stored OpenID Connect configuration for a tenant (issue #17, slice B).
type TenantOIDC struct {
	TenantID     string
	Issuer       string
	ClientID     string
	ClientSecret string
	GroupRoles   map[string]string
	UpdatedAt    time.Time
}

// PutTenantOIDC creates or updates the tenant's OIDC configuration. ErrNotFound if the tenant does not exist.
func (s *Store) PutTenantOIDC(ctx context.Context, o TenantOIDC) error {
	roles := o.GroupRoles
	if roles == nil {
		roles = make(map[string]string)
	}
	raw, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("store: marshal group roles: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO tenant_oidc(tenant_id, issuer, client_id, client_secret, group_roles, updated_at)
		SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM tenants WHERE id = ?)
		ON CONFLICT(tenant_id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id,
		client_secret = excluded.client_secret, group_roles = excluded.group_roles, updated_at = excluded.updated_at`,
		o.TenantID, o.Issuer, o.ClientID, o.ClientSecret, string(raw), o.UpdatedAt.Unix(), o.TenantID)
	return affected(res, err)
}

// GetTenantOIDC retrieves the OIDC configuration of a tenant. ErrNotFound if not configured.
func (s *Store) GetTenantOIDC(ctx context.Context, tenantID string) (TenantOIDC, error) {
	var o TenantOIDC
	o.TenantID = tenantID
	var rawRoles string
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT issuer, client_id, client_secret, group_roles, updated_at FROM tenant_oidc WHERE tenant_id = ?`, tenantID).
		Scan(&o.Issuer, &o.ClientID, &o.ClientSecret, &rawRoles, &at)
	if err != nil {
		return TenantOIDC{}, mapErr(err)
	}
	if err := json.Unmarshal([]byte(rawRoles), &o.GroupRoles); err != nil {
		return TenantOIDC{}, fmt.Errorf("store: unmarshal group roles: %w", err)
	}
	if o.GroupRoles == nil {
		o.GroupRoles = make(map[string]string)
	}
	o.UpdatedAt = time.Unix(at, 0)
	return o, nil
}

// DeleteTenantOIDC removes the OIDC configuration of a tenant. ErrNotFound if it does not exist.
func (s *Store) DeleteTenantOIDC(ctx context.Context, tenantID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tenant_oidc WHERE tenant_id = ?`, tenantID)
	return affected(res, err)
}
