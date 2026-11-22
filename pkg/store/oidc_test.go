package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestTenantOIDC(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)

	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "missing tenant put",
			run: func(t *testing.T) {
				err := s.PutTenantOIDC(ctx, TenantOIDC{
					TenantID:     "missing",
					Issuer:       "https://idp.example.com",
					ClientID:     "client-1",
					ClientSecret: "secret-1",
					GroupRoles:   map[string]string{"admin-group": "admin"},
					UpdatedAt:    now,
				})
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			name: "unconfigured tenant get",
			run: func(t *testing.T) {
				_, err := s.GetTenantOIDC(ctx, "acme")
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			name: "put and get config",
			run: func(t *testing.T) {
				cfg := TenantOIDC{
					TenantID:     "acme",
					Issuer:       "https://idp.example.com",
					ClientID:     "client-1",
					ClientSecret: "secret-1",
					GroupRoles: map[string]string{
						"admins":  "admin",
						"editors": "policy-editor",
						"viewers": "viewer",
					},
					UpdatedAt: now,
				}
				if err := s.PutTenantOIDC(ctx, cfg); err != nil {
					t.Fatalf("put failed: %v", err)
				}
				got, err := s.GetTenantOIDC(ctx, "acme")
				if err != nil {
					t.Fatalf("get failed: %v", err)
				}
				if got.TenantID != cfg.TenantID || got.Issuer != cfg.Issuer || got.ClientID != cfg.ClientID || got.ClientSecret != cfg.ClientSecret {
					t.Fatalf("mismatch in fields: got %+v, want %+v", got, cfg)
				}
				if !reflect.DeepEqual(got.GroupRoles, cfg.GroupRoles) {
					t.Fatalf("mismatch in group roles: got %+v, want %+v", got.GroupRoles, cfg.GroupRoles)
				}
				if !got.UpdatedAt.Equal(cfg.UpdatedAt) {
					t.Fatalf("mismatch in updated at: got %v, want %v", got.UpdatedAt, cfg.UpdatedAt)
				}
			},
		},
		{
			name: "put update",
			run: func(t *testing.T) {
				updatedNow := now.Add(5 * time.Minute)
				updated := TenantOIDC{
					TenantID:     "acme",
					Issuer:       "https://idp2.example.com",
					ClientID:     "client-2",
					ClientSecret: "secret-2",
					GroupRoles: map[string]string{
						"super-admins": "admin",
					},
					UpdatedAt: updatedNow,
				}
				if err := s.PutTenantOIDC(ctx, updated); err != nil {
					t.Fatalf("update failed: %v", err)
				}
				got, err := s.GetTenantOIDC(ctx, "acme")
				if err != nil {
					t.Fatalf("get updated failed: %v", err)
				}
				if got.Issuer != updated.Issuer || got.ClientID != updated.ClientID || got.ClientSecret != updated.ClientSecret {
					t.Fatalf("mismatch in updated fields: got %+v", got)
				}
				if !reflect.DeepEqual(got.GroupRoles, updated.GroupRoles) {
					t.Fatalf("mismatch in updated group roles: got %+v", got.GroupRoles)
				}
			},
		},
		{
			name: "delete and re-delete",
			run: func(t *testing.T) {
				if err := s.DeleteTenantOIDC(ctx, "acme"); err != nil {
					t.Fatalf("delete failed: %v", err)
				}
				if _, err := s.GetTenantOIDC(ctx, "acme"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
				if err := s.DeleteTenantOIDC(ctx, "acme"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound on second delete, got %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}
