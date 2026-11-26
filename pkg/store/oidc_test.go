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

// TestOIDCPending covers issue #66: a pending sign-in is taken once, expires, and the
// capacity counts only live sign-ins.
func TestOIDCPending(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	p := OIDCPending{State: "st1", TenantID: "acme", Verifier: "v", Nonce: "n", ExpiresAt: now.Add(10 * time.Minute)}
	if err := s.PutOIDCPending(ctx, p, now, 2); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeOIDCPending(ctx, "st1", now)
	if err != nil || got.TenantID != "acme" || got.Verifier != "v" || got.Nonce != "n" {
		t.Fatalf("take %+v %v", got, err)
	}
	if _, err := s.TakeOIDCPending(ctx, "st1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take: %v", err)
	}
	old := OIDCPending{State: "old", TenantID: "acme", Verifier: "v", Nonce: "n", ExpiresAt: now.Add(-time.Second)}
	if err := s.PutOIDCPending(ctx, old, now.Add(-time.Hour), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeOIDCPending(ctx, "old", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired take: %v", err)
	}
	for i, st := range []string{"a", "b"} {
		if err := s.PutOIDCPending(ctx, OIDCPending{State: st, TenantID: "acme", ExpiresAt: now.Add(time.Minute)}, now, 2); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := s.PutOIDCPending(ctx, OIDCPending{State: "c", TenantID: "acme", ExpiresAt: now.Add(time.Minute)}, now, 2); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	// Once the two expire they no longer count.
	if err := s.PutOIDCPending(ctx, OIDCPending{State: "c", TenantID: "acme", ExpiresAt: now.Add(time.Hour)}, now.Add(2*time.Minute), 2); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}
