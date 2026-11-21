package store

import (
	"context"
	"testing"
	"time"
)

func TestAuditListAndRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	for _, e := range []AuditEntry{
		{At: now.Add(-400 * 24 * time.Hour), Actor: "super", Method: "POST", Path: "/v1/admin/tenants", Status: 201},
		{At: now.Add(-time.Hour), Actor: "token:a", TenantID: "acme", Method: "PUT", Path: "/v1/admin/tenants/acme/policy", Status: 204},
		{At: now, Actor: "token:b", TenantID: "beta", Method: "POST", Path: "/v1/admin/tenants/beta/users", Status: 201},
	} {
		if err := s.AddAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	acme, err := s.ListAudit(ctx, AuditFilter{TenantID: "acme"})
	if err != nil || len(acme) != 1 || acme[0].Actor != "token:a" {
		t.Fatalf("acme %+v %v", acme, err)
	}
	all, _ := s.ListAudit(ctx, AuditFilter{AllTenants: true, Limit: 2})
	if len(all) != 2 || all[0].Actor != "token:b" {
		t.Fatalf("all newest first, limited: %+v", all)
	}
	n, err := s.DeleteAuditBefore(ctx, now.Add(-365*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("retention deleted %d %v", n, err)
	}
}
