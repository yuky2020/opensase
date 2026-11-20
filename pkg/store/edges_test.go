package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// enrollDevice creates device id with cert serial "1".
func enrollDevice(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	h := sha256.Sum256([]byte("key-" + id))
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h[:], TenantID: "acme", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, h[:], time.Now(), func(Enrollment) (Device, error) {
		return Device{ID: id, Name: "phone", Platform: "android", CertSerial: "1"}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRenewDeviceCert(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	enrollDevice(t, s, "d1")
	enrollDevice(t, s, "d2")
	if err := s.RevokeDevice(ctx, "acme", "d2"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		dev, old, new string
		want          error
	}{
		{"renew", "d1", "1", "2", nil},
		{"retry with the previous cert (lost response)", "d1", "1", "3", nil},
		{"stale serial", "d1", "2", "4", ErrConflict},
		{"renew with the delivered cert", "d1", "3", "5", nil},
		{"superseded twice", "d1", "1", "6", ErrConflict},
		{"revoked", "d2", "1", "2", ErrRevoked},
		{"unknown", "nope", "1", "2", ErrNotFound},
	}
	for _, tc := range tests {
		if err := s.RenewDeviceCert(ctx, tc.dev, tc.old, tc.new); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v want %v", tc.name, err, tc.want)
		}
	}
	if d, _ := s.GetDevice(ctx, "d1"); d.CertSerial != "5" || d.PrevCertSerial != "3" {
		t.Fatalf("serial %q prev %q", d.CertSerial, d.PrevCertSerial)
	}
}

func TestEdgesAndSessions(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	enrollDevice(t, s, "d1")
	enrollDevice(t, s, "d2")
	if err := s.CreateEdge(ctx, "edge-1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEdge(ctx, "edge-1", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup edge: %v", err)
	}
	if err := s.CreateEdge(ctx, "edge-2", ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.ReportEdgeSessions(ctx, "edge-1", []string{"d1", "ghost"}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	has := func(edge, dev string) bool {
		ok, err := s.EdgeHasSession(ctx, edge, dev, now.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !has("edge-1", "d1") || has("edge-1", "d2") || has("edge-2", "d1") || has("edge-1", "ghost") {
		t.Fatal("session scoping")
	}
	// A later report without d1 keeps it only within the keep window.
	if err := s.ReportEdgeSessions(ctx, "edge-1", []string{"d2"}, now.Add(2*time.Minute), time.Minute); err != nil {
		t.Fatal(err)
	}
	if has("edge-1", "d1") {
		t.Fatal("stale session kept")
	}
	if err := s.RevokeEdge(ctx, "edge-1"); err != nil {
		t.Fatal(err)
	}
	if e, err := s.GetEdge(ctx, "edge-1"); err != nil || !e.Revoked {
		t.Fatalf("revoked edge %+v %v", e, err)
	}
	if ok, _ := s.EdgeHasSession(ctx, "edge-1", "d2", time.Time{}); ok {
		t.Fatal("revoked edge kept sessions")
	}
	if err := s.RevokeEdge(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	if es, _ := s.ListEdges(ctx); len(es) != 2 || es[0].ID != "edge-1" {
		t.Fatalf("edges %+v", es)
	}
}

func TestDeleteFlowsBefore(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	now := time.Now()
	recs := []api.FlowRecord{{Start: now.Add(-8 * 24 * time.Hour), DeviceID: "d1"}, {Start: now, DeviceID: "d1"}}
	if err := s.InsertFlows(ctx, "acme", recs); err != nil {
		t.Fatal(err)
	}
	n, err := s.DeleteFlowsBefore(ctx, now.Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("deleted %d %v", n, err)
	}
	if got, _ := s.ListFlows(ctx, "acme", 10); len(got) != 1 {
		t.Fatalf("left %d", len(got))
	}
}
