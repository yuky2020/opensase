package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store/storetest"
)

// open returns an empty store. With OPENSASE_TEST_POSTGRES set to a PostgreSQL URL, every
// test runs on PostgreSQL in its own schema (ADR-0033); otherwise on a SQLite file.
func open(t *testing.T) *Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "cp.db")
	if pg := os.Getenv("OPENSASE_TEST_POSTGRES"); pg != "" {
		dsn = testSchema(t, pg)
	}
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// testSchema returns a URL for a fresh PostgreSQL schema.
func testSchema(t *testing.T, _ string) string {
	t.Helper()
	dsn, ok := storetest.PostgresDSN(t)
	if !ok {
		t.Skip("OPENSASE_TEST_POSTGRES not set")
	}
	return dsn
}

func seed(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, Tenant{ID: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{ID: "u1", TenantID: "acme", Email: "a@acme", Name: "A"}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cp.db")
	for range 2 {
		s, err := Open(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
}

func TestTenantsAndUsers(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	if err := s.CreateTenant(ctx, Tenant{ID: "acme", Name: "dup"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup tenant: %v", err)
	}
	if err := s.CreateUser(ctx, User{ID: "u2", TenantID: "nope", Email: "x", Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user in missing tenant: %v", err)
	}
	if _, err := s.GetUser(ctx, "other", "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant user lookup: %v", err)
	}
	if tn, err := s.GetTenant(ctx, "acme"); err != nil || tn.Name != "Acme" {
		t.Fatalf("GetTenant %+v %v", tn, err)
	}
}

func TestEnrollConsumesKey(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	now := time.Now()
	h := func(k string) []byte { x := sha256.Sum256([]byte(k)); return x[:] }
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h("single"), TenantID: "acme", UserID: "u1", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h("multi"), TenantID: "acme", UserID: "u1", MaxUses: 3, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h("old"), TenantID: "acme", UserID: "u1", ExpiresAt: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h("x"), TenantID: "acme", UserID: "ghost", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key for unknown user: %v", err)
	}
	n := 0
	mk := func(e Enrollment) (Device, error) {
		n++
		return Device{ID: "d" + string(rune('0'+n)), Name: "phone", Platform: "android", CertSerial: "1"}, nil
	}
	tests := []struct {
		key  string
		want error
	}{
		{"single", nil},
		{"single", ErrKeyInvalid},
		{"old", ErrKeyInvalid},
		{"unknown", ErrKeyInvalid},
		{"multi", nil},
		{"multi", nil},
		{"multi", nil},
		{"multi", ErrKeyInvalid},
	}
	for i, tc := range tests {
		d, err := s.Enroll(ctx, h(tc.key), now, mk)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%d %s: err=%v want %v", i, tc.key, err, tc.want)
		}
		if err == nil && (d.TenantID != "acme" || d.UserID != "u1") {
			t.Fatalf("device %+v", d)
		}
	}
	// A failing mkDevice does not consume the key.
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h("retry"), TenantID: "acme", UserID: "u1", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, h("retry"), now, func(Enrollment) (Device, error) { return Device{}, errors.New("boom") }); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.Enroll(ctx, h("retry"), now, mk); err != nil {
		t.Fatalf("key consumed by failed enrollment: %v", err)
	}
	devs, err := s.ListDevices(ctx, DeviceFilter{TenantID: "acme", UserID: "u1"})
	if err != nil || len(devs) != 5 {
		t.Fatalf("devices %d %v", len(devs), err)
	}
	if err := s.RevokeDevice(ctx, "acme", devs[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, "other", devs[1].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	devs, _ = s.ListDevices(ctx, DeviceFilter{TenantID: "acme"})
	if len(devs) != 4 {
		t.Fatalf("after revoke %d", len(devs))
	}
	all, _ := s.ListDevices(ctx, DeviceFilter{IncludeRevoked: true})
	if len(all) != 5 {
		t.Fatalf("with revoked %d", len(all))
	}
}

func TestPoliciesAndSnapshots(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	if _, err := s.GetTenantPolicy(ctx, "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing policy: %v", err)
	}
	tp := api.TenantPolicy{DefaultAction: policy.ActionAllow, AllowUserRules: true, Rules: []policy.Rule{{ID: "r1", Action: policy.ActionBlock}}}
	if err := s.PutTenantPolicy(ctx, "acme", tp); err != nil {
		t.Fatal(err)
	}
	tp.Lockdown = true
	if err := s.PutTenantPolicy(ctx, "acme", tp); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTenantPolicy(ctx, "acme")
	if err != nil || !got.Lockdown || got.Rules[0].ID != "r1" {
		t.Fatalf("policy %+v %v", got, err)
	}
	ur := api.UserRules{Apps: map[string]policy.AppPolicy{"com.x": {WiFi: policy.ActionBlock}}}
	if err := s.PutUserRules(ctx, "acme", "u1", ur); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUserRules(ctx, "other", "u1", ur); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant user rules: %v", err)
	}
	if r, err := s.GetUserRules(ctx, "acme", "u1"); err != nil || r.Apps["com.x"].WiFi != policy.ActionBlock {
		t.Fatalf("rules %+v %v", r, err)
	}

	h := sha256.Sum256([]byte("k"))
	_ = s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h[:], TenantID: "acme", UserID: "u1", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)})
	for _, id := range []string{"d1", "d2"} {
		if _, err := s.Enroll(ctx, h[:], time.Now(), func(Enrollment) (Device, error) { return Device{ID: id, Name: id, Platform: "linux"}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	// Concurrent saves still yield unique, increasing versions.
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[uint64]bool{}
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dev := []string{"d1", "d2"}[i%2]
			rec, err := s.SaveSnapshot(ctx, dev, time.Now(), time.Now().Add(time.Hour), func(v uint64) ([]byte, error) {
				return []byte(`{"v":1}`), nil
			})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			if seen[rec.Version] {
				t.Errorf("duplicate version %d", rec.Version)
			}
			seen[rec.Version] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	last, err := s.LatestSnapshot(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSnapshot(ctx, "d1", time.Now(), time.Now(), func(uint64) ([]byte, error) { return nil, errors.New("sign failed") }); err == nil {
		t.Fatal("expected error")
	}
	next, err := s.SaveSnapshot(ctx, "d1", time.Now(), time.Now(), func(uint64) ([]byte, error) { return []byte("x"), nil })
	if err != nil || next.Version <= last.Version {
		t.Fatalf("version did not increase: %d -> %d (%v)", last.Version, next.Version, err)
	}
	if err := s.RevokeDevice(ctx, "acme", "d2"); err != nil {
		t.Fatal(err)
	}
	act, err := s.ActiveSnapshots(ctx)
	if err != nil || len(act) != 1 || act[0].Device.ID != "d1" || act[0].Snapshot.Version != next.Version {
		t.Fatalf("active %+v %v", act, err)
	}
	if err := s.PruneSnapshots(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.LatestSnapshot(ctx, "d1"); l.Version != next.Version {
		t.Fatal("prune removed latest")
	}
}

func TestFlows(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	recs := []api.FlowRecord{
		{Start: time.Now(), Where: "edge", DeviceID: "d1", Flow: policy.Flow{Protocol: "tcp", DstIP: "1.1.1.1", DstPort: 443}},
		{Start: time.Now(), Where: "device", DeviceID: "d1", Flow: policy.Flow{Protocol: "tcp", DstIP: "1.1.1.1", DstPort: 25}},
	}
	if err := s.InsertFlows(ctx, "acme", recs); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertFlows(ctx, "ghost", recs); err == nil {
		t.Fatal("flows for unknown tenant accepted")
	}
	got, err := s.ListFlows(ctx, "acme", 1)
	if err != nil || len(got) != 1 || got[0].Flow.DstPort != 25 {
		t.Fatalf("flows %+v %v", got, err)
	}
	if got, _ := s.ListFlows(ctx, "other", 10); len(got) != 0 {
		t.Fatal("cross-tenant flows")
	}
}

func TestExperience(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	now := time.Now().UTC().Truncate(time.Second)

	dev1Samples := []api.ExperienceSample{
		{At: now.Add(-2 * time.Hour), EdgeID: "e1", RTTms: 25.5, LossPct: 0.0, DNSms: 12.0, Network: "wifi"},
		{At: now.Add(-1 * time.Hour), EdgeID: "e1", RTTms: 30.0, LossPct: 10.0, DNSms: 15.5, Network: "cellular"},
		{At: now, EdgeID: "e2", RTTms: 45.0, LossPct: 20.0, DNSms: 0.0, Network: ""},
	}
	dev2Samples := []api.ExperienceSample{
		{At: now, EdgeID: "e1", RTTms: 10.0, LossPct: 0.0, DNSms: 5.0, Network: "ethernet"},
	}

	if err := s.InsertExperience(ctx, "acme", "dev-1", dev1Samples); err != nil {
		t.Fatalf("insert dev-1 experience: %v", err)
	}
	if err := s.InsertExperience(ctx, "acme", "dev-2", dev2Samples); err != nil {
		t.Fatalf("insert dev-2 experience: %v", err)
	}
	if err := s.InsertExperience(ctx, "ghost", "dev-1", dev1Samples); err == nil {
		t.Fatal("experience for unknown tenant accepted")
	}

	tests := []struct {
		name      string
		tenant    string
		since     time.Time
		deviceID  string
		wantCount int
	}{
		{"all devices all time", "acme", now.Add(-3 * time.Hour), "", 4},
		{"all devices since 90m ago", "acme", now.Add(-90 * time.Minute), "", 3},
		{"dev-1 only", "acme", now.Add(-3 * time.Hour), "dev-1", 3},
		{"dev-2 only", "acme", now.Add(-3 * time.Hour), "dev-2", 1},
		{"unknown device", "acme", now.Add(-3 * time.Hour), "dev-ghost", 0},
		{"cross-tenant query", "other", now.Add(-3 * time.Hour), "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ExperienceSince(ctx, tc.tenant, tc.since, tc.deviceID)
			if err != nil {
				t.Fatalf("ExperienceSince failed: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Fatalf("got %d rows, want %d", len(got), tc.wantCount)
			}
			for _, r := range got {
				if tc.deviceID != "" && r.DeviceID != tc.deviceID {
					t.Errorf("got device %q, want %q", r.DeviceID, tc.deviceID)
				}
				if r.At.Before(tc.since) {
					t.Errorf("got sample at %v before since %v", r.At, tc.since)
				}
			}
		})
	}

	// Retention: delete samples older than 90 minutes ago (should delete dev1Samples[0]).
	deleted, err := s.DeleteExperienceBefore(ctx, now.Add(-90*time.Minute))
	if err != nil {
		t.Fatalf("DeleteExperienceBefore failed: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d rows, want 1", deleted)
	}
	remaining, err := s.ExperienceSince(ctx, "acme", now.Add(-3*time.Hour), "")
	if err != nil {
		t.Fatalf("ExperienceSince after retention: %v", err)
	}
	if len(remaining) != 3 {
		t.Fatalf("remaining %d rows, want 3", len(remaining))
	}
}

// TestUpdateTenantPolicyConditional covers issue #66: the update sees the stored policy, an
// error aborts the write, and a write bumps the version.
func TestUpdateTenantPolicyConditional(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, Tenant{ID: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	first := api.TenantPolicy{Categories: []string{"malware"}}
	if _, err := s.UpdateTenantPolicy(ctx, "acme", func(_ api.TenantPolicy, exists bool) (api.TenantPolicy, error) {
		if exists {
			t.Fatal("exists before the first write")
		}
		return first, nil
	}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	_, err := s.UpdateTenantPolicy(ctx, "acme", func(cur api.TenantPolicy, exists bool) (api.TenantPolicy, error) {
		if !exists || len(cur.Categories) != 1 || cur.Categories[0] != "malware" {
			t.Fatalf("cur %+v exists %v", cur, exists)
		}
		return api.TenantPolicy{}, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if v, _ := s.TenantPolicyVersion(ctx, "acme"); v != 1 {
		t.Fatalf("version after aborted write: %d", v)
	}
	if _, err := s.UpdateTenantPolicy(ctx, "acme", func(api.TenantPolicy, bool) (api.TenantPolicy, error) { return api.TenantPolicy{}, nil }); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.TenantPolicyVersion(ctx, "acme"); v != 2 {
		t.Fatalf("version: %d", v)
	}
}

// TestTunnelOffsets covers issue #70: every device gets a distinct, growing tunnel offset,
// and devices from before migration 0015 get one at start.
func TestTunnelOffsets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cp.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s)
	h := sha256.Sum256([]byte("k"))
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h[:], TenantID: "acme", UserID: "u1", MaxUses: 3, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var offs []uint32
	for _, id := range []string{"a", "b"} {
		d, err := s.Enroll(ctx, h[:], time.Now(), func(Enrollment) (Device, error) {
			return Device{ID: id, Name: id, Platform: "linux", CertSerial: "1"}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetDevice(ctx, id)
		if got.TunnelOffset != d.TunnelOffset {
			t.Fatalf("stored %d returned %d", got.TunnelOffset, d.TunnelOffset)
		}
		offs = append(offs, d.TunnelOffset)
	}
	if offs[0] != 2 || offs[1] != 3 {
		t.Fatalf("offsets %v", offs)
	}
	// A device without an offset (enrolled before the migration) gets the next one at start.
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET tunnel_offset = 0 WHERE id = 'a'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if a, _ := s.GetDevice(ctx, "a"); a.TunnelOffset != 4 {
		t.Fatalf("backfilled offset %d", a.TunnelOffset)
	}
}
