package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

func createConnector(t *testing.T, s *Store, id, group string, exp time.Time) []byte {
	t.Helper()
	h := sha256.Sum256([]byte("ckey-" + id))
	if _, err := s.CreateConnector(context.Background(), Connector{ID: id, TenantID: "acme", Name: "dc " + id, Group: group}, h[:], exp); err != nil {
		t.Fatal(err)
	}
	return h[:]
}

func TestConnectorLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	now := time.Now()
	k1 := createConnector(t, s, "c1", "dc1", now.Add(24*time.Hour))
	k2 := createConnector(t, s, "c2", "dc2", now.Add(24*time.Hour))
	kExp := createConnector(t, s, "c3", "dc1", now.Add(-time.Second))

	h := sha256.Sum256([]byte("x"))
	if _, err := s.CreateConnector(ctx, Connector{ID: "c1", TenantID: "acme", Name: "dup", Group: "g"}, h[:], now); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup connector: %v", err)
	}
	if _, err := s.CreateConnector(ctx, Connector{ID: "c9", TenantID: "nope", Name: "x", Group: "g"}, h[:], now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant: %v", err)
	}

	sign := func(serial string) func(Connector) (string, error) {
		return func(Connector) (string, error) { return serial, nil }
	}
	// A failing signer does not consume the key.
	if _, err := s.EnrollConnector(ctx, k1, now, func(Connector) (string, error) { return "", errors.New("boom") }); err == nil {
		t.Fatal("signer error swallowed")
	}
	c, err := s.EnrollConnector(ctx, k1, now, sign("100"))
	if err != nil || c.ID != "c1" || c.Group != "dc1" || c.TenantID != "acme" || c.CertSerial != "100" {
		t.Fatalf("enroll %+v %v", c, err)
	}
	if _, err := s.EnrollConnector(ctx, k1, now, sign("101")); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("reused key: %v", err)
	}
	if _, err := s.EnrollConnector(ctx, kExp, now, sign("102")); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("expired key: %v", err)
	}

	// Enrolled-only listing; revocation deletes the unused key of c2.
	if l, _ := s.ListConnectors(ctx, ConnectorFilter{EnrolledOnly: true}); len(l) != 1 || l[0].ID != "c1" {
		t.Fatalf("enrolled %+v", l)
	}
	if err := s.RevokeConnector(ctx, "acme", "c2"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeConnector(ctx, "other", "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if _, err := s.EnrollConnector(ctx, k2, now, sign("103")); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("key of revoked connector: %v", err)
	}
	if l, _ := s.ListConnectors(ctx, ConnectorFilter{TenantID: "acme"}); len(l) != 2 {
		t.Fatalf("non-revoked %+v", l)
	}
	if l, _ := s.ListConnectors(ctx, ConnectorFilter{TenantID: "acme", IncludeRevoked: true}); len(l) != 3 || !l[1].Revoked {
		t.Fatalf("all %+v", l)
	}

	// Renewal mirrors devices.
	tests := []struct {
		name          string
		id, old, new  string
		want          error
		cur, wantPrev string
	}{
		{"renew", "c1", "100", "200", nil, "200", "100"},
		{"retry with previous", "c1", "100", "201", nil, "201", "100"},
		{"stale", "c1", "200", "202", ErrConflict, "201", "100"},
		{"renew with delivered", "c1", "201", "203", nil, "203", "201"},
		{"not enrolled", "c3", "", "1", ErrConflict, "", ""},
		{"revoked", "c2", "x", "1", ErrRevoked, "", ""},
		{"unknown", "nope", "1", "2", ErrNotFound, "", ""},
	}
	for _, tc := range tests {
		if err := s.RenewConnectorCert(ctx, tc.id, tc.old, tc.new); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v want %v", tc.name, err, tc.want)
		}
		if tc.cur != "" {
			if c, _ := s.GetConnector(ctx, tc.id); c.CertSerial != tc.cur || c.PrevCertSerial != tc.wantPrev {
				t.Errorf("%s: serial %q prev %q", tc.name, c.CertSerial, c.PrevCertSerial)
			}
		}
	}

	// last_seen.
	seen := time.Unix(now.Unix(), 0)
	if err := s.TouchConnectors(ctx, "", []string{"c1", "c2", "ghost"}, seen); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetConnector(ctx, "c1"); !c.LastSeen.Equal(seen) {
		t.Fatalf("last seen %v", c.LastSeen)
	}
	if c, _ := s.GetConnector(ctx, "c2"); !c.LastSeen.IsZero() {
		t.Fatalf("revoked connector touched: %v", c.LastSeen)
	}
}

func TestConnectorConfigVersion(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	createConnector(t, s, "c1", "g", time.Now().Add(time.Hour))
	steps := []struct {
		hash string
		want uint64
	}{{"a", 1}, {"a", 1}, {"b", 2}, {"a", 3}, {"a", 3}}
	for i, st := range steps {
		h := sha256.Sum256([]byte(st.hash))
		if v, err := s.ConnectorConfigVersion(ctx, "c1", h[:]); err != nil || v != st.want {
			t.Fatalf("step %d: %d %v want %d", i, v, err, st.want)
		}
	}
	if _, err := s.ConnectorConfigVersion(ctx, "nope", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestTenantPolicyVersionAndLists(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	if v, err := s.TenantPolicyVersion(ctx, "acme"); err != nil || v != 0 {
		t.Fatalf("no policy: %d %v", v, err)
	}
	for want := uint64(1); want <= 3; want++ {
		if err := s.PutTenantPolicy(ctx, "acme", api.TenantPolicy{}); err != nil {
			t.Fatal(err)
		}
		if v, _ := s.TenantPolicyVersion(ctx, "acme"); v != want {
			t.Fatalf("version %d want %d", v, want)
		}
	}
	// PrivateApps round-trip through the policy JSON.
	tp := api.TenantPolicy{PrivateApps: []api.TenantPrivateApp{{Users: []string{"u1"}}}}
	tp.PrivateApps[0].ID = "app"
	tp.PrivateApps[0].ConnectorGroup = "g"
	if err := s.PutTenantPolicy(ctx, "acme", tp); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetTenantPolicy(ctx, "acme"); len(got.PrivateApps) != 1 || got.PrivateApps[0].ID != "app" || got.PrivateApps[0].Users[0] != "u1" {
		t.Fatalf("private apps %+v", got.PrivateApps)
	}

	if err := s.CreateTenant(ctx, Tenant{ID: "beta", Name: "Beta"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{ID: "u0", TenantID: "acme", Email: "0@acme", Name: "Z"}); err != nil {
		t.Fatal(err)
	}
	if ts, err := s.ListTenants(ctx); err != nil || len(ts) != 2 || ts[0].ID != "acme" || ts[1].ID != "beta" {
		t.Fatalf("tenants %+v %v", ts, err)
	}
	if us, err := s.ListUsers(ctx, "acme"); err != nil || len(us) != 2 || us[0].ID != "u0" {
		t.Fatalf("users %+v %v", us, err)
	}
	if us, err := s.ListUsers(ctx, "beta"); err != nil || len(us) != 0 {
		t.Fatalf("beta users %+v %v", us, err)
	}
}
