package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func createTestDevice(t *testing.T, s *Store, tenantID, userID, deviceID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	h := func(k string) []byte { x := sha256.Sum256([]byte(k)); return x[:] }
	if err := s.CreateProvisioningKey(ctx, ProvisioningKey{Hash: h(deviceID), TenantID: tenantID, UserID: userID, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Enroll(ctx, h(deviceID), now, func(Enrollment) (Device, error) {
		return Device{ID: deviceID, Name: "gw-" + deviceID, Platform: "linux", CertSerial: "1"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeviceRoutesValidation(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	createTestDevice(t, s, "acme", "u1", "d1")

	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"10.0.0.0/8 too broad", "10.0.0.0/8", true},
		{"10.0.0.0/15 too broad", "10.0.0.0/15", true},
		{"10.0.0.0/16 valid", "10.0.0.0/16", false},
		{"10.30.0.0/24 valid", "10.30.0.0/24", false},
		{"10.30.0.1/32 valid", "10.30.0.1/32", false},
		{"172.16.0.0/12 too broad", "172.16.0.0/12", true},
		{"172.16.0.0/16 valid", "172.16.0.0/16", false},
		{"172.31.255.0/24 valid", "172.31.255.0/24", false},
		{"172.32.0.0/16 not private", "172.32.0.0/16", true},
		{"192.168.0.0/15 too broad", "192.168.0.0/15", true},
		{"192.168.0.0/16 valid", "192.168.0.0/16", false},
		{"192.168.1.0/24 valid", "192.168.1.0/24", false},
		{"100.64.0.0/10 cgnat forbidden", "100.64.0.0/10", true},
		{"100.64.1.0/24 cgnat forbidden", "100.64.1.0/24", true},
		{"public 8.8.8.0/24 forbidden", "8.8.8.0/24", true},
		{"public 1.1.1.0/24 forbidden", "1.1.1.0/24", true},
		{"ipv6 fd00::/64 forbidden", "fd00::/64", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := netip.ParsePrefix(tc.cidr)
			if err != nil && !tc.wantErr {
				t.Fatalf("parse prefix %s: %v", tc.cidr, err)
			}
			var cidrs []netip.Prefix
			if err == nil {
				cidrs = []netip.Prefix{p}
			}
			err = s.SetDeviceRoutes(ctx, "acme", "d1", cidrs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SetDeviceRoutes(%q) error = %v, wantErr %v", tc.cidr, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidRoute) {
				t.Fatalf("SetDeviceRoutes(%q) error = %v, want ErrInvalidRoute", tc.cidr, err)
			}
		})
	}
}

func TestDeviceRoutesOverlapAcrossTenants(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	if err := s.CreateTenant(ctx, Tenant{ID: "beta", Name: "Beta"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{ID: "u2", TenantID: "beta", Email: "b@beta", Name: "B"}); err != nil {
		t.Fatal(err)
	}
	createTestDevice(t, s, "acme", "u1", "d1")
	createTestDevice(t, s, "beta", "u2", "d2")

	// Set initial routes for d1 in tenant acme
	d1Routes := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	if err := s.SetDeviceRoutes(ctx, "acme", "d1", d1Routes); err != nil {
		t.Fatalf("set d1 routes: %v", err)
	}

	overlapTests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"exact match across tenants", "10.30.0.0/24", true},
		{"sub-prefix overlap", "10.30.0.0/25", true},
		{"super-prefix overlap", "10.30.0.0/16", true},
		{"another sub-prefix", "10.30.0.128/25", true},
		{"single host inside", "10.30.0.1/32", true},
		{"non-overlapping adjacent", "10.30.1.0/24", false},
		{"different private range", "192.168.1.0/24", false},
	}

	for _, tc := range overlapTests {
		t.Run(tc.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.cidr)
			err := s.SetDeviceRoutes(ctx, "beta", "d2", []netip.Prefix{p})
			if (err != nil) != tc.wantErr {
				t.Fatalf("SetDeviceRoutes(%s) on d2: err = %v, wantErr %v", tc.cidr, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrRouteOverlap) {
				t.Fatalf("SetDeviceRoutes(%s) on d2: err = %v, want ErrRouteOverlap", tc.cidr, err)
			}
		})
	}
}

func TestDeviceRoutesSameDeviceReplace(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	createTestDevice(t, s, "acme", "u1", "d1")

	p1 := netip.MustParsePrefix("10.30.0.0/24")
	p2 := netip.MustParsePrefix("10.31.0.0/24")
	p3 := netip.MustParsePrefix("192.168.10.0/24")

	// Set routes for d1
	if err := s.SetDeviceRoutes(ctx, "acme", "d1", []netip.Prefix{p1, p2}); err != nil {
		t.Fatalf("initial set: %v", err)
	}

	got, err := s.DeviceRoutes(ctx, "d1")
	if err != nil {
		t.Fatalf("DeviceRoutes: %v", err)
	}
	want := []netip.Prefix{p1, p2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeviceRoutes got %v, want %v", got, want)
	}

	// Replacing routes on the same device with same + new route is allowed (no self-overlap)
	if err := s.SetDeviceRoutes(ctx, "acme", "d1", []netip.Prefix{p1, p3}); err != nil {
		t.Fatalf("replace set: %v", err)
	}

	got, err = s.DeviceRoutes(ctx, "d1")
	if err != nil {
		t.Fatalf("DeviceRoutes after replace: %v", err)
	}
	want = []netip.Prefix{p1, p3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeviceRoutes got %v, want %v", got, want)
	}

	// Clearing routes with empty slice
	if err := s.SetDeviceRoutes(ctx, "acme", "d1", []netip.Prefix{}); err != nil {
		t.Fatalf("clear routes: %v", err)
	}
	got, err = s.DeviceRoutes(ctx, "d1")
	if err != nil {
		t.Fatalf("DeviceRoutes after clear: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty routes, got %v", got)
	}
}

func TestDeviceRoutesCrossTenantAndNotFound(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	if err := s.CreateTenant(ctx, Tenant{ID: "beta", Name: "Beta"}); err != nil {
		t.Fatal(err)
	}
	createTestDevice(t, s, "acme", "u1", "d1")

	p := netip.MustParsePrefix("10.30.0.0/24")

	// Device d1 belongs to acme; trying to set from beta must return ErrNotFound
	if err := s.SetDeviceRoutes(ctx, "beta", "d1", []netip.Prefix{p}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant set: got %v, want ErrNotFound", err)
	}

	// Non-existent device must return ErrNotFound
	if err := s.SetDeviceRoutes(ctx, "acme", "ghost", []netip.Prefix{p}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-existent device set: got %v, want ErrNotFound", err)
	}
	if _, err := s.DeviceRoutes(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-existent device get: got %v, want ErrNotFound", err)
	}
}

func TestAllDeviceRoutes(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	seed(t, s)
	if err := s.CreateTenant(ctx, Tenant{ID: "beta", Name: "Beta"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{ID: "u2", TenantID: "beta", Email: "b@beta", Name: "B"}); err != nil {
		t.Fatal(err)
	}
	createTestDevice(t, s, "acme", "u1", "d1")
	createTestDevice(t, s, "beta", "u2", "d2")

	p1 := netip.MustParsePrefix("10.30.0.0/24")
	p2 := netip.MustParsePrefix("10.40.0.0/24")

	_ = s.SetDeviceRoutes(ctx, "acme", "d1", []netip.Prefix{p1})
	_ = s.SetDeviceRoutes(ctx, "beta", "d2", []netip.Prefix{p2})

	all, err := s.AllDeviceRoutes(ctx)
	if err != nil {
		t.Fatalf("AllDeviceRoutes: %v", err)
	}

	if len(all) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(all))
	}
	if !reflect.DeepEqual(all["d1"], []netip.Prefix{p1}) {
		t.Fatalf("d1 routes got %v, want %v", all["d1"], []netip.Prefix{p1})
	}
	if !reflect.DeepEqual(all["d2"], []netip.Prefix{p2}) {
		t.Fatalf("d2 routes got %v, want %v", all["d2"], []netip.Prefix{p2})
	}
}
