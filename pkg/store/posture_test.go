package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/store/storetest"
)

func runOnBothEngines(t *testing.T, fn func(t *testing.T, s *Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		dsn := filepath.Join(t.TempDir(), "cp.db")
		s, err := Open(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		fn(t, s)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn, ok := storetest.PostgresDSN(t)
		if !ok {
			t.Skip("OPENSASE_TEST_POSTGRES not set")
		}
		s, err := Open(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		fn(t, s)
	})
}

func TestDevicePostureStore(t *testing.T) {
	runOnBothEngines(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seed(t, s)

		// Non-existent device posture returns ErrNotFound.
		if _, err := s.DevicePosture(ctx, "d-ghost"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}

		// Enroll a device.
		h := sha256.Sum256([]byte("posture-key"))
		now := time.Now().UTC().Truncate(time.Second)
		if err := s.CreateProvisioningKey(ctx, ProvisioningKey{
			Hash:      h[:],
			TenantID:  "acme",
			UserID:    "u1",
			MaxUses:   1,
			ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		dev, err := s.Enroll(ctx, h[:], now, func(Enrollment) (Device, error) {
			return Device{ID: "d1", Name: "laptop", Platform: "linux", CertSerial: "100"}, nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// Initially no posture.
		if _, err := s.DevicePosture(ctx, dev.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}

		tTrue := true
		p1 := api.Posture{
			OS:            "linux",
			OSVersion:     "6.8.0",
			ClientVersion: "1.0.0",
			DiskEncrypted: &tTrue,
			CollectedAt:   now,
		}
		failing1 := []string{"managed"}

		// Insert posture.
		if err := s.SetDevicePosture(ctx, "acme", dev.ID, p1, failing1, now); err != nil {
			t.Fatalf("SetDevicePosture: %v", err)
		}

		got1, err := s.DevicePosture(ctx, dev.ID)
		if err != nil {
			t.Fatalf("DevicePosture: %v", err)
		}
		if got1.OS != "linux" || got1.OSVersion != "6.8.0" || got1.ClientVersion != "1.0.0" {
			t.Fatalf("posture mismatch: %+v", got1)
		}
		if got1.DiskEncrypted == nil || !*got1.DiskEncrypted {
			t.Fatalf("diskEncrypted mismatch: %+v", got1)
		}
		if !slices.Equal(got1.Failing, failing1) {
			t.Fatalf("failing mismatch: got %v, want %v", got1.Failing, failing1)
		}
		if !got1.ReportedAt.Equal(now) {
			t.Fatalf("reportedAt mismatch: got %v, want %v", got1.ReportedAt, now)
		}

		// Upsert with updated report and empty failing.
		later := now.Add(15 * time.Minute)
		p2 := api.Posture{
			OS:            "linux",
			OSVersion:     "6.8.0",
			ClientVersion: "1.0.1",
			DiskEncrypted: &tTrue,
			Managed:       &tTrue,
			CollectedAt:   later,
		}
		if err := s.SetDevicePosture(ctx, "acme", dev.ID, p2, nil, later); err != nil {
			t.Fatalf("SetDevicePosture upsert: %v", err)
		}

		got2, err := s.DevicePosture(ctx, dev.ID)
		if err != nil {
			t.Fatalf("DevicePosture after upsert: %v", err)
		}
		if got2.ClientVersion != "1.0.1" {
			t.Fatalf("clientVersion not updated: got %s", got2.ClientVersion)
		}
		if len(got2.Failing) != 0 {
			t.Fatalf("expected empty failing, got %v", got2.Failing)
		}
		if !got2.ReportedAt.Equal(later) {
			t.Fatalf("reportedAt not updated: got %v, want %v", got2.ReportedAt, later)
		}
	})
}
