package mobile

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

func boolPtr(b bool) *bool {
	return &b
}

func TestSetPostureValidation(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
		check       func(t *testing.T, p *api.Posture)
	}{
		{
			name:  "valid full posture",
			input: `{"os":"linux","osVersion":"6.12.0","clientVersion":"1.0.0","diskEncrypted":true,"screenLock":true,"firewall":false,"managed":true,"bootTime":"2026-01-01T00:00:00Z"}`,
			check: func(t *testing.T, p *api.Posture) {
				if p.OS != "linux" || p.OSVersion != "6.12.0" || p.ClientVersion != "1.0.0" {
					t.Fatalf("unexpected strings: %+v", p)
				}
				if p.DiskEncrypted == nil || !*p.DiskEncrypted {
					t.Fatalf("expected DiskEncrypted true, got %v", p.DiskEncrypted)
				}
				if p.ScreenLock == nil || !*p.ScreenLock {
					t.Fatalf("expected ScreenLock true, got %v", p.ScreenLock)
				}
				if p.Firewall == nil || *p.Firewall {
					t.Fatalf("expected Firewall false, got %v", p.Firewall)
				}
				if p.Managed == nil || !*p.Managed {
					t.Fatalf("expected Managed true, got %v", p.Managed)
				}
				if p.CollectedAt.IsZero() || p.CollectedAt.Location() != time.UTC {
					t.Fatalf("expected non-zero UTC CollectedAt, got %v", p.CollectedAt)
				}
			},
		},
		{
			name:  "valid partial defaults client version",
			input: `{"os":"linux","osVersion":"6.12.0"}`,
			check: func(t *testing.T, p *api.Posture) {
				if p.ClientVersion != defaultClientVersion() {
					t.Fatalf("expected clientVersion %q, got %q", defaultClientVersion(), p.ClientVersion)
				}
				if p.CollectedAt.IsZero() {
					t.Fatal("expected non-zero CollectedAt")
				}
				if p.DiskEncrypted != nil || p.ScreenLock != nil || p.Firewall != nil || p.Managed != nil {
					t.Fatalf("expected nil pointers, got %+v", p)
				}
			},
		},
		{
			name: "valid 64 byte string fields",
			input: `{"os":"` + strings.Repeat("o", 64) + `",` +
				`"osVersion":"` + strings.Repeat("v", 64) + `",` +
				`"clientVersion":"` + strings.Repeat("c", 64) + `"}`,
			check: func(t *testing.T, p *api.Posture) {
				if len(p.OS) != 64 || len(p.OSVersion) != 64 || len(p.ClientVersion) != 64 {
					t.Fatalf("expected 64 byte strings, got %+v", p)
				}
			},
		},
		{
			name:        "invalid empty string",
			input:       "",
			wantErr:     true,
			errContains: "invalid JSON",
		},
		{
			name:        "invalid malformed json",
			input:       `{"os": "linux"`,
			wantErr:     true,
			errContains: "invalid JSON",
		},
		{
			name:        "invalid non object json",
			input:       `["linux"]`,
			wantErr:     true,
			errContains: "invalid JSON",
		},
		{
			name:        "invalid field type",
			input:       `{"os": 123}`,
			wantErr:     true,
			errContains: "invalid JSON",
		},
		{
			name:        "invalid os longer than 64 bytes",
			input:       `{"os":"` + strings.Repeat("x", 65) + `","osVersion":"1.0"}`,
			wantErr:     true,
			errContains: "string field longer than 64 bytes",
		},
		{
			name:        "invalid osVersion longer than 64 bytes",
			input:       `{"os":"linux","osVersion":"` + strings.Repeat("y", 65) + `"}`,
			wantErr:     true,
			errContains: "string field longer than 64 bytes",
		},
		{
			name:        "invalid clientVersion longer than 64 bytes",
			input:       `{"os":"linux","osVersion":"1.0","clientVersion":"` + strings.Repeat("z", 65) + `"}`,
			wantErr:     true,
			errContains: "string field longer than 64 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.SetPosture(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			p := e.getPosture()
			if p == nil {
				t.Fatal("stored posture is nil")
			}
			if tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

func TestSetPostureChangeDetection(t *testing.T) {
	tests := []struct {
		name       string
		prev       *api.Posture
		next       *api.Posture
		wantDiffer bool
	}{
		{
			name:       "nil prev differs from non-nil next",
			prev:       nil,
			next:       &api.Posture{OS: "linux"},
			wantDiffer: true,
		},
		{
			name:       "both nil does not differ",
			prev:       nil,
			next:       nil,
			wantDiffer: false,
		},
		{
			name: "identical posture does not differ",
			prev: &api.Posture{
				OS:            "linux",
				OSVersion:     "6.1.0",
				ClientVersion: "1.0.0",
				DiskEncrypted: boolPtr(true),
				ScreenLock:    boolPtr(false),
				Firewall:      boolPtr(true),
				Managed:       boolPtr(false),
				BootTime:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				CollectedAt:   time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
			},
			next: &api.Posture{
				OS:            "linux",
				OSVersion:     "6.1.0",
				ClientVersion: "1.0.0",
				DiskEncrypted: boolPtr(true),
				ScreenLock:    boolPtr(false),
				Firewall:      boolPtr(true),
				Managed:       boolPtr(false),
				BootTime:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				CollectedAt:   time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC), // different CollectedAt
			},
			wantDiffer: false,
		},
		{
			name:       "different OS differs",
			prev:       &api.Posture{OS: "linux", OSVersion: "1.0"},
			next:       &api.Posture{OS: "windows", OSVersion: "1.0"},
			wantDiffer: true,
		},
		{
			name:       "different OSVersion differs",
			prev:       &api.Posture{OS: "linux", OSVersion: "1.0"},
			next:       &api.Posture{OS: "linux", OSVersion: "2.0"},
			wantDiffer: true,
		},
		{
			name:       "different ClientVersion differs",
			prev:       &api.Posture{OS: "linux", ClientVersion: "1.0"},
			next:       &api.Posture{OS: "linux", ClientVersion: "1.1"},
			wantDiffer: true,
		},
		{
			name:       "different DiskEncrypted differs",
			prev:       &api.Posture{OS: "linux", DiskEncrypted: boolPtr(true)},
			next:       &api.Posture{OS: "linux", DiskEncrypted: boolPtr(false)},
			wantDiffer: true,
		},
		{
			name:       "DiskEncrypted set to nil differs",
			prev:       &api.Posture{OS: "linux", DiskEncrypted: boolPtr(true)},
			next:       &api.Posture{OS: "linux", DiskEncrypted: nil},
			wantDiffer: true,
		},
		{
			name:       "different ScreenLock differs",
			prev:       &api.Posture{OS: "linux", ScreenLock: nil},
			next:       &api.Posture{OS: "linux", ScreenLock: boolPtr(true)},
			wantDiffer: true,
		},
		{
			name:       "different Firewall differs",
			prev:       &api.Posture{OS: "linux", Firewall: boolPtr(false)},
			next:       &api.Posture{OS: "linux", Firewall: boolPtr(true)},
			wantDiffer: true,
		},
		{
			name:       "different Managed differs",
			prev:       &api.Posture{OS: "linux", Managed: nil},
			next:       &api.Posture{OS: "linux", Managed: boolPtr(true)},
			wantDiffer: true,
		},
		{
			name:       "different BootTime differs",
			prev:       &api.Posture{OS: "linux", BootTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
			next:       &api.Posture{OS: "linux", BootTime: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			wantDiffer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := postureEqual(tt.prev, tt.next)
			gotDiffer := !equal
			if gotDiffer != tt.wantDiffer {
				t.Fatalf("gotDiffer = %v, wantDiffer = %v", gotDiffer, tt.wantDiffer)
			}
		})
	}
}

func TestPostureLoop_AtStart(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	e.postureInterval = 50 * time.Millisecond
	e.postureDelay = 10 * time.Millisecond

	if err := e.SetPosture(`{"os":"linux","osVersion":"6.12.0","diskEncrypted":true}`); err != nil {
		t.Fatal(err)
	}

	if err := e.Enroll(fc.cp.URL, "pk-good", "device1"); err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	waitUntil(t, "posture report at start", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.postures) >= 1
	})

	fc.mu.Lock()
	defer fc.mu.Unlock()
	got := fc.postures[0]
	if got.OS != "linux" || got.OSVersion != "6.12.0" {
		t.Fatalf("unexpected posture: %+v", got)
	}
	if got.DiskEncrypted == nil || !*got.DiskEncrypted {
		t.Fatalf("expected diskEncrypted true, got %+v", got)
	}
	if got.ClientVersion != defaultClientVersion() {
		t.Fatalf("expected clientVersion %q, got %q", defaultClientVersion(), got.ClientVersion)
	}
	if got.CollectedAt.IsZero() {
		t.Fatal("expected non-zero collectedAt")
	}
}

func TestPostureLoop_AfterChange(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	e.postureInterval = 10 * time.Minute // long interval so ticker won't fire
	e.postureDelay = 10 * time.Millisecond

	if err := e.SetPosture(`{"os":"linux","osVersion":"6.12.0","diskEncrypted":true}`); err != nil {
		t.Fatal(err)
	}

	if err := e.Enroll(fc.cp.URL, "pk-good", "device1"); err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	// Wait for the start report
	waitUntil(t, "initial posture report", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.postures) >= 1
	})

	// Trigger a change
	if err := e.SetPosture(`{"os":"linux","osVersion":"6.12.0","diskEncrypted":false}`); err != nil {
		t.Fatal(err)
	}

	// Wait for the changed report
	waitUntil(t, "changed posture report", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.postures) >= 2
	})

	fc.mu.Lock()
	rep2 := fc.postures[1]
	fc.mu.Unlock()
	if rep2.DiskEncrypted == nil || *rep2.DiskEncrypted {
		t.Fatalf("expected diskEncrypted false in second report, got %+v", rep2)
	}

	// Setting identical posture should not trigger a new report
	if err := e.SetPosture(`{"os":"linux","osVersion":"6.12.0","diskEncrypted":false}`); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	fc.mu.Lock()
	count := len(fc.postures)
	fc.mu.Unlock()
	if count != 2 {
		t.Fatalf("expected exactly 2 reports, got %d", count)
	}
}

func TestPostureLoop_SkipWhenUnset(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	e.postureInterval = 10 * time.Minute
	e.postureDelay = 10 * time.Millisecond

	// Do not set posture before Start
	if err := e.Enroll(fc.cp.URL, "pk-good", "device1"); err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	time.Sleep(30 * time.Millisecond)
	fc.mu.Lock()
	count := len(fc.postures)
	fc.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected 0 reports when posture was unset, got %d", count)
	}

	// Now set posture; change detection signals the loop
	if err := e.SetPosture(`{"os":"linux","osVersion":"6.12.0"}`); err != nil {
		t.Fatal(err)
	}

	waitUntil(t, "posture report after initial set", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.postures) >= 1
	})
}

func TestEnrollSendsPosture(t *testing.T) {
	t.Run("with posture set", func(t *testing.T) {
		fc := newFakeCloud(t)
		e, _ := newTestEngine(t, fc)

		if err := e.SetPosture(`{"os":"linux","osVersion":"6.12.0","clientVersion":"2.3.4","diskEncrypted":true}`); err != nil {
			t.Fatal(err)
		}

		if err := e.Enroll(fc.cp.URL, "pk-good", "device1"); err != nil {
			t.Fatal(err)
		}

		fc.mu.Lock()
		defer fc.mu.Unlock()
		if fc.lastEnrollReq == nil || fc.lastEnrollReq.Posture == nil {
			t.Fatalf("expected enroll request to contain posture, got %+v", fc.lastEnrollReq)
		}
		p := fc.lastEnrollReq.Posture
		if p.OS != "linux" || p.OSVersion != "6.12.0" || p.ClientVersion != "2.3.4" {
			t.Fatalf("unexpected posture in enroll request: %+v", p)
		}
		if p.DiskEncrypted == nil || !*p.DiskEncrypted {
			t.Fatalf("expected diskEncrypted true, got %+v", p)
		}
	})

	t.Run("without posture set", func(t *testing.T) {
		fc := newFakeCloud(t)
		e, _ := newTestEngine(t, fc)

		if err := e.Enroll(fc.cp.URL, "pk-good", "device1"); err != nil {
			t.Fatal(err)
		}

		fc.mu.Lock()
		defer fc.mu.Unlock()
		if fc.lastEnrollReq == nil {
			t.Fatal("expected enroll request")
		}
		if fc.lastEnrollReq.Posture != nil {
			t.Fatalf("expected nil posture in enroll request, got %+v", fc.lastEnrollReq.Posture)
		}
	})
}

func TestPostureFailingAndStatus(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)

	// No snapshot yet
	if got := e.PostureFailing(); got != "[]" {
		t.Fatalf("expected %q, got %q", "[]", got)
	}

	// Status without snapshot
	var st statusJSON
	if err := json.Unmarshal([]byte(e.Status()), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.PostureFailing) != 0 {
		t.Fatalf("expected empty postureFailing in status, got %+v", st.PostureFailing)
	}

	// Enroll and install a snapshot with no failing posture checks
	if err := e.Enroll(fc.cp.URL, "pk-good", "device1"); err != nil {
		t.Fatal(err)
	}

	if got := e.PostureFailing(); got != "[]" {
		t.Fatalf("expected %q, got %q", "[]", got)
	}

	// Update snapshot with failing posture checks
	fc.mu.Lock()
	fc.snap = &policy.Snapshot{
		SchemaVersion:  1,
		Version:        2,
		TenantID:       testTenant,
		DeviceID:       testDevice,
		IssuedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
		PostureFailing: []string{"diskEncryption", "screenLock"},
		Firewall: policy.FirewallPolicy{
			DefaultAction: policy.ActionAllow,
		},
		DNS: policy.DNSPolicy{BlockResponse: "nxdomain"},
	}
	fc.updated = make(chan struct{})
	fc.mu.Unlock()

	id := e.en.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.pollSnapshot(ctx, id, 0); err != nil {
		t.Fatal(err)
	}

	// PostureFailing should now return JSON array of failing checks
	got := e.PostureFailing()
	var failing []string
	if err := json.Unmarshal([]byte(got), &failing); err != nil {
		t.Fatalf("failed to unmarshal PostureFailing result: %v", err)
	}
	if len(failing) != 2 || failing[0] != "diskEncryption" || failing[1] != "screenLock" {
		t.Fatalf("unexpected failing checks: %+v", failing)
	}

	// Status should now include postureFailing
	if err := json.Unmarshal([]byte(e.Status()), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.PostureFailing) != 2 || st.PostureFailing[0] != "diskEncryption" || st.PostureFailing[1] != "screenLock" {
		t.Fatalf("unexpected postureFailing in status: %+v", st.PostureFailing)
	}
	if !strings.Contains(e.Status(), `"postureFailing":["diskEncryption","screenLock"]`) {
		t.Fatalf("expected status string to contain postureFailing: %s", e.Status())
	}
}
