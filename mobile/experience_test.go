package mobile

import (
	"context"
	"math"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/yuky2020/opensase/pkg/api"
)

func TestMedianMs(t *testing.T) {
	tests := []struct {
		name string
		ds   []time.Duration
		want float64
	}{
		{name: "empty", ds: nil, want: 0},
		{name: "empty slice", ds: []time.Duration{}, want: 0},
		{name: "single", ds: []time.Duration{10 * time.Millisecond}, want: 10.0},
		{name: "two elements", ds: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}, want: 15.0},
		{name: "three elements unsorted", ds: []time.Duration{30 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}, want: 20.0},
		{name: "four elements unsorted", ds: []time.Duration{40 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}, want: 25.0},
		{name: "five elements unsorted", ds: []time.Duration{50 * time.Millisecond, 10 * time.Millisecond, 40 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}, want: 30.0},
		{name: "fractional milliseconds odd", ds: []time.Duration{1500 * time.Microsecond}, want: 1.5},
		{name: "fractional milliseconds even", ds: []time.Duration{1200 * time.Microsecond, 1800 * time.Microsecond}, want: 1.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := medianMs(tt.ds)
			if math.Abs(got-tt.want) > 1e-6 {
				t.Fatalf("medianMs(%v) = %v, want %v", tt.ds, got, tt.want)
			}
		})
	}
}

func TestLossPct(t *testing.T) {
	tests := []struct {
		name       string
		unanswered int
		total      int
		want       float64
	}{
		{name: "zero loss of 5", unanswered: 0, total: 5, want: 0.0},
		{name: "one loss of 5", unanswered: 1, total: 5, want: 20.0},
		{name: "two loss of 5", unanswered: 2, total: 5, want: 40.0},
		{name: "three loss of 5", unanswered: 3, total: 5, want: 60.0},
		{name: "four loss of 5", unanswered: 4, total: 5, want: 80.0},
		{name: "all lost of 5", unanswered: 5, total: 5, want: 100.0},
		{name: "zero total", unanswered: 0, total: 0, want: 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lossPct(tt.unanswered, tt.total)
			if math.Abs(got-tt.want) > 1e-6 {
				t.Fatalf("lossPct(%d, %d) = %v, want %v", tt.unanswered, tt.total, got, tt.want)
			}
		})
	}
}

func TestExperienceQueueBounds(t *testing.T) {
	rs := &runState{}
	for i := 0; i < 70; i++ {
		rs.addExperienceSample(api.ExperienceSample{
			EdgeID: "edge-1",
			RTTms:  float64(i),
		})
	}
	rs.expMu.Lock()
	n := len(rs.pendingSamples)
	oldest := rs.pendingSamples[0].RTTms
	newest := rs.pendingSamples[n-1].RTTms
	rs.expMu.Unlock()

	if n != maxPendingSamples {
		t.Fatalf("queue len = %d, want %d", n, maxPendingSamples)
	}
	// First 10 samples (0..9) should be dropped; oldest remaining is 10.
	if oldest != 10.0 {
		t.Fatalf("oldest sample RTTms = %v, want 10.0", oldest)
	}
	if newest != 69.0 {
		t.Fatalf("newest sample RTTms = %v, want 69.0", newest)
	}
}

func TestUploadExperienceProbes(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	rs := e.running.Load()
	if rs == nil {
		t.Fatal("running state is nil")
	}

	s1 := api.ExperienceSample{
		At:      time.Now().UTC(),
		EdgeID:  "edge-1",
		RTTms:   12.5,
		LossPct: 0.0,
		DNSms:   4.2,
		Network: "wifi",
	}
	s2 := api.ExperienceSample{
		At:      time.Now().UTC(),
		EdgeID:  "edge-1",
		RTTms:   18.0,
		LossPct: 20.0,
		DNSms:   5.0,
		Network: "wifi",
	}

	rs.addExperienceSample(s1)
	rs.addExperienceSample(s2)

	// Ensure there are no flow records.
	rs.pendingFlows = nil

	// Simulate failure on the Control Plane: POST /v1/flows returns HTTP 500.
	fc.mu.Lock()
	fc.flowFail = 1
	fc.mu.Unlock()

	ctx := context.Background()
	err := e.uploadFlows(ctx, rs)
	if err == nil {
		t.Fatal("expected upload error, got nil")
	}

	// Samples must remain queued on failure.
	rs.expMu.Lock()
	pendingLen := len(rs.pendingSamples)
	rs.expMu.Unlock()
	if pendingLen != 2 {
		t.Fatalf("pending samples after failure = %d, want 2", pendingLen)
	}

	fc.mu.Lock()
	uploadedProbes := len(fc.probes)
	fc.mu.Unlock()
	if uploadedProbes != 0 {
		t.Fatalf("server received %d probes on failed upload, want 0", uploadedProbes)
	}

	// Retry without failure: upload must succeed.
	err = e.uploadFlows(ctx, rs)
	if err != nil {
		t.Fatalf("expected successful upload, got: %v", err)
	}

	// Queue must be cleared after success.
	rs.expMu.Lock()
	pendingLen = len(rs.pendingSamples)
	rs.expMu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("pending samples after success = %d, want 0", pendingLen)
	}

	// Server must have received both samples in a batch with NO flow records.
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.probes) != 2 {
		t.Fatalf("server received %d probes, want 2", len(fc.probes))
	}
	if len(fc.flows) != 0 {
		t.Fatalf("server received %d flow records, want 0", len(fc.flows))
	}
	if fc.probes[0].EdgeID != "edge-1" || fc.probes[0].RTTms != 12.5 || fc.probes[0].DNSms != 4.2 {
		t.Fatalf("probe[0] mismatch: %+v", fc.probes[0])
	}
	if fc.probes[1].EdgeID != "edge-1" || fc.probes[1].RTTms != 18.0 || fc.probes[1].LossPct != 20.0 {
		t.Fatalf("probe[1] mismatch: %+v", fc.probes[1])
	}
}

func TestExperienceLoopIntegration(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := newTestEngine(t, fc)
	e.experienceInterval = 20 * time.Millisecond
	e.flowInterval = 20 * time.Millisecond
	e.experienceProbeTimeout = 500 * time.Millisecond

	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	if err := e.StartDevice(ct.TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	// Wait for the experience loop to generate a sample and the flow loop to upload it.
	waitUntil(t, "experience probe upload", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.probes) > 0
	})

	fc.mu.Lock()
	defer fc.mu.Unlock()
	sample := fc.probes[0]
	if sample.EdgeID != "edge-1" {
		t.Fatalf("EdgeID = %q, want %q", sample.EdgeID, "edge-1")
	}
	if sample.LossPct != 0.0 {
		t.Fatalf("LossPct = %v, want 0.0", sample.LossPct)
	}
	if sample.Network != "wifi" {
		t.Fatalf("Network = %q, want %q", sample.Network, "wifi")
	}
}
