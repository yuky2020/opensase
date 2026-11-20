package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestSingleTenantScope(t *testing.T) {
	tests := []struct {
		tenant  string
		want    bool // device d1 (tenant acme) accepted
		wantCAs int  // root + tenant CAs kept from the bundle
	}{
		{"", true, 2},
		{"acme", true, 2},
		{"beta", false, 1},
	}
	for _, tc := range tests {
		t.Run("tenant="+tc.tenant, func(t *testing.T) {
			fx := newFixtureCfg(t, func(c *Config) { c.TenantID = tc.tenant })
			fx.setPeer("d1", 1)
			fx.cp.peers.Connectors = []api.EdgeConnector{{ConnectorID: "c1", TenantID: "acme"}}
			if err := fx.e.syncPeers(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := fx.e.reg.get("d1") != nil; got != tc.want {
				t.Fatalf("device accepted = %v, want %v", got, tc.want)
			}
			if got := len(fx.e.trust.Load().pool.Subjects()); got != tc.wantCAs { //nolint:staticcheck // SA1019: Subjects is fine for counting a pool built from parsed certs
				t.Fatalf("trusted CAs %d, want %d", got, tc.wantCAs)
			}
			if _, got := fx.e.hub.isAllowed(pki.Identity{Kind: pki.PeerConnector, TenantID: "acme", ConnectorID: "c1"}); got != tc.want {
				t.Fatalf("connector allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStateCache(t *testing.T) {
	state := t.TempDir()
	fx := newFixtureCfg(t, func(c *Config) { c.StateDir = state; c.TenantID = "acme" })
	fx.setPeer("d1", 1)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, stateFile)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %v", st.Mode())
	}
	// An unchanged sync does not rewrite the file.
	mod := st.ModTime()
	time.Sleep(20 * time.Millisecond)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(path); !st2.ModTime().Equal(mod) {
		t.Fatal("unchanged state rewritten")
	}

	// A fresh Edge with the same state dir starts from the cache.
	load := func(tenant string) (*Edge, error) {
		t.Helper()
		e, err := newEdge(context.Background(), Config{Root: fx.auth.Root.Cert, Cert: fx.e.cfg.Cert, WGPrivateKey: fx.e.cfg.WGPrivateKey, StateDir: state, TenantID: tenant,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, fx.cp)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.loadState()
		return e, err
	}
	e2, err := load("acme")
	if err != nil {
		t.Fatal(err)
	}
	if e2.reg.get("d1") == nil || e2.trust.Load() == nil {
		t.Fatal("cached device not loaded")
	}
	if _, err := load("beta"); err == nil {
		t.Fatal("cache of another tenant accepted")
	}

	// A tampered snapshot in the cache does not verify, so the device is not accepted.
	var cs cachedState
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	cs.Peers.Devices[0].Snapshot.Payload = append([]byte(nil), cs.Peers.Devices[0].Snapshot.Payload...)
	cs.Peers.Devices[0].Snapshot.Payload[len(cs.Peers.Devices[0].Snapshot.Payload)/2] ^= 1
	b, _ = json.Marshal(cs)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	e3, err := load("acme")
	if err != nil {
		t.Fatal(err)
	}
	if e3.reg.get("d1") != nil {
		t.Fatal("tampered cached snapshot accepted")
	}

	// A cache whose CA bundle does not chain to the root is rejected outright.
	cs.Bundle.CAPEM = ""
	cs.Bundle.SnapshotKeys = nil
	b, _ = json.Marshal(cs)
	_ = os.WriteFile(path, b, 0o600)
	if _, err := load("acme"); err == nil {
		t.Fatal("cache without snapshot keys accepted")
	}
}

func TestLocalFlowLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	l := newLocalFlowLog(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	l.maxBytes = 600
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.run(ctx) }()
	for i := range 10 {
		l.add([]api.FlowRecord{{DeviceID: "d1", Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.1", DstPort: uint16(i)}, Where: "edge"}})
	}
	l.add(nil)
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, p := range []string{path + ".1", path} {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		if st, _ := f.Stat(); st.Mode().Perm() != 0o600 || st.Size() > l.maxBytes {
			t.Fatalf("%s: mode %v size %d", p, st.Mode(), st.Size())
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var r api.FlowRecord
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.DeviceID != "d1" {
				t.Fatalf("bad line %q: %v", sc.Text(), err)
			}
			lines++
		}
		f.Close()
	}
	// Only one backup is kept, so some of the oldest records may be gone; the newest are not.
	if lines == 0 || lines > 10 {
		t.Fatalf("lines %d", lines)
	}
}
