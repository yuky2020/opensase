package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/store"
)

// TestScheduledBackup covers issue #67: a backup holds the database and the PKI directory,
// old backups are pruned, and a backup restores to a working database.
func TestScheduledBackup(t *testing.T) {
	bdir := t.TempDir()
	clock := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	e := newEnvCfg(t, func(c *Config) {
		c.BackupDir, c.BackupKeep = bdir, 2
		c.Now = func() time.Time { return clock }
	})
	e.s.cfg.PKIDir = e.dir
	e.setupTenant(1)
	ctx := context.Background()
	for i := range 3 {
		clock = clock.Add(time.Duration(i+1) * time.Hour)
		if err := e.s.backupOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(bdir)
	var dbs, pkis []string
	for _, en := range entries {
		switch {
		case strings.HasPrefix(en.Name(), "controlplane-"):
			dbs = append(dbs, en.Name())
		case strings.HasPrefix(en.Name(), "pki-"):
			pkis = append(pkis, en.Name())
		}
		if fi, _ := en.Info(); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", en.Name(), fi.Mode())
		}
	}
	if len(dbs) != 2 || len(pkis) != 2 {
		t.Fatalf("kept %v %v", dbs, pkis)
	}
	to := filepath.Join(t.TempDir(), "restored.db")
	if err := store.Restore(ctx, filepath.Join(bdir, dbs[1]), to); err != nil {
		t.Fatal(err)
	}
	r, err := store.Open(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.GetTenantPolicy(ctx, "acme"); err != nil {
		t.Fatalf("restored policy: %v", err)
	}
}

// TestOpsEndpoints covers issue #73: /metrics exposes the series, /healthz and /readyz answer.
func TestOpsEndpoints(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	e.enroll(key)
	e.s.logAuditHead(context.Background())
	srv := httptest.NewServer(e.s.OpsHandler())
	defer srv.Close()
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	if code, body := get("/readyz"); code != 200 {
		t.Fatalf("readyz %d %s", code, body)
	}
	code, body := get("/metrics")
	if code != 200 {
		t.Fatalf("metrics %d", code)
	}
	for _, want := range []string{
		"opensase_cp_devices 1\n",
		"opensase_cp_leader 1\n",
		"opensase_cp_audit_chain_ok 1\n",
		`opensase_cp_http_requests_total{class="2xx"}`,
		`opensase_cp_certificate_expiry_seconds{cert="root"}`,
		`opensase_cp_edge_sessions{edge="edge-1"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}

// TestAdminStatus covers issue #73: the status page data, super-admin only.
func TestAdminStatus(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	er, _ := e.enroll(key)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	if err := e.s.cfg.Store.ReportEdgeSessions(context.Background(), "edge-1", []string{er.DeviceID}, time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	var st api.AdminStatus
	if err := json.Unmarshal(e.adminDo("GET", "/v1/admin/status", nil, 200), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Edges) != 1 || !st.Edges[0].Reporting || st.Edges[0].Sessions != 1 || st.DevicesOnline != 1 || st.DevicesEnrolled != 1 || !st.Leader {
		t.Fatalf("status %+v", st)
	}
	if len(st.Certificates) == 0 || st.AuditChain == "" {
		t.Fatalf("status %+v", st)
	}
}
