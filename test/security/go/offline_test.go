package securitytest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// cachedState mirrors internal/edge's state.json (ADR-0014).
type cachedState struct {
	SavedAt time.Time     `json:"savedAt"`
	Tenant  string        `json:"tenant,omitempty"`
	Bundle  api.PKIBundle `json:"bundle"`
	Peers   api.EdgePeers `json:"peers"`
}

// offlineEdge starts a throwaway Edge container from the dev image with no network (the
// Control Plane is unreachable), the dev Edge's PKI and stateDir as its cache, and returns
// its log once it is ready or has given up on the cache.
func offlineEdge(f *fixture, stateDir string, args ...string) (string, error) {
	img := getenv("SECTEST_EDGE_IMAGE", "opensase/edge:dev")
	pkiDir, err := filepath.Abs(filepath.Join(f.devDir, "pki", "edge"))
	if err != nil {
		return "", err
	}
	name := "sectest-offline-edge-" + f.run + "-" + strconv.FormatInt(time.Now().UnixNano()%1e6, 10)
	run := append([]string{"run", "-d", "--name", name, "--network", "none",
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_BIND_SERVICE", "--cap-add", "SETUID", "--cap-add", "SETGID",
		"--security-opt", "no-new-privileges:true", "--device", "/dev/net/tun",
		"-e", "EDGE_UID=" + strconv.Itoa(os.Getuid()), "-e", "EDGE_GID=" + strconv.Itoa(os.Getgid()),
		"-v", pkiDir + ":/pki:ro", "-v", stateDir + ":/var/lib/opensase-edge",
		img, "-control-url", "https://127.0.0.1:1", "-pki", "/pki", "-state-dir", "/var/lib/opensase-edge"}, args...)
	if out, err := exec.Command("docker", run...).CombinedOutput(); err != nil { //nolint:gosec // G204: fixed docker CLI
		return "", fmt.Errorf("docker run: %w: %s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", name).Run() //nolint:errcheck,gosec // cleanup
	var logs string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput() //nolint:gosec // G204: fixed docker CLI
		logs = string(out)
		if strings.Contains(logs, `"edge ready"`) || strings.Count(logs, "waiting for control plane") >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return logs, nil
}

var syncedRE = regexp.MustCompile(`"msg":"peers synced","devices":(\d+),"updated":(\d+),"removed":\d+,"invalid":(\d+)`)

// synced returns devices/updated/invalid of the first "peers synced" log line (zeros if none).
func synced(logs string) (devices, updated, invalid int) {
	m := syncedRE.FindStringSubmatch(logs)
	if m == nil {
		return 0, 0, 0
	}
	devices, _ = strconv.Atoi(m[1])
	updated, _ = strconv.Atoi(m[2])
	invalid, _ = strconv.Atoi(m[3])
	return
}

func writeState(t *testing.T, st cachedState) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), j, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOffline(t *testing.T) {
	f := stack(t)
	raw, err := os.ReadFile(filepath.Join(f.devDir, "edge-state", "state.json"))
	var base cachedState
	if err == nil {
		err = json.Unmarshal(raw, &base)
	}
	if err == nil && len(base.Peers.Devices) == 0 {
		err = errors.New("cache holds no devices")
	}
	if err != nil {
		check(t, "SEC-OFF-000", "control: offline Edge starts from an untampered cache", "", func(*testing.T) error {
			return skipf("deploy/dev/edge-state/state.json: %v", err)
		})
		return
	}
	clone := func() cachedState {
		var c cachedState
		_ = json.Unmarshal(raw, &c)
		return c
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Control: an untampered copy of the live cache is loaded and enforced.
	check(t, "SEC-OFF-000", "control: offline Edge starts from an untampered cache", "", func(t *testing.T) error {
		logs, err := offlineEdge(f, writeState(t, clone()))
		if err != nil {
			return skipf("%v", err)
		}
		if !strings.Contains(logs, "enforcing cached state") {
			return skipf("edge did not start from the cache: %.400s", logs)
		}
		if _, upd, inv := synced(logs); upd == 0 || inv != 0 {
			return fmt.Errorf("control: updated=%d invalid=%d", upd, inv)
		}
		return nil
	})

	// Tampered snapshots (payload changed, signature kept): none may be enforced.
	check(t, "SEC-OFF-001", "tampered state.json: modified snapshots refused (signature check)", "", func(t *testing.T) error {
		st := clone()
		for i := range st.Peers.Devices {
			e := &st.Peers.Devices[i].Snapshot
			e.Payload = bytes.ReplaceAll(e.Payload, []byte(`"block"`), []byte(`"allow"`))
			e.Payload = append(e.Payload[:len(e.Payload)-1], []byte(` }`)...)
		}
		logs, err := offlineEdge(f, writeState(t, st))
		if err != nil {
			return skipf("%v", err)
		}
		dev, upd, inv := synced(logs)
		if upd != 0 {
			return fmt.Errorf("edge enforced %d tampered snapshots (devices=%d invalid=%d)", upd, dev, inv)
		}
		t.Logf("devices=%d updated=%d invalid=%d", dev, upd, inv)
		if inv != len(st.Peers.Devices) {
			return fmt.Errorf("want all %d snapshots invalid, got invalid=%d: %.300s", len(st.Peers.Devices), inv, logs)
		}
		return nil
	})

	// Garbage state file: refused, the Edge waits for the Control Plane.
	check(t, "SEC-OFF-002", "corrupt state.json refused (Edge waits for the Control Plane)", "", func(t *testing.T) error {
		dir := t.TempDir()
		_ = os.Chmod(dir, 0o700)
		_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"bundle":{"caPem":"-----BEGIN`), 0o600)
		logs, err := offlineEdge(f, dir)
		if err != nil {
			return skipf("%v", err)
		}
		if strings.Contains(logs, "enforcing cached state") {
			return errors.New("edge started from a corrupt cache")
		}
		if !strings.Contains(logs, "state cache unusable") {
			return fmt.Errorf("no refusal logged: %.300s", logs)
		}
		return nil
	})

	// A cache written for another tenant (here: a public Edge's cache) is refused by a
	// Private Edge started with -tenant.
	check(t, "SEC-OFF-003", "cache of another tenant refused by a Private Edge (-tenant)", "", func(t *testing.T) error {
		st := clone()
		st.Tenant = ""
		logs, err := offlineEdge(f, writeState(t, st), "-tenant", f.tA)
		if err != nil {
			return skipf("%v", err)
		}
		if strings.Contains(logs, "enforcing cached state") {
			return fmt.Errorf("private edge of %s loaded a public edge's cache", f.tA)
		}
		if !strings.Contains(logs, "state cache unusable") {
			return fmt.Errorf("no refusal logged: %.300s", logs)
		}
		return nil
	})

	// The Tenant label is itself untrusted: relabel a multi-tenant cache as tenant A's.
	// The Private Edge must still keep only tenant A's devices (as scopePeers does live).
	check(t, "SEC-OFF-004", "relabelled multi-tenant cache: Private Edge keeps only its tenant's devices", "ST-07", func(t *testing.T) error {
		st := clone()
		st.Tenant = f.tA
		own := 0
		for _, d := range st.Peers.Devices {
			if d.TenantID == f.tA {
				own++
			}
		}
		logs, err := offlineEdge(f, writeState(t, st), "-tenant", f.tA)
		if err != nil {
			return skipf("%v", err)
		}
		if !strings.Contains(logs, "enforcing cached state") {
			return nil // refused outright
		}
		dev, upd, _ := synced(logs)
		if upd > own {
			return fmt.Errorf("private edge of %s loaded %d devices from the cache, only %d are its own (of %d)", f.tA, upd, own, dev)
		}
		return nil
	})

	// Snapshot signing keys come from the cache itself: replace them with an attacker key
	// and re-sign permissive snapshots. ADR-0014 accepts this (state-dir write == Edge key
	// read); recorded so the trade-off stays visible.
	check(t, "SEC-OFF-005", "cache with attacker snapshot key and re-signed snapshots refused", "ST-06", func(t *testing.T) error {
		st := clone()
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		kid := "sectest-" + hex.EncodeToString(pub[:4])
		st.Bundle.SnapshotKeys = []api.SigningKey{{KeyID: kid, Algorithm: policy.AlgEd25519, PublicKey: pub}}
		for i := range st.Peers.Devices {
			e := &st.Peers.Devices[i].Snapshot
			var s policy.Snapshot
			if err := json.Unmarshal(e.Payload, &s); err != nil {
				return err
			}
			s.Firewall.Rules = nil
			s.Version += 1000
			p, _ := json.Marshal(s)
			*e = policy.Envelope{KeyID: kid, Algorithm: policy.AlgEd25519, Payload: p, Signature: ed25519.Sign(priv, p)}
		}
		logs, err := offlineEdge(f, writeState(t, st))
		if err != nil {
			return skipf("%v", err)
		}
		if _, upd, _ := synced(logs); upd > 0 && strings.Contains(logs, "enforcing cached state") {
			return fmt.Errorf("edge enforced %d snapshots signed by a key that only the cache vouches for", upd)
		}
		return nil
	})
}
