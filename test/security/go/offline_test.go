package securitytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

// cachedState mirrors the cache content of internal/edge's state.json (ADR-0014).
type cachedState struct {
	SavedAt time.Time     `json:"savedAt"`
	Tenant  string        `json:"tenant,omitempty"`
	Bundle  api.PKIBundle `json:"bundle"`
	Peers   api.EdgePeers `json:"peers"`
}

// signedState is the on-disk form since the ST-06 fix: the cachedState JSON signed with the
// Edge certificate key (ECDSA P-256: ASN.1 signature over SHA-256 of the state bytes).
type signedState struct {
	State     json.RawMessage `json:"state"`
	Signature []byte          `json:"signature"`
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

// signState wraps a cache body the way the Edge does, signed with key.
func signState(body []byte, key *ecdsa.PrivateKey) []byte {
	d := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		panic(err)
	}
	j, _ := json.Marshal(signedState{State: body, Signature: sig})
	return j
}

// writeCache writes raw as state.json into a fresh 0700 directory and returns it.
func writeCache(t *testing.T, raw []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// liveCache waits until the dev Edge's own signed state.json lists at least one device of
// tenant (the fixture enrolled some; the Edge saves the cache on its 10s peer sync) and
// returns the file as written by the Edge plus its decoded content.
func liveCache(f *fixture, tenant string, d time.Duration) ([]byte, cachedState, error) {
	deadline := time.Now().Add(d)
	var last error
	for {
		raw, err := os.ReadFile(filepath.Join(f.devDir, "edge-state", "state.json"))
		var ss signedState
		var st cachedState
		if err == nil {
			err = json.Unmarshal(raw, &ss)
		}
		if err == nil && len(ss.Signature) == 0 {
			err = errors.New("state.json is not in the signed format (old Edge image?)")
		}
		if err == nil {
			err = json.Unmarshal(ss.State, &st)
		}
		if err == nil {
			for _, dv := range st.Peers.Devices {
				if dv.TenantID == tenant {
					return raw, st, nil
				}
			}
			err = fmt.Errorf("no device of %s in the cache yet (%d devices)", tenant, len(st.Peers.Devices))
		}
		last = err
		if time.Now().After(deadline) {
			return nil, cachedState{}, last
		}
		time.Sleep(2 * time.Second)
	}
}

func TestOffline(t *testing.T) {
	f := stack(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	live, base, err := liveCache(f, f.tA, 45*time.Second)
	if err != nil {
		check(t, "SEC-OFF-000", "control: offline Edge starts from its own signed cache", "", func(*testing.T) error {
			return skipf("deploy/dev/edge-state/state.json: %v", err)
		})
		return
	}
	// The harness signs with the dev Edge's own key (deploy/dev/pki/edge/edge.key). This
	// models an attacker who holds the Edge key (or a bug that corrupts the cache after the
	// Edge signed it): the per-snapshot checks must still hold.
	kb, err := os.ReadFile(filepath.Join(f.devDir, "pki", "edge", "edge.key"))
	var edgeKey *ecdsa.PrivateKey
	if err == nil {
		edgeKey, err = pki.ParseKeyPEM(kb)
	}
	if err != nil {
		t.Fatalf("edge key: %v", err)
	}
	clone := func() cachedState {
		j, _ := json.Marshal(base)
		var c cachedState
		_ = json.Unmarshal(j, &c)
		return c
	}
	body := func(st cachedState) []byte { j, _ := json.Marshal(st); return j }
	own := 0
	for _, d := range base.Peers.Devices {
		if d.TenantID == f.tA {
			own++
		}
	}

	// Control: the Edge's own cache, byte for byte, is loaded and its snapshots enforced.
	check(t, "SEC-OFF-000", "control: offline Edge starts from its own signed cache", "", func(t *testing.T) error {
		logs, err := offlineEdge(f, writeCache(t, live))
		if err != nil {
			return skipf("%v", err)
		}
		if !strings.Contains(logs, "enforcing cached state") {
			return fmt.Errorf("edge did not start from its own cache: %.400s", logs)
		}
		if _, upd, inv := synced(logs); upd == 0 || inv != 0 {
			return fmt.Errorf("control: updated=%d invalid=%d", upd, inv)
		}
		return nil
	})

	// Tampered snapshots (payload changed, snapshot signature kept), cache re-signed with
	// the Edge key: the cache loads, but no tampered snapshot may be enforced.
	check(t, "SEC-OFF-001", "cache signed by the Edge key with tampered snapshots: devices rejected", "", func(t *testing.T) error {
		st := clone()
		for i := range st.Peers.Devices {
			e := &st.Peers.Devices[i].Snapshot
			e.Payload = bytes.ReplaceAll(e.Payload, []byte(`"block"`), []byte(`"allow"`))
			e.Payload = append(e.Payload[:len(e.Payload)-1], []byte(` }`)...)
		}
		logs, err := offlineEdge(f, writeCache(t, signState(body(st), edgeKey)))
		if err != nil {
			return skipf("%v", err)
		}
		if !strings.Contains(logs, "enforcing cached state") {
			return fmt.Errorf("control: the Edge-signed cache was not loaded: %.300s", logs)
		}
		dev, upd, inv := synced(logs)
		t.Logf("devices=%d updated=%d invalid=%d", dev, upd, inv)
		if upd != 0 {
			return fmt.Errorf("edge enforced %d tampered snapshots", upd)
		}
		if inv != len(st.Peers.Devices) {
			return fmt.Errorf("want all %d snapshots invalid, got invalid=%d", len(st.Peers.Devices), inv)
		}
		return nil
	})

	// Garbage state file: refused, the Edge waits for the Control Plane.
	check(t, "SEC-OFF-002", "corrupt state.json refused (Edge waits for the Control Plane)", "", func(t *testing.T) error {
		logs, err := offlineEdge(f, writeCache(t, []byte(`{"state":{"bundle":{"caPem":"-----BEGIN`)))
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

	// A cache written for another tenant (a public Edge's cache, validly signed) is refused
	// by a Private Edge started with -tenant.
	check(t, "SEC-OFF-003", "validly signed cache of another tenant refused by a Private Edge (-tenant)", "", func(t *testing.T) error {
		st := clone()
		st.Tenant = ""
		logs, err := offlineEdge(f, writeCache(t, signState(body(st), edgeKey)), "-tenant", f.tA)
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

	// The Tenant label is inside the signed state, but an Edge-key holder can relabel a
	// multi-tenant cache: the Private Edge must still keep only its tenant's devices (ST-07).
	check(t, "SEC-OFF-004", "relabelled multi-tenant cache: Private Edge keeps only its tenant's devices (ST-07)", "", func(t *testing.T) error {
		st := clone()
		st.Tenant = f.tA
		if own == 0 || own == len(st.Peers.Devices) {
			return skipf("cache needs devices of %s and of other tenants (own %d of %d)", f.tA, own, len(st.Peers.Devices))
		}
		logs, err := offlineEdge(f, writeCache(t, signState(body(st), edgeKey)), "-tenant", f.tA)
		if err != nil {
			return skipf("%v", err)
		}
		if !strings.Contains(logs, "enforcing cached state") {
			return fmt.Errorf("control: relabelled cache not loaded at all: %.300s", logs)
		}
		_, upd, _ := synced(logs)
		if upd != own {
			return fmt.Errorf("private edge of %s enforced %d devices from the cache, its own are %d (of %d)", f.tA, upd, own, len(st.Peers.Devices))
		}
		return nil
	})

	// ST-06: attacker snapshot key, re-signed permissive snapshots, cache signed with a key
	// that is not the Edge's (only write access to the state dir). Must be refused whole.
	check(t, "SEC-OFF-005", "cache signed by a foreign key (attacker snapshot key inside) refused (ST-06)", "", func(t *testing.T) error {
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
		logs, err := offlineEdge(f, writeCache(t, signState(body(st), newKey())))
		if err != nil {
			return skipf("%v", err)
		}
		if strings.Contains(logs, "enforcing cached state") {
			_, upd, _ := synced(logs)
			return fmt.Errorf("edge loaded a cache signed by a foreign key (%d snapshots enforced)", upd)
		}
		if !strings.Contains(logs, "state cache unusable") {
			return fmt.Errorf("no refusal logged: %.300s", logs)
		}
		return nil
	})

	// The pre-fix format (plain cachedState JSON, no signature) and a signed cache edited
	// after signing are both refused.
	check(t, "SEC-OFF-006", "unsigned (legacy) cache and cache edited after signing refused", "", func(t *testing.T) error {
		var errs []error
		var ss signedState
		_ = json.Unmarshal(live, &ss)
		edited := bytes.Replace(ss.State, []byte(`"tenantId":"`+f.tA+`"`), []byte(`"tenantId":"`+f.tB+`"`), 1)
		if bytes.Equal(edited, ss.State) {
			return skipf("nothing to edit in the cache")
		}
		ss.State = edited
		tampered, _ := json.Marshal(ss)
		for name, raw := range map[string][]byte{"unsigned legacy": body(clone()), "edited after signing": tampered} {
			logs, err := offlineEdge(f, writeCache(t, raw))
			if err != nil {
				return skipf("%v", err)
			}
			switch {
			case strings.Contains(logs, "enforcing cached state"):
				errs = append(errs, fmt.Errorf("%s cache loaded", name))
			case !strings.Contains(logs, "state cache unusable"):
				errs = append(errs, fmt.Errorf("%s: no refusal logged: %.200s", name, logs))
			}
		}
		return errors.Join(errs...)
	})
}
