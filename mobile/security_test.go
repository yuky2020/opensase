package mobile

// Regression tests for the security review of 2026-11-19 (docs/security/review-2026-11-19.md).

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

func enrolled(t *testing.T, fc *fakeCloud) (*Engine, *recPlatform) {
	t.Helper()
	e, pl := newTestEngine(t, fc)
	if err := e.Enroll(fc.cp.URL, "pk-good", "pixel"); err != nil {
		t.Fatal(err)
	}
	return e, pl
}

func status(t *testing.T, e *Engine) statusJSON {
	t.Helper()
	var st statusJSON
	if err := json.Unmarshal([]byte(e.Status()), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// #1: enrollment (CA file and pinned bootstrap) requires the Control Plane identity.
func TestEnrollRequiresControlPlaneIdentity(t *testing.T) {
	fc := newFakeCloud(t)
	caSum := sha256.Sum256(fc.pki.ca.Raw)
	pin := "#sha256=" + hex.EncodeToString(caSum[:])
	servers := map[string]*url.URL{
		"edge cert":     pki.EdgeURI("edge-1"),
		"device URI":    pki.DeviceURI(testTenant, testDevice),
		"no URI":        nil,
		"control plane": pki.ControlPlaneURI(),
	}
	for name, uri := range servers {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/enroll", fc.enroll)
		srv := startTLS(t, fc.pki, mux, true, uri)
		for _, mode := range []string{"ca file", "pin"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				u := srv.URL
				if mode == "ca file" {
					os.WriteFile(dir+"/"+fileBootstrapCA, []byte(fc.pki.caPEM), 0o600)
				} else {
					u += pin
				}
				e, err := NewEngine(dir, &recPlatform{})
				if err != nil {
					t.Fatal(err)
				}
				err = e.Enroll(u, "pk-good", "pixel")
				if name == "control plane" {
					if err != nil {
						t.Fatalf("Enroll: %v", err)
					}
					return
				}
				if err == nil || e.IsEnrolled() {
					t.Fatalf("enrolled against a server with identity %v", uri)
				}
			})
		}
	}
}

// #1: an Edge certificate cannot pose as the Control Plane for snapshots or snapshot keys.
func TestControlPlaneImpostorCannotInstallKeys(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := enrolled(t, fc)
	id := e.en.Load()

	_, evilKey, _ := ed25519.GenerateKey(rand.Reader)
	evilSnap := *fc.snap
	evilSnap.Version = 99
	evilSnap.Firewall.DefaultAction = policy.ActionAllow
	evilSnap.Firewall.Rules = nil
	env, err := policy.Sign(&evilSnap, "evil", evilKey)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/snapshot", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(env) })
	mux.HandleFunc("GET /v1/pki/ca", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.PKIBundle{CAPEM: fc.pki.caPEM, SnapshotKeys: []api.SigningKey{
			{KeyID: "evil", Algorithm: policy.AlgEd25519, PublicKey: evilKey.Public().(ed25519.PublicKey)}}})
	})
	impostor := startTLS(t, fc.pki, mux, true, pki.EdgeURI("edge-1")) // valid chain, wrong role

	id.resp.ControlURL = impostor.URL
	if err := e.pollSnapshot(context.Background(), id, 0); err == nil {
		t.Fatal("snapshot accepted from an Edge certificate")
	}
	if _, ok := (*id.keys.Load())["evil"]; ok || len(*id.keys.Load()) != 1 {
		t.Fatalf("snapshot keys changed: %v", *id.keys.Load())
	}
	if e.currentVersion() == 99 {
		t.Fatal("attacker snapshot installed")
	}
}

// #1: a key refresh over the verified Control Plane works and is reported as an event.
func TestSnapshotKeyRefreshIsLogged(t *testing.T) {
	fc := newFakeCloud(t)
	e, pl := enrolled(t, fc)
	id := e.en.Load()
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	fc.mu.Lock()
	fc.extraKeys = []api.SigningKey{{KeyID: "k2", Algorithm: policy.AlgEd25519, PublicKey: k2.Public().(ed25519.PublicKey)}}
	s := *fc.snap
	fc.mu.Unlock()
	s.Version = 5
	env, _ := policy.Sign(&s, "k2", k2)
	if ok, err := e.applyEnvelope(context.Background(), id, env); !ok || err != nil {
		t.Fatalf("applyEnvelope: %v %v", ok, err)
	}
	if !pl.has(`log {"attrs":{"added":["k2"]`) {
		t.Fatalf("no key change event: %v", pl.events)
	}
}

// #1: an Edge session URL must prove spiffe://opensase/edge/<EdgeInfo.ID>.
func TestEdgeSessionRequiresEdgeIdentity(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := enrolled(t, fc)
	id := e.en.Load()
	good := id.resp.Edges[0]
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/session", fc.requireCert(fc.session))
	otherEdge := startTLS(t, fc.pki, mux, true, pki.EdgeURI("edge-2"))
	tests := []struct {
		name string
		url  string
		ok   bool
	}{
		{"matching edge", good.SessionURL, true},
		{"control plane cert", fc.cp.URL, false},
		{"other edge id", otherEdge.URL, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edge := good
			edge.SessionURL = tt.url
			s, err := e.setupSession(context.Background(), id.enrollment, edge, nil)
			if (err == nil) != tt.ok {
				t.Fatalf("err=%v, want ok=%v", err, tt.ok)
			}
			if s != nil {
				s.wipe()
			}
		})
	}
}

// #4: renewal at >50% of the lifetime with a new key, persisted and hot-swapped.
func TestCertificateRenewal(t *testing.T) {
	fc := newFakeCloud(t)
	fc.certFrom, fc.certTo = -90*time.Minute, 30*time.Minute // 75% elapsed at enrollment
	e, pl := enrolled(t, fc)
	e.renewRetryMin = 20 * time.Millisecond
	id := e.en.Load()
	old := id.leaf()
	fc.mu.Lock()
	fc.certFrom, fc.certTo = -time.Minute, 24*time.Hour
	fc.renewFail = 2 // the first two attempts fail: backoff and retry
	fc.mu.Unlock()

	if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	waitUntil(t, "renewal", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return fc.renewals == 1
	})
	waitUntil(t, "hot swap", func() bool { return id.leaf().SerialNumber.Cmp(old.SerialNumber) != 0 })
	cur := id.leaf()
	if cur.PublicKey.(*ecdsa.PublicKey).Equal(old.PublicKey) {
		t.Fatal("renewal reused the old key")
	}
	if !pl.has(`error {"message":"renew: http 500`) {
		t.Fatal("renew failure not reported")
	}
	if st := status(t, e); st.CertExpiresAt != cur.NotAfter.UTC().Format(time.RFC3339) || st.State != StateConnected {
		t.Fatalf("status %+v", st)
	}
	// The Control Plane and the Edge now see the new certificate.
	if err := e.SetAppPolicy("com.x", "allow", "", ""); err != nil {
		t.Fatal(err)
	}
	if c := fc.clientCert("/v1/self/rules"); c == nil || !c.Equal(cur) {
		t.Fatal("Control Plane client still uses the old certificate")
	}
	if err := e.rotate(e.running.Load()); err != nil {
		t.Fatal(err)
	}
	if c := fc.clientCert("/v1/session"); c == nil || !c.Equal(cur) {
		t.Fatal("Edge session client still uses the old certificate")
	}
	// Persisted atomically as one 0600 file; a restart loads the renewed identity.
	if st, err := os.Stat(e.statePath(fileDeviceBundle)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("bundle: %v", err)
	}
	e2, err := NewEngine(e.stateDir, &recPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	if !e2.en.Load().leaf().Equal(cur) {
		t.Fatal("restart did not load the renewed certificate")
	}
}

func TestRenewNow(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := enrolled(t, fc)
	old := e.en.Load().leaf()
	fc.certTo = 2 * time.Hour
	if err := e.RenewNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.en.Load().leaf().Equal(old) || fc.renewals != 1 {
		t.Fatal("not renewed")
	}
}

// #4: an expired certificate blocks the tunnel and is reported as an error.
func TestExpiredCertificate(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := enrolled(t, fc)
	id := e.en.Load()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := fc.pki.issueFor(t, &k.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now().Add(-2*time.Hour), time.Now().Add(-time.Minute))
	leaf, _ := x509.ParseCertificate(der)
	id.cert.Store(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf})

	if _, err := e.TunnelConfig(); !errors.Is(err, errCertExpired) {
		t.Fatalf("TunnelConfig: %v", err)
	}
	if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "wifi"); !errors.Is(err, errCertExpired) {
		t.Fatalf("StartDevice: %v", err)
	}
	if err := e.RenewNow(context.Background()); !errors.Is(err, errCertExpired) {
		t.Fatalf("RenewNow: %v", err)
	}
	st := status(t, e)
	if st.State != StateError || st.Error != "certificate expired, re-enrollment required" {
		t.Fatalf("status %+v", st)
	}
}

// reissue signs a certificate for pub that reuses old's serial number and identity.
func reissue(t *testing.T, p *testPKI, old *x509.Certificate, pub any, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: old.SerialNumber, Subject: old.Subject, URIs: old.URIs,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCheckRenewResponse(t *testing.T) {
	fc := newFakeCloud(t)
	other := newPKI(t)
	oldKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	old, _ := x509.ParseCertificate(fc.pki.issueFor(t, &oldKey.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemOf := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	later := time.Now().Add(24 * time.Hour)
	tests := []struct {
		name    string
		cert    string
		wantErr string
	}{
		{"valid", pemOf(fc.pki.issueFor(t, &key.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now(), later)) + fc.pki.caPEM, ""},
		{"other key", pemOf(fc.pki.issueFor(t, &otherKey.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now(), later)), "new key"},
		{"other device", pemOf(fc.pki.issueFor(t, &key.PublicKey, testDevice, false, pki.DeviceURI(testTenant, "dev-2"), time.Now(), later)), "another device"},
		{"edge identity", pemOf(fc.pki.issueFor(t, &key.PublicKey, testDevice, false, pki.EdgeURI("edge-1"), time.Now(), later)), "another device"},
		{"untrusted CA", pemOf(other.issueFor(t, &key.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now(), later)) + other.caPEM, "chain"},
		{"same expiry (same-second renewal)", pemOf(fc.pki.issueFor(t, &key.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now(), old.NotAfter)) + fc.pki.caPEM, ""},
		{"expires earlier", pemOf(fc.pki.issueFor(t, &key.PublicKey, testDevice, false, pki.DeviceURI(testTenant, testDevice), time.Now(), old.NotAfter.Add(-time.Minute))), "earlier"},
		{"garbage", "nope", "no certificate"},
		{"reused serial", pemOf(reissue(t, fc.pki, old, &key.PublicKey, later)), "serial"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// CAPEM from the response is never used as a root: "untrusted CA" includes it.
			_, err := checkRenewResponse(&api.RenewResponse{CertificatePEM: tt.cert, CAPEM: other.caPEM}, key, old, fc.pki.pool(), time.Now())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v, want %q", err, tt.wantErr)
			}
		})
	}
}

// #5: a rejected (409) or lost rotation falls back to a new session at epoch 0 with a new
// WireGuard key and full reconfiguration, so the device and the Edge agree on the PSK.
func TestRotationRecovery(t *testing.T) {
	for _, mode := range []string{"409", "lost"} {
		t.Run(mode, func(t *testing.T) {
			fc := newFakeCloud(t)
			fc.rotate = 1
			fc.rotationMode = mode
			e, _ := enrolled(t, fc)
			if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "wifi"); err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			priv0 := deviceIPC(t, e)["private_key"]
			waitUntil(t, "new session", func() bool {
				fc.mu.Lock()
				n := fc.sessions0
				fc.mu.Unlock()
				if n < 2 {
					return false
				}
				psk, _ := fc.edgePSK(0)
				ipc := deviceIPC(t, e)
				return ipc["private_key"] != priv0 && ipc["preshared_key"] == hex.EncodeToString(psk[:])
			})
			if st := status(t, e); st.State != StateConnected || st.Epoch != 0 {
				t.Fatalf("status %+v", st)
			}
		})
	}
}

// #5: a stale WireGuard handshake is never reported as connected and triggers a new session.
func TestLiveness(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		fc := newFakeCloud(t)
		e, _ := enrolled(t, fc)
		e.livenessTimeout, e.livenessInterval = 200*time.Millisecond, time.Hour // loop never acts
		if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "wifi"); err != nil {
			t.Fatal(err)
		}
		defer e.Stop()
		if st := status(t, e); st.State != StateConnected {
			t.Fatalf("status %+v", st)
		}
		time.Sleep(300 * time.Millisecond)
		if st := status(t, e); st.State != StateConnecting || !strings.Contains(st.Error, "no WireGuard handshake") {
			t.Fatalf("dead tunnel reported as %+v", st)
		}
	})
	t.Run("re-session", func(t *testing.T) {
		fc := newFakeCloud(t)
		e, pl := enrolled(t, fc)
		e.livenessTimeout, e.livenessInterval = 200*time.Millisecond, 20*time.Millisecond
		if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "wifi"); err != nil {
			t.Fatal(err)
		}
		defer e.Stop()
		waitUntil(t, "liveness re-session", func() bool {
			fc.mu.Lock()
			defer fc.mu.Unlock()
			return fc.sessions0 >= 2
		})
		if !pl.has(`state {"error":"tunnel down: no WireGuard handshake","state":"connecting"}`) {
			t.Fatal("no connecting state event")
		}
	})
}

// Enroll fetches, verifies and persists the first snapshot, so the policy screens are
// filled before the first connect.
func TestEnrollFetchesSnapshot(t *testing.T) {
	fc := newFakeCloud(t)
	e, _ := enrolled(t, fc)
	if e.currentVersion() != 1 || !strings.Contains(e.Snapshot(), `"no-8080"`) {
		t.Fatalf("snapshot after enroll: v%d %q", e.currentVersion(), e.Snapshot())
	}
	if _, err := os.Stat(e.statePath(fileSnapshot)); err != nil {
		t.Fatalf("snapshot not persisted: %v", err)
	}
	if fc.clientCert("/v1/snapshot") == nil {
		t.Fatal("snapshot not fetched over mTLS")
	}
}

// A failing renewal never tears down the tunnel while the current certificate is valid:
// it is reported, retried with backoff, and the tunnel stays connected.
func TestRenewalFailureKeepsTunnel(t *testing.T) {
	fc := newFakeCloud(t)
	fc.certFrom, fc.certTo = -90*time.Minute, 30*time.Minute // renewal due at start
	e, pl := enrolled(t, fc)
	e.renewRetryMin = 20 * time.Millisecond
	fc.mu.Lock()
	fc.renewFail = 1 << 30 // always fails
	fc.mu.Unlock()
	if err := e.RenewNow(context.Background()); err == nil {
		t.Fatal("RenewNow succeeded against a failing CA")
	}
	if err := e.StartDevice(tuntest.NewChannelTUN().TUN(), "wifi"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	waitUntil(t, "renew retries", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return fc.renewFail < 1<<30-3 // the loop retried several times
	})
	if !pl.has(`error {"message":"renew: http 500`) {
		t.Fatal("renew failure not reported")
	}
	if st := status(t, e); st.State != StateConnected || e.running.Load() == nil {
		t.Fatalf("tunnel affected by renewal failure: %+v", st)
	}
}
