package mobile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/dnsfilter"
	"github.com/yuky2020/opensase/pkg/firewall"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Engine states reported by Status and "state" events.
const (
	StateStopped    = "stopped"
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateError      = "error"
)

// pendingSessionMaxAge bounds how long a session from TunnelConfig may wait for Start.
const pendingSessionMaxAge = 2 * time.Minute

// Tunnel liveness (review #5): with persistent keepalive, wireguard-go re-handshakes about
// every 2 minutes, so a last handshake older than 3 minutes means the tunnel is dead.
const (
	defaultLivenessTimeout  = 3 * time.Minute
	defaultLivenessInterval = 30 * time.Second
)

// Edge failover (issue #70). When nothing came through the tunnel for probeIdle, the client
// asks the Edge whether its session is still live, every probeInterval. A missing session
// (Edge restarted) means a new session at once; probeFailures unanswered probes mean the
// Edge is down and the client moves to the next Edge. Together this keeps the failover
// under 30 seconds. On a backup Edge, the client returns to the first Edge of the list after
// failbackAfter of stable service.
const (
	defaultProbeInterval = 10 * time.Second
	defaultProbeIdle     = 10 * time.Second
	defaultProbeTimeout  = 4 * time.Second
	defaultFailbackAfter = 5 * time.Minute
	probeFailures        = 2
)

// Engine is the Client core. See mobile/api.go for the method contract.
type Engine struct {
	stateDir string
	platform Platform
	protect  protectFunc
	hosts    *hostCache
	log      *slog.Logger

	opMu    sync.Mutex // serialises Enroll/Unenroll/TunnelConfig/Start/Stop
	en      atomic.Pointer[identity]
	running atomic.Pointer[runState]
	lastFW  atomic.Pointer[firewall.FilteringTUN]
	lastDNS atomic.Pointer[dnsfilter.Interceptor]
	network atomic.Pointer[policy.NetworkType]
	pending *session // from TunnelConfig, consumed by Start; guarded by opMu
	pendAt  time.Time

	snapMu      sync.RWMutex
	snap        *policy.Snapshot
	snapPayload []byte
	compiled    *policy.Compiled

	statusMu sync.Mutex
	state    string
	lastErr  string

	renewMu sync.Mutex // serialises certificate renewals

	// Options for tests and the headless Linux client.
	flowInterval     time.Duration
	pollWait         int // seconds
	statsInterval    time.Duration
	livenessTimeout  time.Duration
	livenessInterval time.Duration
	renewRetryMin    time.Duration
	probeInterval    time.Duration
	probeIdle        time.Duration
	probeTimeout     time.Duration
	failbackAfter    time.Duration
}

// identity is the enrolled device plus its Control Plane client. Every cp connection must
// prove spiffe://opensase/controlplane; tr is swapped when the certificate is renewed.
type identity struct {
	*enrollment
	cp    *http.Client
	tr    *swapTransport
	keys  atomic.Pointer[map[string]ed25519.PublicKey] // snapshot keys; refreshed from /v1/pki/ca
	edges atomic.Pointer[[]api.EdgeInfo]               // refreshed, ordered Edge list (issue #71); nil: resp.Edges
}

// NewEngine opens (or creates) stateDir and loads any previous enrollment and snapshot.
func NewEngine(stateDir string, platform Platform) (*Engine, error) {
	if stateDir == "" {
		return nil, errors.New("mobile: stateDir is required")
	}
	if err := os.MkdirAll(stateDir, stateDirMode); err != nil {
		return nil, err
	}
	if err := restrictPath(stateDir, true); err != nil {
		return nil, err
	}
	e := &Engine{
		stateDir:      stateDir,
		platform:      platform,
		state:         StateStopped,
		flowInterval:  15 * time.Second,
		pollWait:      30,
		statsInterval: 5 * time.Second,

		livenessTimeout:  defaultLivenessTimeout,
		livenessInterval: defaultLivenessInterval,
		renewRetryMin:    defaultMinRenewRetry,
		probeInterval:    defaultProbeInterval,
		probeIdle:        defaultProbeIdle,
		probeTimeout:     defaultProbeTimeout,
		failbackAfter:    defaultFailbackAfter,
	}
	if platform != nil {
		e.protect = platform.Protect
	}
	e.hosts = newHostCache(e.protect)
	e.log = slog.New(&eventHandler{emit: e.emitRaw, level: slog.LevelInfo})
	nt := policy.NetworkUnknown
	e.network.Store(&nt)

	en, err := loadEnrollment(stateDir)
	switch {
	case err == nil:
		e.setIdentity(en)
		if err := e.loadCachedSnapshot(); err != nil {
			e.log.Warn("cached snapshot rejected", "err", err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	return e, nil
}

// SetLogHandler sends engine logs to h as well as to Platform.OnEvent("log"). Go-only
// (not exported by gomobile); used by cmd/opensase-client.
func (e *Engine) SetLogHandler(h slog.Handler) {
	e.log = slog.New(&eventHandler{emit: e.emitRaw, next: h, level: slog.LevelInfo})
}

func (e *Engine) setIdentity(en *enrollment) {
	if en == nil {
		e.en.Store(nil)
		return
	}
	tr := &swapTransport{}
	tr.swap(pqTransport(mtlsConfig(en, pki.ServerControlPlane, ""), e.protect, e.hosts, true))
	id := &identity{enrollment: en, cp: &http.Client{Transport: tr}, tr: tr}
	keys := snapshotKeys(en.resp.SnapshotKeys)
	id.keys.Store(&keys)
	e.loadEdges(id)
	e.en.Store(id)
}

// IsEnrolled reports whether the device has an identity.
func (e *Engine) IsEnrolled() bool { return e.en.Load() != nil }

func platformName() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "android", "linux", "windows", "ios":
		return runtime.GOOS
	}
	return "linux"
}

// Enroll generates the device key and CSR, calls POST /v1/enroll and stores the identity.
func (e *Engine) Enroll(controlURL, provisioningKey, deviceName string) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.IsEnrolled() {
		return errors.New("mobile: already enrolled")
	}
	u, err := url.Parse(controlURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("mobile: control URL must be https://host[:port]")
	}
	bootstrapPEM, err := readStateFile(e.stateDir, fileBootstrapCA)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tlsCfg, err := bootstrapTLS(u, bootstrapPEM)
	if err != nil {
		return err
	}
	u.Fragment, u.RawFragment = "", "" // a #sha256= pin is only used for the bootstrap
	base := strings.TrimRight(u.String(), "/")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceName},
	}, key)
	if err != nil {
		return err
	}
	req := api.EnrollRequest{
		ProvisioningKey: provisioningKey,
		DeviceName:      deviceName,
		Platform:        platformName(),
		CSRPEM:          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	}
	client := &http.Client{Transport: pqTransport(tlsCfg, e.protect, e.hosts, false), Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	var resp api.EnrollResponse
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := doJSON(ctx, client, http.MethodPost, base+"/v1/enroll", nil, &req, &resp); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := checkEnrollResponse(&resp, key); err != nil {
		return err
	}
	if resp.ControlURL == "" {
		resp.ControlURL = base
	}
	if err := saveEnrollment(e.stateDir, key, &resp); err != nil {
		return err
	}
	en, err := loadEnrollment(e.stateDir)
	if err != nil {
		return err
	}
	e.setIdentity(en)
	id := e.en.Load()
	e.log.Info("enrolled", "tenant", resp.TenantID, "device", resp.DeviceID, "edges", len(resp.Edges))
	// Fetch, verify and persist the first snapshot now, so the policy screens are filled
	// before the first connect. Best effort: the snapshot loop retries after Start.
	sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer scancel()
	if err := e.pollSnapshot(sctx, id, 0); err != nil {
		e.log.Warn("initial snapshot fetch failed", "err", err)
	}
	return nil
}

// checkEnrollResponse verifies that the issued certificate is for our key and chains to
// the returned CA, and that the response is usable.
func checkEnrollResponse(r *api.EnrollResponse, key *ecdsa.PrivateKey) error {
	blk, _ := pem.Decode([]byte(r.CertificatePEM))
	if blk == nil {
		return errors.New("enroll: no certificate in response")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("enroll: certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("enroll: certificate is not for the device key")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(r.CAPEM)) {
		return errors.New("enroll: no CA in response")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("enroll: certificate does not chain to the tenant CA: %w", err)
	}
	if r.DeviceID == "" || r.TenantID == "" {
		return errors.New("enroll: response without device or tenant id")
	}
	if len(r.Edges) == 0 {
		return errors.New("enroll: no Edge in response")
	}
	if len(snapshotKeys(r.SnapshotKeys)) == 0 {
		return errors.New("enroll: no usable snapshot signing key")
	}
	return nil
}

// Unenroll stops the engine and deletes the identity and cached policy.
func (e *Engine) Unenroll() error {
	e.Stop()
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if id := e.en.Load(); id != nil {
		id.cp.CloseIdleConnections()
	}
	e.setIdentity(nil)
	e.snapMu.Lock()
	e.snap, e.snapPayload, e.compiled = nil, nil, nil
	e.snapMu.Unlock()
	return removeState(e.stateDir)
}

// SetNetworkType updates the network used by per-app, per-network rules.
func (e *Engine) SetNetworkType(networkType string) {
	nt := parseNetwork(networkType)
	e.network.Store(&nt)
	if rs := e.running.Load(); rs != nil {
		rs.fw.SetNetwork(nt)
	}
}

func parseNetwork(s string) policy.NetworkType {
	switch nt := policy.NetworkType(strings.ToLower(s)); nt {
	case policy.NetworkWiFi, policy.NetworkCellular, policy.NetworkRoaming, policy.NetworkEthernet:
		return nt
	}
	return policy.NetworkUnknown
}

// tunnelConfigJSON is the TunnelConfig result.
type tunnelConfigJSON struct {
	IPv4 string   `json:"ipv4"`
	IPv6 string   `json:"ipv6"`
	DNS  []string `json:"dns"`
	MTU  int      `json:"mtu"`
}

func tunnelConfig(s *session) string {
	mtu := s.resp.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	dns := s.resp.DNSServers
	if dns == nil {
		dns = []string{}
	}
	b, _ := json.Marshal(tunnelConfigJSON{IPv4: s.resp.TunnelIPv4, IPv6: s.resp.TunnelIPv6, DNS: dns, MTU: mtu})
	return string(b)
}

// TunnelConfig performs session setup with the Edge and returns the interface config.
func (e *Engine) TunnelConfig() (string, error) {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if rs := e.running.Load(); rs != nil {
		rs.sessMu.Lock()
		defer rs.sessMu.Unlock()
		return tunnelConfig(rs.sess), nil
	}
	id := e.en.Load()
	if id == nil {
		return "", errors.New("mobile: not enrolled")
	}
	if err := checkCertValid(id.enrollment, time.Now()); err != nil {
		e.setState(StateError, err.Error())
		return "", err
	}
	e.setState(StateConnecting, "")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	s, err := e.newSession(ctx, id, "")
	if err != nil {
		e.setState(StateError, err.Error())
		return "", err
	}
	if e.pending != nil {
		e.pending.wipe()
	}
	e.pending, e.pendAt = s, time.Now()
	return tunnelConfig(s), nil
}

// newSession tries each Edge in order. avoid (an Edge ID, or "") is tried last: it is the
// Edge that just stopped answering (issue #70).
func (e *Engine) newSession(ctx context.Context, id *identity, avoid string) (*session, error) {
	list := id.edgeList()
	edges := make([]api.EdgeInfo, 0, len(list))
	var last []api.EdgeInfo
	for _, ed := range list {
		if ed.ID == avoid {
			last = append(last, ed)
			continue
		}
		edges = append(edges, ed)
	}
	edges = append(edges, last...)
	var errs []error
	for _, edge := range edges {
		s, err := e.setupSession(ctx, id.enrollment, edge, nil)
		if err == nil {
			e.log.Info("session established", "edge", edge.ID, "epoch", s.resp.Epoch, "kex", s.kex)
			return s, nil
		}
		e.log.Warn("session setup failed", "edge", edge.ID, "err", err)
		errs = append(errs, fmt.Errorf("%s: %w", edge.ID, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// Start takes ownership of tunFd and starts the tunnel.
func (e *Engine) Start(tunFd int, networkType string) error {
	dev, err := openTUN(tunFd)
	if err != nil {
		return fmt.Errorf("mobile: open TUN: %w", err)
	}
	if err := e.StartDevice(dev, networkType); err != nil {
		return err
	}
	return nil
}

// runState is one running tunnel.
type runState struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	dev    *device.Device
	fw     *firewall.FilteringTUN
	dns    *dnsfilter.Interceptor
	id     *identity

	sessMu        sync.Mutex
	sess          *session
	started       time.Time
	sessSince     time.Time    // when sess was fully configured (liveness grace period)
	probeClient   *http.Client // keeps the session probe connection (issue #70)
	probeEdge     string       // Edge of probeClient
	failbackTried time.Time

	pendingFlows []api.FlowRecord // owned by the flow loop
	stale        atomic.Bool
}

// StartDevice is Start with any tun.Device (Go-only: tests and the headless Linux client).
// It takes ownership of dev and closes it on failure.
func (e *Engine) StartDevice(dev tun.Device, networkType string) (err error) {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	defer func() {
		if err != nil {
			e.setState(StateError, err.Error())
		}
	}()
	if e.running.Load() != nil {
		dev.Close()
		return errors.New("mobile: already started")
	}
	id := e.en.Load()
	if id == nil {
		dev.Close()
		return errors.New("mobile: not enrolled")
	}
	if err := checkCertValid(id.enrollment, time.Now()); err != nil {
		dev.Close()
		return err
	}
	e.SetNetworkType(networkType)
	e.setState(StateConnecting, "")

	ctx, cancel := context.WithCancel(context.Background())
	sess := e.pending
	e.pending = nil
	if sess != nil && time.Since(e.pendAt) > pendingSessionMaxAge {
		sess.wipe()
		sess = nil
	}
	if sess == nil {
		sctx, scancel := context.WithTimeout(ctx, 45*time.Second)
		sess, err = e.newSession(sctx, id, "")
		scancel()
		if err != nil {
			cancel()
			dev.Close()
			return err
		}
	}

	now := time.Now()
	rs := &runState{ctx: ctx, cancel: cancel, id: id, sess: sess, started: now, sessSince: now}
	rs.dns = dnsfilter.New(dnsfilter.Config{})
	var dnsServers []netip.Addr
	for _, s := range sess.resp.DNSServers {
		if a, perr := netip.ParseAddr(s); perr == nil {
			dnsServers = append(dnsServers, a)
		}
	}
	var resolver firewall.UIDResolver
	if e.platform != nil {
		resolver = firewall.NewCachingResolver(platformResolver{e.platform}, time.Minute, 4096)
	}
	rs.fw, err = firewall.New(firewall.Config{
		Inner:      dev,
		Resolver:   resolver,
		Decider:    cloudDecider{e: e, id: id},
		DNS:        rs.dns,
		DNSServers: dnsServers,
		DeviceID:   id.resp.DeviceID,
		OnEvent:    e.emitRaw,
		Logger:     e.log.With("component", "firewall"),
	})
	if err != nil {
		cancel()
		dev.Close()
		sess.wipe()
		return err
	}
	rs.fw.SetNetwork(*e.network.Load())
	e.snapMu.RLock()
	if e.compiled != nil {
		rs.fw.SetPolicy(e.compiled, e.snap.Firewall.DefaultAction)
	}
	e.snapMu.RUnlock()

	wgLog := e.log.With("component", "wireguard")
	rs.dev = device.NewDevice(rs.fw, newProtectedBind(e.protect, wgLog), &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { wgLog.Warn(fmt.Sprintf(format, args...)) },
	})
	cfg := uapiFull(sess)
	err = rs.dev.IpcSetOperation(bytes.NewReader(cfg))
	clear(cfg)
	if err == nil {
		err = rs.dev.Up()
	}
	if err != nil {
		cancel()
		rs.dev.Close() // closes the bind and rs.fw, which closes dev
		sess.wipe()
		return fmt.Errorf("mobile: configure WireGuard: %w", err)
	}
	e.running.Store(rs)
	e.lastFW.Store(rs.fw)
	e.lastDNS.Store(rs.dns)

	rs.wg.Add(6)
	go e.edgesLoop(rs)
	go e.snapshotLoop(rs)
	go e.flowLoop(rs)
	go e.sessionLoop(rs)
	go e.statsLoop(rs)
	go e.renewLoop(rs)
	e.setState(StateConnected, "")
	e.log.Info("tunnel started", "edge", sess.edge.ID, "network", string(*e.network.Load()))
	return nil
}

// Stop stops the tunnel, uploads the remaining flow records and wipes session keys.
func (e *Engine) Stop() {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.pending != nil {
		e.pending.wipe()
		e.pending = nil
	}
	rs := e.running.Swap(nil)
	if rs == nil {
		return
	}
	rs.cancel()
	rs.wg.Wait()
	rs.dev.Close()
	rs.fw.Flush()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := e.uploadFlows(ctx, rs); err != nil {
		e.log.Debug("final flow upload failed", "err", err)
	}
	cancel()
	rs.sessMu.Lock()
	rs.closeProbeLocked()
	rs.sess.wipe()
	rs.sessMu.Unlock()
	e.setState(StateStopped, "")
	e.log.Info("tunnel stopped")
}

// Snapshot returns the current snapshot JSON (the signed payload) or "".
func (e *Engine) Snapshot() string {
	e.snapMu.RLock()
	defer e.snapMu.RUnlock()
	return string(e.snapPayload)
}

// SetUserRules replaces the user's policy layer (api.UserRules JSON) via PUT /v1/self/rules.
func (e *Engine) SetUserRules(js string) error {
	var ur api.UserRules
	dec := json.NewDecoder(strings.NewReader(js))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ur); err != nil {
		return fmt.Errorf("mobile: user rules: %w", err)
	}
	return e.putUserRules(&ur)
}

func (e *Engine) putUserRules(ur *api.UserRules) error {
	id := e.en.Load()
	if id == nil {
		return errors.New("mobile: not enrolled")
	}
	for i := range ur.Rules {
		switch ur.Rules[i].Source {
		case "":
			ur.Rules[i].Source = policy.SourceUser
		case policy.SourceUser:
		default:
			return fmt.Errorf("mobile: rule %q: user rules must have source %q", ur.Rules[i].ID, policy.SourceUser)
		}
	}
	if ur.Rules == nil {
		ur.Rules = []policy.Rule{}
	}
	if ur.Apps == nil {
		ur.Apps = map[string]policy.AppPolicy{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var env policy.Envelope
	if _, err := doJSON(ctx, id.cp, http.MethodPut, joinURL(id.resp.ControlURL, "/v1/self/rules"), nil, ur, &env); err != nil {
		return fmt.Errorf("mobile: set user rules: %w", err)
	}
	if b, err := json.Marshal(ur); err == nil {
		if err := writeFileAtomic(e.stateDir, fileUserRules, b); err != nil {
			e.log.Warn("persist user rules", "err", err)
		}
	}
	_, err := e.applyEnvelope(ctx, id, &env)
	return err
}

// SetAppPolicy sets one app's per-network verdicts ("allow","block","ask" or "" to unset)
// in the user layer.
func (e *Engine) SetAppPolicy(pkg string, wifi, cellular, roaming string) error {
	if pkg == "" {
		return errors.New("mobile: empty package name")
	}
	ap := policy.AppPolicy{WiFi: policy.Action(wifi), Cellular: policy.Action(cellular), Roaming: policy.Action(roaming)}
	for _, a := range []policy.Action{ap.WiFi, ap.Cellular, ap.Roaming} {
		switch a {
		case "", policy.ActionAllow, policy.ActionBlock, policy.ActionAsk:
		default:
			return fmt.Errorf("mobile: invalid action %q", a)
		}
	}
	ur := e.currentUserRules()
	if ap == (policy.AppPolicy{}) {
		delete(ur.Apps, pkg)
	} else {
		ur.Apps[pkg] = ap
	}
	return e.putUserRules(ur)
}

// currentUserRules returns the last user layer sent from this device, or the user rules
// visible in the snapshot.
//
// CONTRACT-CHANGE-REQUEST: there is no GET /v1/self/rules, and Snapshot.Firewall.Apps
// merges tenant and user app policies, so a fresh device cannot reconstruct the user layer
// exactly. Proposed: GET /v1/self/rules -> api.UserRules.
func (e *Engine) currentUserRules() *api.UserRules {
	ur := &api.UserRules{}
	if b, err := readStateFile(e.stateDir, fileUserRules); err == nil && json.Unmarshal(b, ur) == nil {
		if ur.Apps == nil {
			ur.Apps = map[string]policy.AppPolicy{}
		}
		return ur
	}
	ur.Apps = map[string]policy.AppPolicy{}
	e.snapMu.RLock()
	defer e.snapMu.RUnlock()
	if e.snap != nil {
		for _, r := range e.snap.Firewall.Rules {
			if r.Source == policy.SourceUser {
				ur.Rules = append(ur.Rules, r)
			}
		}
		for k, v := range e.snap.Firewall.Apps {
			ur.Apps[k] = v
		}
	}
	return ur
}

// RecentFlows returns JSON []api.FlowRecord, newest first.
func (e *Engine) RecentFlows(limit int) string {
	recs := []api.FlowRecord{}
	if fw := e.lastFW.Load(); fw != nil {
		recs = fw.RecentFlows(limit)
	}
	b, _ := json.Marshal(recs)
	return string(b)
}

// appStatJSON is one AppStats element (firewall counters plus DNS counters).
type appStatJSON struct {
	firewall.AppStat
	DNSQueries uint64 `json:"dnsQueries"`
	DNSBlocked uint64 `json:"dnsBlocked"`
}

// AppStats returns per-app traffic statistics JSON.
func (e *Engine) AppStats() string {
	out := []appStatJSON{}
	idx := map[string]int{}
	if fw := e.lastFW.Load(); fw != nil {
		for _, s := range fw.AppStats() {
			idx[s.App] = len(out)
			out = append(out, appStatJSON{AppStat: s})
		}
	}
	if d := e.lastDNS.Load(); d != nil {
		for _, s := range d.Stats() {
			i, ok := idx[s.App]
			if !ok {
				i = len(out)
				out = append(out, appStatJSON{AppStat: firewall.AppStat{App: s.App}})
			}
			out[i].DNSQueries, out[i].DNSBlocked = s.Queries, s.Blocked
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// statusJSON is the Status result.
type statusJSON struct {
	State           string `json:"state"`
	Error           string `json:"error,omitempty"`
	Enrolled        bool   `json:"enrolled"`
	DeviceID        string `json:"deviceId,omitempty"`
	Edge            string `json:"edge,omitempty"`
	Network         string `json:"network"`
	SnapshotVersion uint64 `json:"snapshotVersion"`
	Stale           bool   `json:"stale"`
	PQ              bool   `json:"pq"`
	Kex             string `json:"kex,omitempty"`
	Epoch           uint64 `json:"epoch"`
	LastHandshake   int64  `json:"lastHandshake,omitempty"` // unix seconds
	CertExpiresAt   string `json:"certExpiresAt,omitempty"` // device certificate NotAfter, RFC 3339 UTC
	TxBytes         uint64 `json:"txBytes"`
	RxBytes         uint64 `json:"rxBytes"`
}

// Status returns the engine status JSON. "pq" is true and "kex" is set only when the live
// session-setup connection was verified to use X25519MLKEM768.
func (e *Engine) Status() string {
	st := statusJSON{Network: string(*e.network.Load())}
	e.statusMu.Lock()
	st.State, st.Error = e.state, e.lastErr
	e.statusMu.Unlock()
	now := time.Now()
	if id := e.en.Load(); id != nil {
		st.Enrolled, st.DeviceID = true, id.resp.DeviceID
		st.CertExpiresAt = id.leaf().NotAfter.UTC().Format(time.RFC3339)
		if checkCertValid(id.enrollment, now) != nil {
			st.State, st.Error = StateError, errCertExpired.Error()
		}
	}
	e.snapMu.RLock()
	if e.snap != nil {
		st.SnapshotVersion = e.snap.Version
		st.Stale = e.snap.Stale(time.Now())
	}
	e.snapMu.RUnlock()
	if rs := e.running.Load(); rs != nil {
		rs.sessMu.Lock()
		st.Edge, st.Epoch = rs.sess.edge.ID, rs.sess.resp.Epoch
		if rs.sess.pq && rs.sess.kex == "X25519MLKEM768" {
			st.PQ, st.Kex = true, rs.sess.kex
		}
		rs.sessMu.Unlock()
		st.LastHandshake, st.TxBytes, st.RxBytes = peerStats(rs.dev)
		// Never report "connected" for a dead tunnel, even before the session loop notices.
		if st.State == StateConnected {
			if age := e.handshakeAge(rs, st.LastHandshake, now); age > e.livenessTimeout {
				st.State, st.Error = StateConnecting, fmt.Sprintf("no WireGuard handshake for %s", age.Round(time.Second))
			}
		}
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// peerStats reads handshake time and byte counters from wireguard-go's UAPI.
func peerStats(dev *device.Device) (hs int64, tx, rx uint64) {
	var buf bytes.Buffer
	if err := dev.IpcGetOperation(&buf); err != nil {
		return
	}
	defer clear(buf.Bytes()) // contains the private key and PSK: never convert to string
	for line := range bytes.Lines(buf.Bytes()) {
		k, v, ok := bytes.Cut(bytes.TrimSpace(line), []byte("="))
		if !ok {
			continue
		}
		switch string(k) {
		case "last_handshake_time_sec":
			hs, _ = strconv.ParseInt(string(v), 10, 64)
		case "tx_bytes":
			tx, _ = strconv.ParseUint(string(v), 10, 64)
		case "rx_bytes":
			rx, _ = strconv.ParseUint(string(v), 10, 64)
		}
	}
	return
}

func (e *Engine) setState(state, errMsg string) {
	e.statusMu.Lock()
	changed := e.state != state || e.lastErr != errMsg
	e.state, e.lastErr = state, errMsg
	e.statusMu.Unlock()
	if changed {
		e.emit("state", map[string]any{"state": state, "error": errMsg})
	}
}

func (e *Engine) emitRaw(kind, payload string) {
	if e.platform != nil {
		e.platform.OnEvent(kind, payload)
	}
}

func (e *Engine) emit(kind string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	e.emitRaw(kind, string(b))
}

func (e *Engine) emitError(op string, err error) {
	e.emit("error", map[string]string{"op": op, "message": err.Error()})
}

// statePath is used by tests.
func (e *Engine) statePath(name string) string { return filepath.Join(e.stateDir, name) }

// BypassHosts returns the host names or IPs the core talks to outside the tunnel (Control
// Plane, Edge session URLs and WireGuard endpoints). Go-only: the headless Linux client adds
// host routes for them via the physical gateway; Android uses VpnService.protect instead.
func (e *Engine) BypassHosts() []string {
	id := e.en.Load()
	if id == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if u, err := url.Parse(id.resp.ControlURL); err == nil {
		add(u.Hostname())
	}
	for _, ed := range id.edgeList() {
		if u, err := url.Parse(ed.SessionURL); err == nil {
			add(u.Hostname())
		}
		if h, _, err := net.SplitHostPort(ed.WGEndpoint); err == nil {
			add(h)
		}
	}
	if rs := e.running.Load(); rs != nil {
		rs.sessMu.Lock()
		if h, _, err := net.SplitHostPort(rs.sess.endpoint); err == nil {
			add(h)
		}
		rs.sessMu.Unlock()
	}
	return out
}
