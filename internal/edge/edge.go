package edge

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/pki"
)

// Config configures an Edge.
type Config struct {
	ControlURL   string            // https://controlplane:9443
	Root         *x509.Certificate // provider root CA (verifies the Control Plane and anchors tenant CAs)
	Cert         tls.Certificate   // edge certificate (server for sessions, client for the Control Plane)
	WGPrivateKey []byte            // 32-byte Curve25519 key
	ListenAddr   string            // session server, default ":8443"
	OpsListen    string            // /metrics, /healthz, /readyz over plain HTTP (issue #73); "" off
	WGPort       int               // default 51820
	WGEndpoint   string            // host:port returned to clients, default "edge:51820"
	TUNName      string            // default "wg0"
	MTU          int               // default 1280
	Upstream     string            // default "1.1.1.1:53"
	RotateAfter  time.Duration     // PSK epoch length, default 10m
	PeerRefresh  time.Duration     // default 10s
	FlowFlush    time.Duration     // default 5s
	// Built-in deny list (security review #3): always link-local, loopback, multicast and the
	// Edge's own addresses (LocalAddrs); private ranges unless AllowPrivate; plus DenyCIDRs.
	DenyCIDRs    []netip.Prefix
	AllowPrivate bool
	LocalAddrs   []netip.Addr // Edge interface addresses; Run fills them from the host
	// AllowDoH disables the DNS-over-HTTPS endpoint blocklist (plain DNS and DoT to other
	// resolvers stay blocked).
	AllowDoH bool
	// ZTNA (ADR-0013): ZTNAListen receives the TCP connections the kernel REDIRECTs from the
	// tunnel to SyntheticPrefix (default "0.0.0.0:15001"); BrokerListen accepts Connector
	// connections (default ":8444"). "off" disables either.
	ZTNAListen   string
	BrokerListen string
	// Private Edge (ADR-0014). TenantID != "" makes the Edge single-tenant: it trusts only
	// that tenant's CA and drops other tenants from the peer feed. StateDir caches the last
	// good Control Plane state so the Edge can start and keep enforcing while the Control
	// Plane is unreachable. FlowLogPath appends every flow record to a local JSONL file.
	TenantID    string
	StateDir    string
	FlowLogPath string
	// TLS inspection (ADR-0018): InspectListen receives the tunnel TCP to ports 80 and 443
	// that the kernel REDIRECTs to it ("off", the default, disables inspection on this Edge).
	// InspectRoots verifies upstream servers (nil = the system roots).
	InspectListen string
	InspectRoots  *x509.CertPool
	// ClamdAddr is the ClamAV daemon that scans for malware (ADR-0020), host:port. Empty:
	// content of tenants with malware scanning is unscanned.
	ClamdAddr string
	// ICAPURL is an ICAP service (icap://host[:port]/service, RFC 3507) that scans for
	// malware instead of clamd (issue #25).
	ICAPURL string
	// OCRURL is the ocrd service that reads the text of images for DLP (ADR-0024), for
	// example http://ocr:8090. Empty: images carry no text.
	OCRURL string
	// SkipIPForwardCheck skips the Linux net.ipv4.ip_forward check (e.g. for testing).
	SkipIPForwardCheck bool
	Logger             *slog.Logger
}

func (c *Config) defaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8443"
	}
	if c.WGPort == 0 {
		c.WGPort = 51820
	}
	if c.WGEndpoint == "" {
		c.WGEndpoint = "edge:" + strconv.Itoa(c.WGPort)
	}
	if c.TUNName == "" {
		c.TUNName = "wg0"
	}
	if c.MTU == 0 {
		c.MTU = 1280
	}
	if c.Upstream == "" {
		c.Upstream = "1.1.1.1:53"
	}
	if c.RotateAfter <= 0 {
		c.RotateAfter = 10 * time.Minute
	}
	if c.PeerRefresh <= 0 {
		c.PeerRefresh = 10 * time.Second
	}
	if c.FlowFlush <= 0 {
		c.FlowFlush = 5 * time.Second
	}
	if c.ZTNAListen == "" {
		c.ZTNAListen = "0.0.0.0:15001"
	}
	if c.BrokerListen == "" {
		c.BrokerListen = ":8444"
	}
	if c.InspectListen == "" {
		c.InspectListen = listenOff
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// listenOff is the Config value that disables a ZTNA listener.
const listenOff = "off"

// Edge is a Edge.
type Edge struct {
	cfg   Config
	log   *slog.Logger
	ctx   context.Context
	cp    controlPlane
	wg    wgConfigurer
	wgPub [32]byte
	ipv6  bool

	reg           *registry
	trust         atomic.Pointer[trust]
	ct            *conntrack
	dec           *decider
	snoop         *snoop
	flows         *flowLog
	guard         *guard
	synth         *synthMap              // synthetic PrivateApp addresses (ADR-0013)
	hub           *connectorHub          // live Connector broker connections
	insp          *inspector             // TLS inspection (ADR-0018); nil when InspectListen is off
	av            scanner                // malware scanner (ADR-0020)
	cats          atomic.Pointer[catSet] // web categories (ADR-0022)
	safe          *safeIPs               // addresses of the SafeSearch hostnames (ADR-0025)
	redir         *inspectRedirect       // per-device inspection redirect (issue #22); nil without inspection
	datasets      *datasetCache          // DLP datasets (ADR-0029)
	kroutes       *kernelRoutes          // kernel routes for routed workload subnets
	routesChanged bool                   // routes updated in the last peer sync (guarded by syncMu)
	// origDst recovers the pre-REDIRECT destination of a broker connection (tests stub it).
	origDst func(*net.TCPConn) (netip.AddrPort, error)

	syncMu   sync.Mutex
	lastSync atomic.Int64 // unix nanoseconds of the last peer sync attempt
	syncSF   singleflight.Group
	minSync  time.Duration // minSyncInterval; shorter in tests
	unknown  *negCache     // device IDs absent from a fresh peer feed (security review #7)
	stateSum [32]byte      // hash of the state last written to StateDir (guarded by syncMu)
	reportCh chan struct{} // wakes the session reporter

	obs        *edgeObserver // metrics (issue #73)
	lastSyncOK atomic.Int64  // unix nanoseconds of the last successful peer sync
	ready      atomic.Bool   // a peer feed or the cached state is installed
}

// On-demand peer sync limits (security review #7).
const (
	minSyncInterval = 5 * time.Second
	unknownHold     = 30 * time.Second
	maxUnknown      = 10000
)

func newEdge(ctx context.Context, cfg Config, cp controlPlane) (*Edge, error) {
	cfg.defaults()
	if cfg.Root == nil {
		return nil, errors.New("edge: root CA required")
	}
	k, err := ecdh.X25519().NewPrivateKey(cfg.WGPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("edge: wireguard key: %w", err)
	}
	e := &Edge{
		cfg: cfg, log: cfg.Logger, ctx: ctx, cp: cp,
		reg: newRegistry(), ct: newConntrack(), snoop: newSnoop(), flows: &flowLog{},
		guard:    newGuard(cfg.DenyCIDRs, cfg.LocalAddrs, cfg.AllowPrivate, !cfg.AllowDoH),
		unknown:  newNegCache(maxUnknown),
		reportCh: make(chan struct{}, 1),
		minSync:  minSyncInterval,
		synth:    newSynthMap(SyntheticPrefix, maxSynthEnts, synthIdle),
		hub:      newConnectorHub(cfg.Logger),
		origDst:  originalDst,
		kroutes:  newKernelRoutes("", cfg.Logger),
	}
	e.initMetrics()
	if cfg.InspectListen != listenOff {
		e.insp = newInspector(cp, cfg.InspectRoots)
		e.insp.onIssued = e.saveInspection
		e.redir = &inspectRedirect{ipt: runIPTables}
	}
	e.av = clamd{addr: cfg.ClamdAddr}
	if cfg.ICAPURL != "" {
		ic, err := newICAP(cfg.ICAPURL)
		if err != nil {
			return nil, err
		}
		e.av = ic
	}
	e.safe = newSafeIPs()
	e.datasets = newDatasetCache()
	copy(e.wgPub[:], k.PublicKey().Bytes())
	e.dec = newDecider(ctx, cp, cfg.Logger)
	if cfg.FlowLogPath != "" {
		e.flows.local = newLocalFlowLog(cfg.FlowLogPath, cfg.Logger)
	}
	return e, nil
}

// Run starts the Edge and blocks until ctx is cancelled. It needs CAP_NET_ADMIN and
// /dev/net/tun.
func Run(ctx context.Context, cfg Config) error {
	root := x509.NewCertPool()
	if cfg.Root != nil {
		root.AddCert(cfg.Root)
	}
	cp, err := newCPClient(cfg.ControlURL, root, cfg.Cert)
	if err != nil {
		return err
	}
	if cfg.LocalAddrs == nil {
		cfg.LocalAddrs = hostAddrs()
	}
	e, err := newEdge(ctx, cfg, cp)
	if err != nil {
		return err
	}
	return e.run(ctx)
}

func (e *Edge) run(ctx context.Context) error {
	// 1. Trust material and peers from the Control Plane (retry until it is up). A Private
	// Edge with a state cache starts from the cache instead of waiting (ADR-0014); the
	// periodic peer sync then catches up when the Control Plane is reachable.
	for first := true; ; first = false {
		err := e.syncPeers(ctx)
		if err == nil {
			break
		}
		if first && e.cfg.StateDir != "" {
			saved, lerr := e.loadState()
			if lerr == nil {
				e.ready.Store(true)
				e.log.Warn("control plane unreachable; enforcing cached state", "savedAt", saved, "err", err)
				break
			}
			if !errors.Is(lerr, fs.ErrNotExist) {
				e.log.Warn("state cache unusable", "err", lerr)
			}
		}
		e.log.Warn("waiting for control plane", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	// Cached web categories and inspection intermediates (issue #23): enforced from the start,
	// refreshed when the Control Plane answers.
	if e.cfg.StateDir != "" {
		if err := e.loadCategories(); err != nil && !errors.Is(err, fs.ErrNotExist) {
			e.log.Warn("web category cache unusable", "err", err)
		}
		e.loadInspection()
	}

	// 2. WireGuard on a kernel TUN wrapped by the policy filter.
	if !e.cfg.SkipIPForwardCheck {
		if err := checkIPForward(); err != nil {
			return fmt.Errorf("edge: %w", err)
		}
	}
	tdev, err := tun.CreateTUN(e.cfg.TUNName, e.cfg.MTU)
	if err != nil {
		return fmt.Errorf("edge: create TUN %s: %w", e.cfg.TUNName, err)
	}
	filter := newFilter(tdev, e)
	wglog := &wgdevice.Logger{
		Verbosef: func(f string, a ...any) { e.log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { e.log.Warn("wireguard: " + fmt.Sprintf(f, a...)) },
	}
	wgdev := wgdevice.NewDevice(filter, wgconn.NewDefaultBind(), wglog)
	defer wgdev.Close()
	var b bytes.Buffer
	b.Grow(256)
	b.WriteString("private_key=")
	writeHex(&b, e.cfg.WGPrivateKey)
	b.WriteString("\nlisten_port=" + strconv.Itoa(e.cfg.WGPort) + "\n")
	err = wgdev.IpcSetOperation(bytes.NewReader(b.Bytes()))
	clear(b.Bytes())
	if err != nil {
		return fmt.Errorf("edge: configure wireguard: %w", err)
	}
	if err := wgdev.Up(); err != nil {
		return fmt.Errorf("edge: wireguard up: %w", err)
	}
	e.wg = wgdev
	name, _ := tdev.Name()
	if err := e.configureInterface(ctx, name); err != nil {
		return err
	}

	// 3. DNS resolver on the tunnel addresses.
	rs := newResolver(e, e.cfg.Upstream)
	if err := rs.serveDNS(ctx, net.JoinHostPort(EdgeIPv4.String(), "53")); err != nil {
		return fmt.Errorf("edge: dns: %w", err)
	}
	if e.ipv6 {
		if err := rs.serveDNS(ctx, net.JoinHostPort(EdgeIPv6.String(), "53")); err != nil {
			e.log.Warn("ipv6 dns listener failed", "err", err)
		}
	}

	// 4. ZTNA broker (ADR-0013): redirected client connections and Connector connections.
	if err := e.startZTNA(ctx); err != nil {
		return err
	}
	if err := e.startInspect(ctx); err != nil {
		return err
	}

	// 5. Background loops.
	if e.flows.local != nil {
		go func() {
			if err := e.flows.local.run(ctx); err != nil {
				e.log.Error("local flow log disabled", "err", err)
			}
		}()
	}
	go e.serveOps(ctx)
	go e.peerLoop(ctx)
	go e.sweepLoop(ctx)
	go e.flowLoop(ctx)
	go e.reportLoop(ctx)
	go e.categoryLoop(ctx)
	go e.safeSearchLoop(ctx)
	go e.datasetLoop(ctx)

	// 6. Session-setup server.
	srv := &http.Server{
		Addr:              e.cfg.ListenAddr,
		Handler:           (&sessionServer{e: e}).handler(),
		TLSConfig:         e.sessionTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(e.log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	e.log.Info("built-in deny active", "prefixes", len(e.guard.deny), "allowPrivate", e.cfg.AllowPrivate, "dohBlock", e.guard.blockDoH)
	e.log.Info("edge ready", "tenant", e.cfg.TenantID, "stateDir", e.cfg.StateDir, "session", e.cfg.ListenAddr, "wg", e.cfg.WGPort, "tun", name, "mtu", e.cfg.MTU, "kex", "X25519MLKEM768")
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer fcancel()
		_ = e.flows.flush(fctx, e.cp)
		return nil
	case err := <-errc:
		return err
	}
}

// configureInterface assigns the Edge tunnel addresses with iproute2.
func (e *Edge) configureInterface(ctx context.Context, name string) error {
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput() //nolint:gosec // G204: fixed binary; args from Edge config and constants
		if err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, bytes.TrimSpace(out))
		}
		return nil
	}
	p4 := netip.PrefixFrom(EdgeIPv4, TunnelPrefix4.Bits())
	if err := run("addr", "replace", p4.String(), "dev", name); err != nil {
		return err
	}
	if err := run("link", "set", name, "mtu", strconv.Itoa(e.cfg.MTU), "up"); err != nil {
		return err
	}
	p6 := netip.PrefixFrom(EdgeIPv6, TunnelPrefix6.Bits())
	if err := run("-6", "addr", "replace", p6.String(), "dev", name, "nodad"); err != nil {
		e.log.Warn("ipv6 tunnel address not configured; continuing IPv4-only", "err", err)
	} else {
		e.ipv6 = true
	}
	if err := e.redirectZTNA(ctx, name); err != nil {
		return err
	}
	if err := e.redirectInspect(ctx, name); err != nil {
		return err
	}
	e.redirectDNS(ctx, name)
	if e.kroutes != nil {
		e.kroutes.tunName = name
		e.syncKernelRoutes(ctx)
	}
	return nil
}

// redirectZTNA installs the REDIRECT of tunnel TCP to SyntheticPrefix to the broker
// listener (ADR-0013). edge-entrypoint.sh installs the same rule as root before dropping
// privileges; here it is only checked and added if missing (needs NET_ADMIN).
func (e *Edge) redirectZTNA(ctx context.Context, tunName string) error {
	if e.cfg.ZTNAListen == listenOff {
		return nil
	}
	_, port, err := net.SplitHostPort(e.cfg.ZTNAListen)
	if err != nil {
		return fmt.Errorf("edge: -ztna-listen %q: %w", e.cfg.ZTNAListen, err)
	}
	e.ensureRedirect(ctx, "ztna", []string{"PREROUTING", "-i", tunName, "-d", SyntheticPrefix.String(), "-p", "tcp", "-j", "REDIRECT", "--to-ports", port})
	return nil
}

// redirectDNS sends tunnel DNS addressed to other resolvers to the Edge resolver (issue
// #63). The filter lets such packets through only for devices whose policy sets
// dns.redirectQueries; for the others it blocks them before they reach the kernel.
func (e *Edge) redirectDNS(ctx context.Context, tunName string) {
	for _, proto := range []string{"udp", "tcp"} {
		e.ensureRedirect(ctx, "dns-"+proto, []string{"PREROUTING", "-i", tunName, "-p", proto, "--dport", "53", "!", "-d", EdgeIPv4.String(), "-j", "DNAT", "--to-destination", EdgeIPv4.String() + ":53"})
	}
}

// redirectInspect installs the REDIRECT of tunnel TCP to ports 80 and 443 to the inspection
// listener (ADR-0018). It comes after the ZTNA rule, and excludes synthetic addresses anyway.
func (e *Edge) redirectInspect(ctx context.Context, tunName string) error {
	if e.cfg.InspectListen == listenOff {
		return nil
	}
	_, port, err := net.SplitHostPort(e.cfg.InspectListen)
	if err != nil {
		return fmt.Errorf("edge: -inspect-listen %q: %w", e.cfg.InspectListen, err)
	}
	if e.setupInspectRedirect(ctx, tunName) {
		e.reconcileInspect(ctx)
		return nil
	}
	e.ensureRedirect(ctx, "inspection", []string{"PREROUTING", "-i", tunName, "!", "-d", SyntheticPrefix.String(), "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "REDIRECT", "--to-ports", port})
	return nil
}

// ensureRedirect checks a nat rule and appends it if missing. Failure is logged, not fatal:
// the entrypoint may have installed it with privileges the Edge no longer has.
func (e *Edge) ensureRedirect(ctx context.Context, what string, rule []string) {
	ipt := func(op string) error {
		args := append([]string{"-w", "5", "-t", "nat", op}, rule...)
		out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput() //nolint:gosec // G204: fixed binary; args from Edge config and constants
		if err != nil {
			return fmt.Errorf("iptables %v: %w: %s", args, err, bytes.TrimSpace(out))
		}
		return nil
	}
	if ipt("-C") == nil {
		e.log.Info(what+" redirect present", "rule", strings.Join(rule, " "))
		return
	}
	if err := ipt("-A"); err != nil {
		e.log.Warn(what+" redirect not installed; unreachable unless the entrypoint added it", "err", err)
		return
	}
	e.log.Info(what+" redirect installed", "rule", strings.Join(rule, " "))
}

// startInspect starts the TLS inspection listener (ADR-0018).
func (e *Edge) startInspect(ctx context.Context) error {
	if e.insp == nil {
		return nil
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", e.cfg.InspectListen)
	if err != nil {
		return fmt.Errorf("edge: inspection listener: %w", err)
	}
	go e.serveInspect(ctx, ln)
	e.log.Info("web inspection listening", "addr", e.cfg.InspectListen)
	return nil
}

// startZTNA starts the broker listener and the Connector listener.
func (e *Edge) startZTNA(ctx context.Context) error {
	if e.cfg.ZTNAListen != listenOff {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", e.cfg.ZTNAListen)
		if err != nil {
			return fmt.Errorf("edge: ztna listener: %w", err)
		}
		go e.serveBroker(ctx, ln)
		e.log.Info("ztna broker listening", "addr", e.cfg.ZTNAListen, "prefix", SyntheticPrefix)
	}
	if e.cfg.BrokerListen != listenOff {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", e.cfg.BrokerListen)
		if err != nil {
			return fmt.Errorf("edge: connector listener: %w", err)
		}
		go e.serveConnectors(ctx, ln)
		e.log.Info("connector listener", "addr", e.cfg.BrokerListen, "alpn", api.BrokerALPN)
	}
	return nil
}

// ztnaName returns the name a synthetic address maps to, if the mapping belongs to d's
// tenant, and whether that name is a private app d is entitled to.
func (e *Edge) ztnaName(d *device, dst netip.Addr, now time.Time) (string, bool) {
	v := d.ztna.Load()
	if v == nil {
		return "", false
	}
	tenant, name, ok := e.synth.lookup(dst, now)
	if !ok || tenant != v.tenant {
		return "", false
	}
	_, entitled := v.app(name)
	return name, entitled
}

// syncPeers refreshes trust material and the device list from the Control Plane, and caches
// them in StateDir (ADR-0014).
func (e *Edge) syncPeers(ctx context.Context) error {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	e.lastSync.Store(time.Now().UnixNano())
	b, err := e.cp.PKIBundle(ctx)
	if err != nil {
		return fmt.Errorf("pki bundle: %w", err)
	}
	peers, err := e.cp.Peers(ctx)
	if err != nil {
		return fmt.Errorf("peers: %w", err)
	}
	peers = e.scopePeers(peers)
	if err := e.applyState(b, peers); err != nil {
		return err
	}
	if err := e.saveState(b, peers); err != nil {
		e.log.Warn("state cache not written", "err", err)
	}
	e.reconcileInspect(ctx)
	if e.routesChanged {
		e.syncKernelRoutes(ctx)
		e.routesChanged = false
	}
	e.lastSyncOK.Store(time.Now().UnixNano())
	e.ready.Store(true)
	return nil
}

// applyState installs a PKI bundle and peer feed. Caller holds syncMu.
func (e *Edge) applyState(b api.PKIBundle, peers api.EdgePeers) error {
	t, err := parseBundle(b, e.cfg.Root, e.cfg.TenantID)
	if err != nil {
		return err
	}
	e.trust.Store(t)
	res := e.reg.sync(peers, t.keys)
	e.hub.setAllowed(peers.Connectors, e.supersededGrace())
	e.reg.mu.Lock()
	for _, d := range res.removed {
		if e.reg.devices[d.id] == nil && e.wg != nil {
			e.removePeer(d)
		}
	}
	for _, d := range res.routesUpdated {
		if d.hasPeer && e.wg != nil {
			var buf bytes.Buffer
			writePeerAllowedIPs(&buf, d.wgPub, d)
			if err := e.wg.IpcSetOperation(bytes.NewReader(buf.Bytes())); err != nil {
				e.log.Error("update wireguard allowed ips", "device", d.id, "err", err)
			}
		}
	}
	e.expireSupersededLocked(time.Now())
	e.reg.mu.Unlock()
	routesChanged := len(res.routesUpdated) > 0
	for _, d := range res.removed {
		if len(d.routes) > 0 {
			routesChanged = true
			break
		}
	}
	e.routesChanged = routesChanged
	if res.updated > 0 || len(res.removed) > 0 || res.invalid > 0 || len(res.routesUpdated) > 0 {
		e.log.Info("peers synced", "devices", len(peers.Devices), "updated", res.updated, "removed", len(res.removed), "invalid", res.invalid, "routesUpdated", len(res.routesUpdated))
	}
	return nil
}

// allDeviceRoutes returns the routes of every enrolled device.
func (e *Edge) allDeviceRoutes() []netip.Prefix {
	e.reg.mu.Lock()
	defer e.reg.mu.Unlock()
	var routes []netip.Prefix
	for _, d := range e.reg.devices {
		routes = append(routes, d.routes...)
	}
	return routes
}

// syncKernelRoutes reconciles kernel routes on the TUN interface.
func (e *Edge) syncKernelRoutes(ctx context.Context) {
	if e.kroutes == nil || e.kroutes.tunName == "" || e.cfg.TUNName == "" {
		return
	}
	e.kroutes.sync(ctx, e.allDeviceRoutes())
}

func (e *Edge) peerLoop(ctx context.Context) {
	t := time.NewTicker(e.cfg.PeerRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.syncPeers(ctx); err != nil && ctx.Err() == nil {
				e.obs.syncFails.Inc()
				e.log.Warn("peer sync failed; enforcing last known snapshots", "err", err)
			}
		}
	}
}

// owner returns the device ID owning the source of an outbound flow key.
func (e *Edge) owner(k packet.FlowKey) string {
	if d := e.reg.byTunnelIP(k.Src); d != nil {
		return d.id
	}
	return ""
}

func (e *Edge) sweepLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.expireSessions(now)
			e.unknown.sweep(now)
			e.flows.add(e.ct.sweep(now, e.owner)...)
			e.dec.sweep(now)
			e.synth.sweep(now)
			e.snoop.sweep(now, func(a netip.Addr) bool { return e.reg.byTunnelIP(a) != nil })
		}
	}
}

func (e *Edge) flowLoop(ctx context.Context) {
	t := time.NewTicker(e.cfg.FlowFlush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.flows.flush(ctx, e.cp); err != nil && ctx.Err() == nil {
				e.log.Warn("flow upload failed", "pending", e.flows.pending(), "err", err)
			}
		}
	}
}

// hostAddrs returns the addresses of every host interface (the Edge's own addresses, which
// tunnel clients must not reach).
func hostAddrs() []netip.Addr {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := []netip.Addr{}
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// lookupDevice returns the registry entry of a device presenting a valid certificate. An
// unknown device triggers an on-demand peer sync, shared by concurrent callers
// (singleflight) and at most every minSyncInterval; a device still absent after a sync that
// started after this call is remembered as unknown for unknownHold, so repeated attempts
// with such a certificate cost nothing (security review #7).
func (e *Edge) lookupDevice(ctx context.Context, id string) *device {
	var d *device
	e.findAfterSync(ctx, id, func() bool { d = e.reg.get(id); return d != nil })
	return d
}

// connectorAllowed reports whether a connector is in the peer feed, with the same
// on-demand sync as lookupDevice, so a just-enrolled connector does not wait for the next
// periodic sync. Negative entries are keyed apart from device IDs.
// serial is the presented certificate's serial: only the connector's current certificate is
// accepted (ST-04).
func (e *Edge) connectorAllowed(ctx context.Context, id pki.Identity, serial string) bool {
	return e.findAfterSync(ctx, "connector:"+id.TenantID+"/"+id.ConnectorID+"/"+serial, func() bool {
		a, ok := e.hub.isAllowed(id)
		return ok && a.CertSerial != "" && a.CertSerial == serial
	})
}

// findAfterSync returns true as soon as found does, running at most two rate-limited
// on-demand peer syncs; key is remembered in the negative cache when a fresh sync did not
// help.
func (e *Edge) findAfterSync(ctx context.Context, key string, found func() bool) bool {
	if found() {
		return true
	}
	now := time.Now()
	if e.unknown.has(key, now) {
		return false
	}
	for range 2 {
		// The shared sync is detached from the caller's ctx on purpose: one caller giving up
		// must not cancel the sync other waiters joined. It is bound to the Edge lifetime.
		ch := e.syncSF.DoChan("peers", func() (any, error) { //nolint:contextcheck // shared singleflight sync uses e.ctx, not one caller's ctx
			if wait := e.minSync - time.Since(time.Unix(0, e.lastSync.Load())); wait > 0 {
				select {
				case <-time.After(wait):
				case <-e.ctx.Done():
					return time.Time{}, e.ctx.Err()
				}
			}
			started := time.Now()
			sctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
			defer cancel()
			return started, e.syncPeers(sctx)
		})
		var res singleflight.Result
		select {
		case res = <-ch:
		case <-ctx.Done():
			return false
		}
		if found() {
			return true
		}
		if res.Err != nil {
			e.log.WarnContext(ctx, "on-demand peer sync failed", "err", res.Err)
			return false
		}
		if started, _ := res.Val.(time.Time); !started.Before(now) {
			e.unknown.add(key, time.Now().Add(unknownHold))
			return false
		}
		// Joined a sync that started before this call: it may predate the enrollment.
	}
	return false
}

// supersededGrace is how long a session may keep running on a certificate the device has
// since renewed: one PSK rotation (when clients set up the session again with the new
// certificate) plus a minute.
func (e *Edge) supersededGrace() time.Duration { return e.cfg.RotateAfter + time.Minute }

// expireSupersededLocked removes peers whose session certificate is no longer the device's
// current one for longer than supersededGrace (ST-10): a stolen superseded certificate
// cannot keep a tunnel alive for the rest of its 24h lifetime. Caller holds reg.mu.
func (e *Edge) expireSupersededLocked(now time.Time) {
	for _, d := range e.reg.devices {
		cur := e.reg.serial(d.id)
		if !d.hasPeer || d.sessionSerial == "" || cur == "" || cur == d.sessionSerial {
			d.staleSince = time.Time{}
			continue
		}
		if d.staleSince.IsZero() {
			d.staleSince = now
			continue
		}
		if now.Sub(d.staleSince) > e.supersededGrace() && e.wg != nil {
			e.log.Info("session certificate superseded; removing peer", "device", d.id)
			e.removePeer(d)
			d.hasPeer, d.staleSince = false, time.Time{}
		}
	}
}

// expireSessions removes the WireGuard peer of every device whose session certificate has
// expired (security review #4). A session set up or rotated with a renewed certificate
// carries the new expiry, so it is not affected.
func (e *Edge) expireSessions(now time.Time) {
	r := e.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.devices {
		if !d.hasPeer || d.certNotAfter.IsZero() || !now.After(d.certNotAfter) {
			continue
		}
		if e.wg != nil {
			e.removePeer(d)
		}
		e.log.Info("session expired with its device certificate", "device", d.id, "notAfter", d.certNotAfter)
		d.hasPeer, d.sessionID, d.epoch, d.certNotAfter = false, "", 0, time.Time{}
	}
}

// liveSessions returns the IDs of devices with a WireGuard peer.
func (e *Edge) liveSessions() []string {
	r := e.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{}
	for id, d := range r.devices {
		if d.hasPeer {
			out = append(out, id)
		}
	}
	return out
}

// triggerReport asks the reporter to send the session list now.
func (e *Edge) triggerReport() {
	select {
	case e.reportCh <- struct{}{}:
	default:
	}
}

// reportLoop sends the live session list to the Control Plane every PeerRefresh and right
// after each session setup, so the Control Plane scopes /v1/decide and /v1/flows from this
// edge to devices it actually serves (security review #9).
func (e *Edge) reportLoop(ctx context.Context) {
	t := time.NewTicker(e.cfg.PeerRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.reportCh:
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := e.cp.ReportSessions(rctx, api.EdgeSessions{DeviceIDs: e.liveSessions(), ConnectorIDs: e.hub.liveIDs()})
		cancel()
		if err != nil && ctx.Err() == nil {
			e.log.Warn("session report failed", "err", err)
		}
	}
}

// negCache remembers device IDs that are not in the peer feed, with an expiry. Bounded:
// when full, new entries are not added.
type negCache struct {
	max int
	mu  sync.Mutex
	m   map[string]time.Time
}

func newNegCache(limit int) *negCache { return &negCache{max: limit, m: map[string]time.Time{}} }

func (c *negCache) has(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[id]
	return ok && now.Before(exp)
}

func (c *negCache) add(id string, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[id]; ok || len(c.m) < c.max {
		c.m[id] = exp
	}
}

func (c *negCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, exp := range c.m {
		if !now.Before(exp) {
			delete(c.m, id)
		}
	}
}
