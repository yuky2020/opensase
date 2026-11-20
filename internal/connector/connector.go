package connector

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

const (
	configWait       = 30 // seconds, long-poll of GET /v1/connector/config
	maxResponseBytes = 8 << 20
	minRetry         = 2 * time.Second
	maxRetry         = time.Minute
	minRenewRetry    = 30 * time.Second
	maxRenewRetry    = 10 * time.Minute
)

// Config configures a Connector.
type Config struct {
	// ControlURL is the Control Plane base URL, optionally with "#sha256=<hex>" pinning the
	// SHA-256 of a certificate (normally the provider root) in the server chain for the
	// first contact. Without a pin the system roots are used for enrollment.
	ControlURL string
	// ProvisioningKey is the single-use connector provisioning key, needed only to enroll.
	ProvisioningKey string
	StateDir        string
	AllowLoopback   bool // let apps resolve to loopback addresses (tests only)
	Resolver        Resolver
	Logger          *slog.Logger
}

// Connector is a running Connector.
type Connector struct {
	cfg  Config
	log  *slog.Logger
	base string // Control Plane base URL without fragment

	id   *identity
	cp   *http.Client
	cpTr *http.Transport

	apps    atomic.Pointer[[]policy.PrivateApp]
	version uint64

	linksMu sync.Mutex
	links   map[string]context.CancelFunc // edge ID|broker addr -> cancel
	up      map[string]bool
	wg      sync.WaitGroup
}

// New loads the identity from StateDir, enrolling first if there is none.
func New(ctx context.Context, cfg Config) (*Connector, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	u, err := url.Parse(cfg.ControlURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("connector: control URL must be https://host[:port][#sha256=<hex>], got %q", cfg.ControlURL)
	}
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return nil, err
	}
	c := &Connector{cfg: cfg, log: cfg.Logger, links: map[string]context.CancelFunc{}, up: map[string]bool{}}
	empty := []policy.PrivateApp{}
	c.apps.Store(&empty)
	id, err := loadIdentity(cfg.StateDir)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		if cfg.ProvisioningKey == "" {
			return nil, errors.New("connector: not enrolled and no provisioning key (-key-file or OPENSASE_CONNECTOR_KEY)")
		}
		if id, err = enroll(ctx, u, cfg.ProvisioningKey, cfg.StateDir); err != nil {
			return nil, err
		}
		c.log.Info("connector enrolled", "tenant", id.info.TenantID, "connector", id.info.ConnectorID, "group", id.info.Group)
	default:
		return nil, err
	}
	if time.Now().After(id.leaf().NotAfter) {
		return nil, fmt.Errorf("connector: certificate expired at %s; enroll again with a new provisioning key (remove %s)", id.leaf().NotAfter.UTC().Format(time.RFC3339), cfg.StateDir)
	}
	c.id = id
	// The operator's -control URL, not EnrollResponse.ControlURL: that one is advertised for
	// devices (it may be an address only phones can reach, e.g. 10.0.2.2 for the emulator).
	u2 := *u
	u2.Fragment = ""
	c.base = strings.TrimRight(u2.String(), "/")
	c.cpTr = &http.Transport{
		TLSClientConfig: pqsession.Harden(&tls.Config{
			RootCAs:              id.rootPool,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return id.cert.Load(), nil },
			VerifyConnection:     pki.ExpectServer(pki.ServerControlPlane, ""),
		}),
		ForceAttemptHTTP2: true,
		MaxIdleConns:      4,
		IdleConnTimeout:   90 * time.Second,
	}
	c.cp = &http.Client{Transport: c.cpTr}
	return c, nil
}

// Run serves until ctx is done.
func (c *Connector) Run(ctx context.Context) error {
	c.log.Info("connector starting", "tenant", c.id.info.TenantID, "connector", c.id.info.ConnectorID, "group", c.id.info.Group,
		"control", c.base, "certNotAfter", c.id.leaf().NotAfter.UTC().Format(time.RFC3339))
	c.wg.Add(1)
	go c.renewLoop(ctx)
	c.configLoop(ctx)
	c.linksMu.Lock()
	for _, cancel := range c.links {
		cancel()
	}
	c.linksMu.Unlock()
	c.wg.Wait()
	c.cpTr.CloseIdleConnections()
	return nil
}

// Apps returns the current ConnectorConfig.Apps.
func (c *Connector) Apps() []policy.PrivateApp { return *c.apps.Load() }

// --- enrollment ---

// bootstrapTLS is the TLS config of the first contact (POST /v1/connector/enroll), like the
// device client: a "#sha256=<hex>" fragment pins a certificate of the server chain, which
// must verify up to it; without one the system roots are used. Either way the server must be
// the Control Plane (SPIFFE URI) over PQ TLS.
func bootstrapTLS(u *url.URL) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: u.Hostname(), VerifyConnection: pki.ExpectServer(pki.ServerControlPlane, "")}
	if pin, ok := strings.CutPrefix(u.Fragment, "sha256="); ok {
		want, err := hex.DecodeString(strings.ReplaceAll(pin, ":", ""))
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("connector: invalid #sha256= pin in control URL")
		}
		name := cfg.ServerName
		cfg.InsecureSkipVerify = true // replaced by verification against the pinned certificate
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error { return verifyPinned(raw, want, name) }
	} else if u.Fragment != "" {
		return nil, errors.New("connector: unsupported control URL fragment")
	}
	return pqsession.Harden(cfg), nil
}

func verifyPinned(rawCerts [][]byte, pin []byte, serverName string) error {
	if len(rawCerts) == 0 {
		return errors.New("connector: no server certificate")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	pinned := false
	for i, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs[i] = c
		if sum := sha256.Sum256(raw); bytes.Equal(sum[:], pin) {
			roots.AddCert(c)
			pinned = true
		} else if i > 0 {
			inter.AddCert(c)
		}
	}
	if !pinned {
		return errors.New("connector: server certificate chain does not contain the pinned certificate")
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: inter})
	return err
}

func newKeyAndCSR(cn string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func enroll(ctx context.Context, u *url.URL, provisioningKey, dir string) (*identity, error) {
	tcfg, err := bootstrapTLS(u)
	if err != nil {
		return nil, err
	}
	key, csr, err := newKeyAndCSR("connector")
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tcfg, ForceAttemptHTTP2: true, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	base := *u
	base.Fragment = ""
	ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var resp api.ConnectorEnrollResponse
	hr, err := doJSON(ectx, &http.Client{Transport: tr}, http.MethodPost, strings.TrimRight(base.String(), "/")+"/v1/connector/enroll", nil,
		api.ConnectorEnrollRequest{ProvisioningKey: provisioningKey, CSRPEM: csr}, &resp)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if hr.TLS == nil || len(hr.TLS.PeerCertificates) == 0 {
		return nil, errors.New("enroll: no TLS state")
	}
	root, chain, err := checkEnrollResponse(&resp, key, hr.TLS.PeerCertificates)
	if err != nil {
		return nil, err
	}
	if resp.ControlURL == "" {
		resp.ControlURL = strings.TrimRight(base.String(), "/")
	}
	if err := saveIdentity(dir, resp, root, key, chain); err != nil {
		return nil, fmt.Errorf("enroll: persist: %w", err)
	}
	return loadIdentity(dir)
}

// checkEnrollResponse verifies that the certificate is for key, has the connector identity
// of the response, and chains to the root in CAPEM; and that this root is the one that
// verified the (pinned) enrollment connection, so CAPEM is anchored by the pin.
func checkEnrollResponse(r *api.ConnectorEnrollResponse, key *ecdsa.PrivateKey, serverChain []*x509.Certificate) (*x509.Certificate, [][]byte, error) {
	if !pki.ValidID(r.TenantID) || !pki.ValidID(r.ConnectorID) {
		return nil, nil, errors.New("enroll: response without valid tenant or connector id")
	}
	certs, err := pki.ParseCertsPEM([]byte(r.CertificatePEM))
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: certificate: %w", err)
	}
	cas, err := pki.ParseCertsPEM([]byte(r.CAPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: CA: %w", err)
	}
	roots := selfSignedCAs(cas)
	if len(roots) != 1 {
		return nil, nil, errors.New("enroll: CAPEM must contain exactly one root CA")
	}
	root := roots[0]
	rootPool, inter := x509.NewCertPool(), x509.NewCertPool()
	rootPool.AddCert(root)
	for _, c := range append(certs[1:], cas...) {
		if !c.Equal(root) {
			inter.AddCert(c)
		}
	}
	srvInter := x509.NewCertPool()
	for _, c := range serverChain[1:] {
		srvInter.AddCert(c)
	}
	if _, err := serverChain[0].Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: srvInter}); err != nil {
		return nil, nil, fmt.Errorf("enroll: returned root does not anchor the Control Plane certificate: %w", err)
	}
	leaf := certs[0]
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("enroll: certificate is not for the connector key")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, nil, fmt.Errorf("enroll: certificate does not chain to the provider root: %w", err)
	}
	if err := checkIdentity(leaf, r.TenantID, r.ConnectorID); err != nil {
		return nil, nil, fmt.Errorf("enroll: %w", err)
	}
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return root, chain, nil
}

// --- renewal ---

func renewAt(c *x509.Certificate) time.Time {
	return c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2)
}

func (c *Connector) renewLoop(ctx context.Context) {
	defer c.wg.Done()
	backoff := minRenewRetry
	for {
		leaf := c.id.leaf()
		if !sleepCtx(ctx, time.Until(renewAt(leaf))) {
			return
		}
		if err := c.renew(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			left := time.Until(leaf.NotAfter)
			if left <= 0 {
				c.log.Error("connector certificate expired; enroll again with a new provisioning key", "notAfter", leaf.NotAfter)
				return
			}
			d := min(backoff, max(left/2, time.Second))
			c.log.Warn("certificate renewal failed", "err", err, "retryIn", d.String())
			backoff = min(2*backoff, maxRenewRetry)
			if !sleepCtx(ctx, d) {
				return
			}
			continue
		}
		backoff = minRenewRetry
		if time.Until(renewAt(c.id.leaf())) <= 0 && !sleepCtx(ctx, minRenewRetry) {
			return
		}
	}
}

// renew gets a certificate for a NEW key over mTLS with the current one, persists it and
// hot-swaps it: new Control Plane and Edge connections use it (GetClientCertificate).
// Existing broker links keep the old one until the Edge closes them at its expiry.
func (c *Connector) renew(ctx context.Context) error {
	cur := c.id.leaf()
	key, csr, err := newKeyAndCSR(cur.Subject.CommonName)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var resp api.RenewResponse
	if _, err := doJSON(rctx, c.cp, http.MethodPost, c.base+"/v1/connector/renew", nil, api.RenewRequest{CSRPEM: csr}, &resp); err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	cert, err := checkRenewResponse(&resp, key, cur, c.id)
	if err != nil {
		return err
	}
	if err := saveCert(c.cfg.StateDir, key, cert.Certificate); err != nil {
		return fmt.Errorf("renew: persist: %w", err)
	}
	c.id.cert.Store(cert)
	c.cpTr.CloseIdleConnections()
	c.log.Info("connector certificate renewed", "notAfter", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

func checkRenewResponse(r *api.RenewResponse, key *ecdsa.PrivateKey, old *x509.Certificate, id *identity) (*tls.Certificate, error) {
	certs, err := pki.ParseCertsPEM([]byte(r.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	leaf := certs[0]
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("renew: certificate is not for the new key")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if extra, err := pki.ParseCertsPEM([]byte(r.CAPEM)); err == nil {
		for _, c := range extra {
			if !c.Equal(id.root) {
				inter.AddCert(c)
			}
		}
	}
	// Roots from enrollment only, never from the response.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: id.rootPool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("renew: certificate does not chain to the provider root: %w", err)
	}
	if err := checkIdentity(leaf, id.info.TenantID, id.info.ConnectorID); err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	if leaf.SerialNumber.Cmp(old.SerialNumber) == 0 {
		return nil, errors.New("renew: certificate reuses the current serial")
	}
	if leaf.NotAfter.Before(old.NotAfter) {
		return nil, errors.New("renew: certificate expires earlier than the current one")
	}
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

// --- configuration and broker links ---

func (c *Connector) configLoop(ctx context.Context) {
	backoff := minRetry
	for ctx.Err() == nil {
		cfg, changed, err := c.pollConfig(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var he *httpError
			if errors.As(err, &he) && (he.Status == http.StatusForbidden || he.Status == http.StatusUnauthorized) {
				c.log.Error("control plane refused the connector (revoked?)", "status", he.Status)
			} else {
				c.log.Warn("connector config poll failed", "err", err, "retryIn", backoff.String())
			}
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(2*backoff, maxRetry)
			continue
		}
		backoff = minRetry
		if changed {
			c.apply(ctx, cfg)
		}
	}
}

// pollConfig long-polls GET /v1/connector/config with If-None-Match.
func (c *Connector) pollConfig(ctx context.Context) (api.ConnectorConfig, bool, error) {
	hdr := http.Header{}
	u := c.base + "/v1/connector/config"
	if c.version > 0 {
		hdr.Set("If-None-Match", `"`+strconv.FormatUint(c.version, 10)+`"`)
		u += "?wait=" + strconv.Itoa(configWait)
	}
	pctx, cancel := context.WithTimeout(ctx, (configWait+15)*time.Second)
	defer cancel()
	var cfg api.ConnectorConfig
	resp, err := doJSON(pctx, c.cp, http.MethodGet, u, hdr, nil, &cfg)
	if err != nil {
		return cfg, false, err
	}
	if resp.StatusCode == http.StatusNotModified || cfg.Version < c.version {
		return cfg, false, nil
	}
	return cfg, cfg.Version != c.version || c.version == 0, nil
}

func linkKey(e api.EdgeInfo) string { return e.ID + "|" + e.BrokerAddr }

func (c *Connector) apply(ctx context.Context, cfg api.ConnectorConfig) {
	c.version = cfg.Version
	apps := append([]policy.PrivateApp(nil), cfg.Apps...)
	c.apps.Store(&apps)
	want := map[string]api.EdgeInfo{}
	for _, e := range cfg.Edges {
		if e.BrokerAddr == "" || !pki.ValidID(e.ID) {
			continue
		}
		if _, _, err := net.SplitHostPort(e.BrokerAddr); err != nil {
			c.log.Warn("edge broker address invalid", "edge", e.ID, "addr", e.BrokerAddr)
			continue
		}
		want[linkKey(e)] = e
	}
	c.linksMu.Lock()
	defer c.linksMu.Unlock()
	for k, cancel := range c.links {
		if _, ok := want[k]; !ok {
			cancel()
			delete(c.links, k)
		}
	}
	for k, e := range want {
		if _, ok := c.links[k]; ok {
			continue
		}
		lctx, cancel := context.WithCancel(ctx)
		c.links[k] = cancel
		host, _, _ := net.SplitHostPort(e.BrokerAddr)
		l := &Link{
			Edge: e,
			TLS:  EdgeTLSConfig(c.id.rootPool, c.id.cert.Load, e.ID, host),
			Handler: &DialHandler{
				Apps: c.Apps, Resolver: c.cfg.Resolver, AllowLoopback: c.cfg.AllowLoopback,
				Log: c.log, EdgeID: e.ID,
			},
			Log: c.log,
			OnState: func(up bool) {
				c.linksMu.Lock()
				c.up[k] = up
				c.linksMu.Unlock()
			},
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			l.Run(lctx)
		}()
	}
	c.log.Info("connector config applied", "version", cfg.Version, "apps", len(apps), "edges", len(want))
}

// LinksUp returns how many broker links are currently up.
func (c *Connector) LinksUp() int {
	c.linksMu.Lock()
	defer c.linksMu.Unlock()
	n := 0
	for k, up := range c.up {
		if _, live := c.links[k]; live && up {
			n++
		}
	}
	return n
}

// --- helpers ---

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("http %d: %s", e.Status, e.Body) }

func doJSON(ctx context.Context, hc *http.Client, method, u string, hdr http.Header, in, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(lr, 512))
		return resp, &httpError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(lr).Decode(out); err != nil {
			return resp, fmt.Errorf("decode %s: %w", u, err)
		}
	}
	return resp, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
