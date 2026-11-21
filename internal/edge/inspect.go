package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/peek"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

// TLS inspection (ADR-0018). With -inspect-listen, the kernel REDIRECTs tunnel TCP to ports
// 80 and 443 to this listener. For each connection the Edge reads the ClientHello or request
// head and then either
//   - splices the bytes to the original destination unchanged (inspection off for the
//     device's tenant, a bypassed host, no SNI, not TLS or HTTP), or
//   - terminates TLS with a certificate for the SNI issued by the Edge's inspection
//     intermediate of the tenant, opens its own verified TLS connection to the original
//     destination and proxies HTTP/1.1 requests, applying the web rules and headers of the
//     device's policy to each one. Plain HTTP is proxied the same way when the policy has
//     web rules.
//
// The browser-facing and server-facing TLS cannot use pqsession.Harden: they talk to
// arbitrary browsers and servers. Both still prefer X25519MLKEM768 (Go's default).

// Inspection limits.
const (
	inspectPeekTimeout = 10 * time.Second
	inspectIdle        = 5 * time.Minute
	inspectDialTimeout = 10 * time.Second
	maxInspectFlows    = 4096
	leafValidity       = 24 * time.Hour
	maxLeafCache       = 4096
	caRetryAfter       = 30 * time.Second
)

// Web decision rule IDs of the inspection path.
const (
	ruleHostMismatch = "web:host-mismatch"
	ruleUpstreamCert = "web:upstream-certificate"
	ruleNoCA         = "web:inspection-unavailable"
	ruleQUIC         = "web:quic"
	ruleIPv6         = "web:ipv6"
)

// inspector issues interception certificates. It holds, per tenant, the Edge's inspection
// intermediate (whose key never leaves the Edge) and a cache of leaf certificates.
type inspector struct {
	cp    controlPlane
	roots *x509.CertPool // verifies upstream servers; nil = system roots
	// dialOK vets the original destination (upstreamOK; tests allow loopback).
	dialOK func(netip.Addr) bool
	now    func() time.Time
	sf     singleflight.Group

	mu  sync.Mutex
	cas map[string]*inspectCA
}

type inspectCA struct {
	cert     *x509.Certificate
	chain    [][]byte // intermediate, root (DER) — sent after each leaf
	key      *ecdsa.PrivateKey
	leafKey  *ecdsa.PrivateKey // shared by the tenant's leaf certificates
	failedAt time.Time         // last failed refresh, to back off
	leaves   map[string]*tls.Certificate
}

func newInspector(cp controlPlane, roots *x509.CertPool) *inspector {
	return &inspector{cp: cp, roots: roots, dialOK: upstreamOK, now: time.Now, cas: map[string]*inspectCA{}}
}

// usable reports whether ca can sign at now; fresh reports whether it is not yet due for
// renewal (half its lifetime).
func (ca *inspectCA) usable(now time.Time) bool { return ca != nil && now.Before(ca.cert.NotAfter) }

func (ca *inspectCA) fresh(now time.Time) bool {
	if !ca.usable(now) {
		return false
	}
	half := ca.cert.NotBefore.Add(ca.cert.NotAfter.Sub(ca.cert.NotBefore) / 2)
	return now.Before(half)
}

// ca returns the tenant's intermediate, fetching or renewing it from the Control Plane when
// needed. A renewal failure keeps using a still valid intermediate.
func (in *inspector) ca(ctx context.Context, tenant string) (*inspectCA, error) {
	now := in.now()
	in.mu.Lock()
	cur := in.cas[tenant]
	backoff := cur != nil && now.Sub(cur.failedAt) < caRetryAfter
	in.mu.Unlock()
	if cur.fresh(now) || (backoff && cur.usable(now)) {
		return cur, nil
	}
	if backoff {
		return nil, errors.New("inspection intermediate unavailable (backing off)")
	}
	v, err, _ := in.sf.Do(tenant, func() (any, error) { return in.fetch(ctx, tenant) })
	if err != nil {
		in.mu.Lock()
		if c := in.cas[tenant]; c != nil {
			c.failedAt = now
		} else {
			in.cas[tenant] = &inspectCA{failedAt: now, cert: &x509.Certificate{}}
		}
		in.mu.Unlock()
		if cur.usable(now) {
			return cur, nil
		}
		return nil, err
	}
	return v.(*inspectCA), nil
}

func (in *inspector) fetch(ctx context.Context, tenant string) (*inspectCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "inspection " + tenant}}, key)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := in.cp.InspectionCA(ctx, api.InspectionCARequest{TenantID: tenant, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if err != nil {
		return nil, err
	}
	certs, err := pki.ParseCertsPEM([]byte(resp.Chain))
	if err != nil {
		return nil, fmt.Errorf("inspection chain: %w", err)
	}
	if len(certs) < 2 {
		return nil, errors.New("inspection chain: intermediate and root expected")
	}
	ic := certs[0]
	// The intermediate must be for our key, a CA limited to leaves, and chain to its root.
	if pub, ok := ic.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(key.Public()) || !ic.IsCA || !ic.MaxPathLenZero {
		return nil, errors.New("inspection intermediate does not match the request")
	}
	if err := ic.CheckSignatureFrom(certs[1]); err != nil {
		return nil, fmt.Errorf("inspection intermediate signature: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ca := &inspectCA{cert: ic, chain: [][]byte{ic.Raw, certs[1].Raw}, key: key, leafKey: leafKey, leaves: map[string]*tls.Certificate{}}
	in.mu.Lock()
	in.cas[tenant] = ca
	in.mu.Unlock()
	return ca, nil
}

// leaf returns a certificate for host signed by ca, from the cache when still valid.
func (in *inspector) leaf(ca *inspectCA, host string) (*tls.Certificate, error) {
	now := in.now()
	in.mu.Lock()
	if c, ok := ca.leaves[host]; ok && now.Before(c.Leaf.NotAfter) {
		in.mu.Unlock()
		return c, nil
	}
	in.mu.Unlock()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     minTime(now.Add(leafValidity), ca.cert.NotAfter),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{ip.AsSlice()}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, ca.leafKey.Public(), ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: append([][]byte{der}, ca.chain...), PrivateKey: ca.leafKey, Leaf: leaf}
	in.mu.Lock()
	if len(ca.leaves) >= maxLeafCache {
		clear(ca.leaves)
	}
	ca.leaves[host] = c
	in.mu.Unlock()
	return c, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// serveInspect accepts redirected web connections on ln until ctx is done.
func (e *Edge) serveInspect(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, maxInspectFlows)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			e.log.Warn("inspection listener stopped", "err", err)
			return
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			resetClose(tc)
			continue
		}
		go func() {
			defer func() { <-sem }()
			src := tc.RemoteAddr().(*net.TCPAddr).AddrPort()
			dst, err := e.origDst(tc)
			if err != nil {
				resetClose(tc)
				return
			}
			e.webConn(ctx, tc, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()))
		}()
	}
}

// webConn handles one redirected connection from tunnel address src to dst.
func (e *Edge) webConn(ctx context.Context, c net.Conn, src, dst netip.AddrPort) {
	d := e.reg.byTunnelIP(src.Addr())
	var cp *policy.Compiled
	var v *ztnaView
	if d != nil {
		cp, v = d.compiled.Load(), d.ztna.Load()
	}
	if cp == nil || v == nil || !e.insp.dialOK(dst.Addr()) {
		resetClose(c)
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(inspectPeekTimeout))
	head, host, proto, err := readHead(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		resetClose(c)
		return
	}
	w := &webFlow{e: e, d: d, c: cp, tenant: v.tenant, dst: dst, host: host}
	switch {
	case proto == "tls" && host != "" && cp.Inspects(host):
		w.intercept(ctx, &prefixConn{Conn: c, head: head})
	case proto == "http" && host != "" && cp.HasWebRules():
		w.scheme = "http"
		w.serveHTTP(ctx, &prefixConn{Conn: c, head: head})
	default:
		e.spliceTo(ctx, c, head, dst)
	}
}

// upstreamOK refuses destinations that would make the Edge talk to itself. The packet
// filter has already applied the built-in deny list and policy to dst.
func upstreamOK(a netip.Addr) bool {
	return a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() && !TunnelPrefix4.Contains(a) && !SyntheticPrefix.Contains(a)
}

// readHead reads until the ClientHello or request head names a host, or proves there is
// none. It returns the bytes read so far.
func readHead(c net.Conn) ([]byte, string, string, error) {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if host, proto, r := peek.Host(buf); r != peek.NeedMore {
			if r != peek.Found {
				return buf, "", proto, nil
			}
			return buf, host, proto, nil
		}
		if err != nil {
			return nil, "", "", err
		}
	}
}

// prefixConn replays head before reading from Conn.
type prefixConn struct {
	net.Conn
	head []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.head) > 0 {
		n := copy(b, p.head)
		p.head = p.head[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// spliceTo forwards c to dst unchanged, starting with head.
func (e *Edge) spliceTo(ctx context.Context, c net.Conn, head []byte, dst netip.AddrPort) {
	defer c.Close()
	up, err := (&net.Dialer{Timeout: inspectDialTimeout}).DialContext(ctx, "tcp", dst.String())
	if err != nil {
		resetClose(c)
		return
	}
	defer up.Close()
	if _, err := up.Write(head); err != nil {
		return
	}
	pipe(ctx, c, up, inspectIdle)
}

// pipe copies both ways until both directions end, either side errs, ctx ends or nothing
// moves for idle.
func pipe(ctx context.Context, a, b net.Conn, idle time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	act := &activity{}
	act.touch()
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		var n atomic.Uint64
		_, err := io.Copy(countWriter{dst, &n, act}, src)
		if err != nil {
			cancel()
			return
		}
		if hc, ok := dst.(halfCloser); ok {
			_ = hc.CloseWrite()
		}
	}
	wg.Add(2)
	go cp(b, a)
	go cp(a, b)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	t := time.NewTicker(idle / 4)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
		case <-t.C:
			if time.Since(time.Unix(0, act.last.Load())) < idle {
				continue
			}
		}
		_ = a.Close()
		_ = b.Close()
		<-done
		return
	}
}

// webFlow is one inspected connection.
type webFlow struct {
	e      *Edge
	d      *device
	c      *policy.Compiled
	tenant string
	dst    netip.AddrPort
	host   string // SNI (or first Host header for plain HTTP), lowercase
	scheme string
}

// intercept terminates the client's TLS and proxies its requests.
func (w *webFlow) intercept(ctx context.Context, c net.Conn) {
	ca, err := w.e.insp.ca(ctx, w.tenant)
	if err != nil {
		// Fail closed: a tenant that asked for inspection never gets uninspected traffic.
		w.e.log.Warn("inspection intermediate unavailable; web connection refused", "tenant", w.tenant, "err", err)
		w.block(ruleNoCA, "")
		resetClose(c)
		return
	}
	leaf, err := w.e.insp.leaf(ca, w.host)
	if err != nil {
		w.e.log.Error("inspection leaf", "host", w.host, "err", err)
		resetClose(c)
		return
	}
	tc := tls.Server(c, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*leaf},
	})
	hctx, cancel := context.WithTimeout(ctx, inspectPeekTimeout)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		// Typically a client that does not trust the inspection root, or a pinned app.
		w.e.log.Debug("inspection handshake failed", "host", w.host, "device", w.d.id, "err", err)
		_ = c.Close()
		return
	}
	w.scheme = "https"
	w.serveHTTP(ctx, tc)
}

// serveHTTP proxies the HTTP/1.1 requests on c.
func (w *webFlow) serveHTTP(ctx context.Context, c net.Conn) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: inspectDialTimeout}).DialContext(ctx, "tcp", w.dst.String())
		},
		TLSClientConfig:     &tls.Config{ServerName: w.host, RootCAs: w.e.insp.roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout: inspectDialTimeout,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	defer tr.CloseIdleConnections()
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = w.scheme
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			for _, h := range w.c.WebHeaders(w.host) {
				pr.Out.Header.Set(h.Name, h.Value)
			}
		},
		Transport: tr,
		ErrorLog:  log.New(io.Discard, "", 0),
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
			var ce *tls.CertificateVerificationError
			if errors.As(err, &ce) {
				w.block(ruleUpstreamCert, r.URL.Path)
				blockPage(rw, http.StatusBadGateway, w.host, "the server's certificate is not trusted")
				return
			}
			if ctx.Err() == nil && r.Context().Err() == nil {
				w.e.log.Debug("inspection upstream", "host", w.host, "err", err)
			}
			rw.WriteHeader(http.StatusBadGateway)
		},
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { w.handle(rw, r, rp) }),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0), // handshake and client noise
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	ln := newOneConnListener(c)
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-ln.closed:
		}
	}()
	_ = srv.Serve(ln)
	<-ln.closed
}

// handle decides one request.
func (w *webFlow) handle(rw http.ResponseWriter, r *http.Request, rp *httputil.ReverseProxy) {
	// Every request on the connection must be for the host the connection was opened (and
	// the hostname checks of ADR-0017 were applied) for.
	if reqHost := normHost(r.Host); reqHost != w.host {
		w.block(ruleHostMismatch, r.URL.Path)
		blockPage(rw, http.StatusMisdirectedRequest, reqHost, "this connection is for another host")
		return
	}
	if act, rule := w.c.WebDecide(w.host, r.Method, r.URL.Path); act == policy.ActionBlock {
		w.block("url:"+rule, r.URL.Path)
		blockPage(rw, http.StatusForbidden, w.host, "blocked by your organisation's web policy (rule "+rule+")")
		return
	}
	if checks := w.c.DLPChecks(w.host); len(checks) > 0 && r.Body != nil && r.Body != http.NoBody {
		if rule, ok := w.scanBody(r, checks); !ok {
			blockPage(rw, http.StatusForbidden, w.host, "the upload contains data your organisation's policy does not allow (rule "+rule+")")
			return
		}
	}
	rp.ServeHTTP(rw, r)
}

// maxDLPScan is how much of a request body DLP scans (ADR-0019). Larger bodies are
// "unscanned": they pass, unless a rule has BlockUnscanned.
const maxDLPScan = 8 << 20

// scanBody runs the DLP checks on the request body. It returns false and the rule when the
// request must be blocked. The body is replaced so that the scanned bytes are still sent.
// Matches are recorded, but never what matched.
func (w *webFlow) scanBody(r *http.Request, checks []policy.DLPCheck) (string, bool) {
	head, err := io.ReadAll(io.LimitReader(r.Body, maxDLPScan+1))
	if err != nil {
		return "dlp:read-error", false
	}
	complete := len(head) <= maxDLPScan
	if complete {
		r.Body = io.NopCloser(bytes.NewReader(head))
	} else {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	}
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	scannable := complete && (enc == "" || enc == "identity")
	text := head
	if scannable && strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		// Form values carry "+" for spaces and percent-escapes; scan the decoded form.
		if dec, err := url.QueryUnescape(string(head)); err == nil {
			text = []byte(dec)
		}
	}
	for _, ch := range checks {
		rule := "dlp:" + ch.ID
		hit := false
		if !scannable {
			hit = ch.BlockUnscanned
			rule += ":unscanned"
		} else {
			n := 0
			for _, c := range ch.Matcher.Counts(text) {
				n += c
			}
			hit = n >= ch.MinMatches
		}
		if !hit {
			continue
		}
		w.record(ch.Action, rule)
		if ch.Action == policy.ActionBlock {
			return rule, false
		}
	}
	return "", true
}

// normHost lowercases host and strips a port and a trailing dot.
func normHost(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
}

// block records a request (or connection) refused on the inspection path.
func (w *webFlow) block(rule, _ string) { w.record(policy.ActionBlock, rule) }

// record adds a flow record for a decision on the inspection path.
func (w *webFlow) record(act policy.Action, rule string) {
	now := time.Now()
	w.e.flows.add(api.FlowRecord{
		Start: now, End: now, Where: "edge", DeviceID: w.d.id,
		Flow:     policy.Flow{Protocol: "tcp", DstIP: w.dst.Addr().String(), DstPort: w.dst.Port(), Domain: w.host},
		Decision: policy.Decision{Action: act, RuleID: rule, Layer: LayerWeb, Log: true},
	})
}

func blockPage(rw http.ResponseWriter, code int, host, why string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(code)
	_, _ = fmt.Fprintf(rw, "<!doctype html><title>Blocked</title><h1>Access blocked</h1><p>%s: %s.</p>\n",
		html.EscapeString(host), html.EscapeString(why))
}

// oneConnListener hands out one connection, then blocks until it is closed.
type oneConnListener struct {
	once   sync.Once
	conn   chan net.Conn
	closed chan struct{}
	addr   net.Addr
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{conn: make(chan net.Conn, 1), closed: make(chan struct{}), addr: c.LocalAddr()}
	l.conn <- &notifyConn{Conn: c, l: l}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conn:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }

type notifyConn struct {
	net.Conn
	l *oneConnListener
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.l.once.Do(func() { close(c.l.closed) })
	return err
}

// webBlockRule is the rule that blocks a new flow which would escape the inspection path
// (IPv4 TCP only), or "": QUIC (UDP 443) and IPv6 HTTPS of a device with TLS inspection on,
// and IPv6 plain HTTP of a device with web rules. Browsers fall back to TCP over IPv4.
func webBlockRule(c *policy.Compiled, proto uint8, dst netip.Addr, port uint16) string {
	switch {
	case proto == packet.ProtoUDP && port == 443 && c.InspectEnabled():
		return ruleQUIC
	case proto == packet.ProtoTCP && dst.Is6() && port == 443 && c.InspectEnabled():
		return ruleIPv6
	case proto == packet.ProtoTCP && dst.Is6() && port == 80 && (c.InspectEnabled() || c.HasWebRules()):
		return ruleIPv6
	}
	return ""
}
