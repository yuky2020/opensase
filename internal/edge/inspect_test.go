package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/policy"
)

type inspectFixture struct {
	*fixture
	ctx      context.Context
	upstream *httptest.Server
	dst      netip.AddrPort
	dev      *device
	root     *x509.CertPool // the tenant's inspection root, as installed on devices
}

// newInspectFixture: device d1 of tenant acme with web inspection on; an upstream HTTPS
// server (certificate for example.com) that echoes the path and the X-Allowed-Tenant header.
func newInspectFixture(t *testing.T, web policy.WebPolicy) *inspectFixture {
	t.Helper()
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			_, _ = fmt.Fprintf(w, "body=%d ", len(b))
		}
		_, _ = fmt.Fprintf(w, "path=%s tenant=%s", r.URL.Path, r.Header.Get("X-Allowed-Tenant"))
	}))
	t.Cleanup(up.Close)
	upRoots := x509.NewCertPool()
	upRoots.AddCert(up.Certificate())
	fx := newFixtureCfg(t, func(c *Config) { c.InspectListen = "127.0.0.1:0"; c.InspectRoots = upRoots })
	fx.e.insp.dialOK = func(a netip.Addr) bool { return a.IsValid() }
	fx.web = web
	fx.setPeer("d1", 1)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()
	fx.cp.inspect = func(r api.InspectionCARequest) (api.InspectionCAResponse, error) {
		chain, cert, err := fx.auth.SignInspectionCSR([]byte(r.CSR), r.TenantID, "edge-1", 0)
		return api.InspectionCAResponse{Chain: string(chain), ExpiresAt: cert.NotAfter}, err
	}
	ica, err := fx.auth.InspectionCA("acme")
	if err != nil {
		t.Fatal(err)
	}
	root := x509.NewCertPool()
	root.AddCert(ica.Cert)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &inspectFixture{fixture: fx, ctx: ctx, upstream: up, dst: netip.MustParseAddrPort(up.Listener.Addr().String()), dev: d, root: root}
}

// dial opens a connection as if the kernel had redirected the device's connection to dst.
func (z *inspectFixture) dial() net.Conn {
	z.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		z.t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		z.t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		z.t.Fatal(err)
	}
	z.t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	go z.e.webConn(z.ctx, s, netip.AddrPortFrom(z.dev.ip4, 40000), z.dst)
	return c
}

// get sends one request over c and returns the status and body.
func get(t *testing.T, c net.Conn, method, host, path string) (int, string) {
	t.Helper()
	if _, err := fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, path, host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%s %s%s: %v", method, host, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (z *inspectFixture) hasRecord(rule string) bool {
	return z.hasRecordAction(rule, policy.ActionBlock)
}

func (z *inspectFixture) hasRecordAction(rule string, act policy.Action) bool {
	z.e.flows.mu.Lock()
	defer z.e.flows.mu.Unlock()
	for _, r := range z.e.flows.recs {
		if r.Decision.RuleID == rule && r.Decision.Layer == LayerWeb && r.Decision.Action == act && r.DeviceID == "d1" {
			return true
		}
	}
	return false
}

var testWeb = policy.WebPolicy{
	Inspect: true,
	Bypass:  []string{"*.bank.example"},
	Rules:   []policy.WebRule{{ID: "no-admin", Domains: []string{"example.com"}, PathPrefixes: []string{"/admin"}, Action: policy.ActionBlock}},
	Headers: []policy.WebHeader{{Domains: []string{"example.com"}, Name: "X-Allowed-Tenant", Value: "acme"}},
}

// TestInspection checks ADR-0018 end to end: interception with the tenant's root, URL rules
// on the decrypted request, header injection, host pinning and flow records.
func TestInspection(t *testing.T) {
	z := newInspectFixture(t, testWeb)
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake with the inspection root: %v", err)
	}
	leaf := c.ConnectionState().PeerCertificates[0]
	if leaf.Issuer.CommonName == "" || !strings.Contains(leaf.Issuer.CommonName, "inspection acme") {
		t.Fatalf("leaf issuer %q", leaf.Issuer.CommonName)
	}
	if code, body := get(t, c, "GET", "example.com", "/ok"); code != 200 || body != "path=/ok tenant=acme" {
		t.Fatalf("allowed request: %d %q", code, body)
	}
	if code, _ := get(t, c, "GET", "example.com", "/x/../ADMIN/users"); code != http.StatusForbidden || !z.hasRecord("url:no-admin") {
		t.Fatalf("admin request: %d", code)
	}
	// Same connection, another host: refused, it never reaches the server.
	if code, _ := get(t, c, "GET", "evil.example", "/ok"); code != http.StatusMisdirectedRequest || !z.hasRecord(ruleHostMismatch) {
		t.Fatalf("other host: %d", code)
	}
	// Leaves are cached per host.
	c2 := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if err := c2.Handshake(); err != nil || !c2.ConnectionState().PeerCertificates[0].Equal(leaf) {
		t.Fatalf("second connection: %v", err)
	}

	// A device trusting only the public roots does not accept the interception certificate.
	c3 := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12})
	if err := c3.Handshake(); err == nil {
		t.Fatal("interception certificate accepted without the inspection root")
	}
}

// TestInspectionBypassAndFailures: bypassed hosts are spliced untouched; an untrusted
// upstream and an unavailable intermediate fail closed.
func TestInspectionBypassAndFailures(t *testing.T) {
	z := newInspectFixture(t, testWeb)
	upRoots := x509.NewCertPool()
	upRoots.AddCert(z.upstream.Certificate())

	// Bypass: the device sees the server's own certificate.
	c := tls.Client(z.dial(), &tls.Config{ServerName: "www.bank.example", RootCAs: upRoots, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // the test checks which certificate arrives
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if !c.ConnectionState().PeerCertificates[0].Equal(z.upstream.Certificate()) {
		t.Fatal("bypassed host was intercepted")
	}

	// Upstream certificate not trusted by the Edge: 502, never proxied.
	z.e.insp.roots = x509.NewCertPool()
	c = tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if code, body := get(t, c, "GET", "example.com", "/ok"); code != http.StatusBadGateway || strings.Contains(body, "path=") || !z.hasRecord(ruleUpstreamCert) {
		t.Fatalf("untrusted upstream: %d %q", code, body)
	}

	// No intermediate (inspection off at the Control Plane): the connection is refused.
	z2 := newInspectFixture(t, testWeb)
	z2.cp.mu.Lock()
	z2.cp.inspect = nil
	z2.cp.mu.Unlock()
	c = tls.Client(z2.dial(), &tls.Config{ServerName: "example.com", RootCAs: z2.root, MinVersion: tls.VersionTLS12})
	if err := c.Handshake(); err == nil || !z2.hasRecord(ruleNoCA) {
		t.Fatalf("no intermediate: handshake %v", err)
	}
}

// TestInspectionPlainHTTP: web rules also apply to plain HTTP, without inspection.
func TestInspectionPlainHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer plain.Close()
	z := newInspectFixture(t, policy.WebPolicy{Rules: testWeb.Rules})
	z.dst = netip.MustParseAddrPort(plain.Listener.Addr().String())
	c := z.dial()
	if code, body := get(t, c, "GET", "example.com", "/ok"); code != 200 || body != "path=/ok" {
		t.Fatalf("plain allowed: %d %q", code, body)
	}
	if code, _ := get(t, c, "GET", "example.com", "/admin"); code != http.StatusForbidden {
		t.Fatalf("plain admin: %d", code)
	}
	if code, _ := get(t, c, "GET", "evil.example", "/"); code != http.StatusMisdirectedRequest {
		t.Fatalf("plain host switch: %d", code)
	}
}

func TestWebBlockRule(t *testing.T) {
	on, _ := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "t", DeviceID: "d", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow}, Web: policy.WebPolicy{Inspect: true}})
	off, _ := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "t", DeviceID: "d", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow}})
	rules, _ := policy.Compile(&policy.Snapshot{SchemaVersion: 1, TenantID: "t", DeviceID: "d", Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow}, Web: policy.WebPolicy{Rules: testWeb.Rules}})
	v4, v6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")
	for _, tc := range []struct {
		c     *policy.Compiled
		proto uint8
		dst   netip.Addr
		port  uint16
		want  string
	}{
		{on, packet.ProtoUDP, v4, 443, ruleQUIC},
		{on, packet.ProtoTCP, v6, 443, ruleIPv6},
		{on, packet.ProtoTCP, v6, 80, ruleIPv6},
		{on, packet.ProtoTCP, v4, 443, ""},
		{on, packet.ProtoUDP, v4, 53, ""},
		{off, packet.ProtoUDP, v4, 443, ""},
		{rules, packet.ProtoUDP, v4, 443, ""},
		{rules, packet.ProtoTCP, v6, 443, ""},
		{rules, packet.ProtoTCP, v6, 80, ruleIPv6},
	} {
		if got := webBlockRule(tc.c, tc.proto, tc.dst, tc.port); got != tc.want {
			t.Errorf("%d %s:%d = %q want %q", tc.proto, tc.dst, tc.port, got, tc.want)
		}
	}
}

// post sends one request with a body over c.
func post(t *testing.T, c net.Conn, hdr, body string) (int, string) {
	t.Helper()
	if _, err := fmt.Fprintf(c, "POST /up HTTP/1.1\r\nHost: example.com\r\n%sContent-Length: %d\r\n\r\n%s", hdr, len(body), body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestInspectionDLP checks ADR-0019: request bodies on the inspected path are scanned; a
// block rule refuses the upload, a log rule records it, unscannable bodies follow
// BlockUnscanned, and clean bodies reach the server intact.
func TestInspectionDLP(t *testing.T) {
	web := testWeb
	web.DLP = []policy.DLPRule{
		{ID: "pci", Detectors: []string{"credit-card"}, Action: policy.ActionBlock, BlockUnscanned: true},
		{ID: "mail-log", Detectors: []string{"email"}, MinMatches: 2, Action: policy.ActionAllow},
	}
	z := newInspectFixture(t, web)
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if code, body := post(t, c, "", "hello world"); code != 200 || body != "body=11 path=/up tenant=acme" {
		t.Fatalf("clean upload: %d %q", code, body)
	}
	if code, _ := post(t, c, "", `{"card":"4111 1111 1111 1111"}`); code != http.StatusForbidden || !z.hasRecord("dlp:pci") {
		t.Fatalf("card upload: %d", code)
	}
	if code, _ := post(t, c, "Content-Type: application/x-www-form-urlencoded\r\n", "pan=4111+1111+1111+1111&x=1"); code != http.StatusForbidden {
		t.Fatalf("form-encoded card: %d", code)
	}
	if code, _ := post(t, c, "Content-Encoding: gzip\r\n", "\x1f\x8bnot-really-gzip"); code != http.StatusForbidden || !z.hasRecord("dlp:pci:unscanned") {
		t.Fatalf("encoded body: %d", code)
	}
	if code, body := post(t, c, "", "a@x.example b@y.example"); code != 200 || !strings.HasPrefix(body, "body=23 ") || !z.hasRecordAction("dlp:mail-log", policy.ActionAllow) {
		t.Fatalf("log-only rule: %d %q", code, body)
	}
}

// TestInspectionDLPOversize: a body beyond the scan limit is forwarded intact unless the rule
// blocks unscanned bodies.
func TestInspectionDLPOversize(t *testing.T) {
	big := strings.Repeat("x", maxDLPScan) + " 4111111111111111"
	for _, blockUnscanned := range []bool{false, true} {
		web := testWeb
		web.DLP = []policy.DLPRule{{ID: "pci", Detectors: []string{"credit-card"}, Action: policy.ActionBlock, BlockUnscanned: blockUnscanned}}
		z := newInspectFixture(t, web)
		c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		code, body := post(t, c, "", big)
		if blockUnscanned {
			if code != http.StatusForbidden || !z.hasRecord("dlp:pci:unscanned") {
				t.Fatalf("blockUnscanned: %d", code)
			}
			continue
		}
		if code != 200 || !strings.HasPrefix(body, fmt.Sprintf("body=%d ", len(big))) {
			t.Fatalf("oversize forwarded: %d %.60q", code, body)
		}
	}
}
