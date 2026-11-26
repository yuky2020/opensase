package edge

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/dlp"
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
	return newInspectFixtureH2(t, web, false)
}

// newInspectFixtureH2 is newInspectFixture with an upstream that speaks HTTP/2 when upH2.
func newInspectFixtureH2(t *testing.T, web policy.WebPolicy, upH2 bool) *inspectFixture {
	t.Helper()
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws":
			// A minimal upgrade: 101, then echo one line.
			if r.Header.Get("Upgrade") != "websocket" {
				http.Error(w, "no upgrade", 400)
				return
			}
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = brw.Flush()
			line, _ := brw.ReadString('\n')
			_, _ = brw.WriteString("echo " + line)
			_ = brw.Flush()
			return
		case "/proto":
			_, _ = io.WriteString(w, r.Proto)
			return
		case "/dl/eicar":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, eicar)
			return
		case "/dl/attachment":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", `attachment; filename="x.txt"`)
			_, _ = io.WriteString(w, eicar)
			return
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, eicar)
			return
		case "/dl/clean":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, "PK clean")
			return
		case "/dl/sheet":
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			_, _ = w.Write(sheetWithCard)
			return
		case "/dl/range":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, "part")
			return
		}
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			_, _ = fmt.Fprintf(w, "body=%d ", len(b))
		}
		_, _ = fmt.Fprintf(w, "path=%s tenant=%s", r.URL.Path, r.Header.Get("X-Allowed-Tenant"))
	}))
	up.EnableHTTP2 = upH2
	up.StartTLS()
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
		chain, cert, err := fx.auth.SignInspectionCSR(context.Background(), []byte(r.CSR), r.TenantID, "edge-1", 0)
		return api.InspectionCAResponse{Chain: string(chain), ExpiresAt: cert.NotAfter}, err
	}
	ica, err := fx.auth.InspectionCA(context.Background(), "acme")
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

// TestInspectionMalware checks ADR-0020: uploads and file downloads are scanned, page
// content is not, and unscannable content follows BlockUnscanned.
func TestInspectionMalware(t *testing.T) {
	web := testWeb
	web.Malware = policy.MalwarePolicy{Uploads: true, Downloads: true}
	z := newInspectFixture(t, web)
	z.e.av = clamd{addr: fakeClamd(t, eicarReply)}
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if code, body := post(t, c, "", "hello"); code != 200 || body != "body=5 path=/up tenant=acme" {
		t.Fatalf("clean upload: %d %q", code, body)
	}
	if code, _ := post(t, c, "", eicar); code != http.StatusForbidden || !z.hasRecord("malware:Eicar-Test-Signature") {
		t.Fatalf("eicar upload: %d", code)
	}
	// The test file as a multipart upload: it does not start the body, only its part.
	mp := "--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"e.com\"\r\n\r\n" + eicar + "\r\n--XB--\r\n"
	if code, _ := post(t, c, "Content-Type: multipart/form-data; boundary=XB\r\n", mp); code != http.StatusForbidden {
		t.Fatalf("eicar in multipart: %d", code)
	}
	for path, want := range map[string]int{"/dl/eicar": 403, "/dl/attachment": 403, "/page": 200, "/dl/clean": 200, "/dl/range": 206} {
		if code, _ := get(t, c, "GET", "example.com", path); code != want {
			t.Errorf("GET %s: %d want %d", path, code, want)
		}
	}

	// Scanner down: content passes unscanned, or is blocked with BlockUnscanned.
	z.e.av = clamd{addr: "127.0.0.1:1"}
	if code, _ := get(t, c, "GET", "example.com", "/dl/clean"); code != 200 {
		t.Fatalf("scanner down, fail open: %d", code)
	}
	web.Malware.BlockUnscanned = true
	z2 := newInspectFixture(t, web)
	z2.e.av = clamd{}
	c2 := tls.Client(z2.dial(), &tls.Config{ServerName: "example.com", RootCAs: z2.root, MinVersion: tls.VersionTLS12})
	if code, _ := get(t, c2, "GET", "example.com", "/dl/clean"); code != http.StatusForbidden || !z2.hasRecord("malware:unscanned") {
		t.Fatalf("scanner down, blockUnscanned: %d", code)
	}
	z2.e.av = clamd{addr: fakeClamd(t, eicarReply)}
	if code, _ := get(t, c2, "GET", "example.com", "/dl/range"); code != http.StatusForbidden {
		t.Fatalf("range response, blockUnscanned: %d", code)
	}
}

// sheetWithCard is a minimal spreadsheet (a ZIP of XML) with a card number in a cell.
var sheetWithCard = func() []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	f, _ := zw.Create("xl/worksheets/sheet1.xml")
	_, _ = f.Write([]byte(`<?xml version="1.0"?><worksheet><sheetData><row><c><v>7</v></c><c><v>4111111111111111</v></c></row></sheetData></worksheet>`))
	_ = zw.Close()
	return b.Bytes()
}()

// encryptedZip has one entry flagged as encrypted.
var encryptedZip = func() []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	f, _ := zw.CreateHeader(&zip.FileHeader{Name: "secret.txt", Flags: 0x1})
	_, _ = f.Write([]byte("ciphertext"))
	_ = zw.Close()
	return b.Bytes()
}()

// TestInspectionDLPDocuments checks ADR-0021: documents and archives are scanned by their
// extracted text, uploads and (when the rule asks) downloads, and containers the Edge cannot
// open follow BlockUnscanned.
func TestInspectionDLPDocuments(t *testing.T) {
	for _, downloads := range []bool{false, true} {
		web := testWeb
		web.DLP = []policy.DLPRule{{ID: "pci", Detectors: []string{"credit-card"}, Action: policy.ActionBlock, BlockUnscanned: true, Downloads: downloads}}
		z := newInspectFixture(t, web)
		c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
		// Uploads: a spreadsheet, the same zipped again, and gzip-encoded.
		var gzBody bytes.Buffer
		gw := gzip.NewWriter(&gzBody)
		_, _ = gw.Write(sheetWithCard)
		_ = gw.Close()
		for name, up := range map[string]struct{ hdr, body string }{
			"xlsx":          {"", string(sheetWithCard)},
			"gzip xlsx":     {"Content-Encoding: gzip\r\n", gzBody.String()},
			"encrypted zip": {"", string(encryptedZip)},
		} {
			if code, _ := post(t, c, up.hdr, up.body); code != http.StatusForbidden {
				t.Errorf("upload %s: %d", name, code)
			}
		}
		if !z.hasRecord("dlp:pci:unscanned") {
			t.Error("no unscanned record for the encrypted zip")
		}
		want := 200
		if downloads {
			want = http.StatusForbidden
		}
		if code, _ := get(t, c, "GET", "example.com", "/dl/sheet"); code != want {
			t.Errorf("download (rule downloads=%v): %d want %d", downloads, code, want)
		}
	}
}

// TestInspectionHTTP2 checks ADR-0023: browsers that offer HTTP/2 get it, the server leg uses
// HTTP/2 when the server supports it, and every per-request control holds on HTTP/2 streams.
func TestInspectionHTTP2(t *testing.T) {
	web := testWeb
	web.DLP = []policy.DLPRule{{ID: "pci", Detectors: []string{"credit-card"}, Action: policy.ActionBlock}}
	for _, upH2 := range []bool{true, false} {
		z := newInspectFixtureH2(t, web, upH2)
		h2only := new(http.Protocols)
		h2only.SetHTTP2(true)
		tr := &http.Transport{
			Protocols:       h2only,
			TLSClientConfig: &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12},
			DialContext:     func(context.Context, string, string) (net.Conn, error) { return z.dial(), nil },
		}
		cc, err := tr.NewClientConn(context.Background(), "https", "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		do := func(method, host, path, body string) (int, string) {
			t.Helper()
			var rd io.Reader
			if body != "" {
				rd = strings.NewReader(body)
			}
			req, _ := http.NewRequest(method, "https://"+host+path, rd)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatalf("%s %s%s: %v", method, host, path, err)
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != 2 {
				t.Fatalf("browser leg is %s, not HTTP/2", resp.Proto)
			}
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		wantUp := "HTTP/1.1"
		if upH2 {
			wantUp = "HTTP/2.0"
		}
		if code, body := do("GET", "example.com", "/proto", ""); code != 200 || body != wantUp {
			t.Fatalf("upstream h2=%v: %d %q", upH2, code, body)
		}
		if code, body := do("GET", "example.com", "/ok", ""); code != 200 || body != "path=/ok tenant=acme" {
			t.Fatalf("header injection over h2: %d %q", code, body)
		}
		if code, _ := do("GET", "example.com", "/admin/x", ""); code != http.StatusForbidden {
			t.Fatalf("URL rule over h2: %d", code)
		}
		if code, _ := do("GET", "evil.example", "/ok", ""); code != http.StatusMisdirectedRequest {
			t.Fatalf("other host over h2: %d", code)
		}
		if code, _ := do("POST", "example.com", "/up", "pan 4111 1111 1111 1111"); code != http.StatusForbidden {
			t.Fatalf("DLP over h2: %d", code)
		}
		// Concurrent streams on the one connection.
		var wg sync.WaitGroup
		errs := make(chan string, 20)
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest("GET", fmt.Sprintf("https://example.com/s%d", i), nil)
				resp, err := cc.RoundTrip(req)
				if err != nil {
					errs <- err.Error()
					return
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if want := fmt.Sprintf("path=/s%d tenant=acme", i); string(b) != want {
					errs <- string(b)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Errorf("concurrent stream: %s", e)
		}
	}
	// An HTTP/1.1 browser still reaches an HTTP/2 server through HTTP/2 on the server leg.
	z := newInspectFixtureH2(t, testWeb, true)
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if code, body := get(t, c, "GET", "example.com", "/proto"); code != 200 || body != "HTTP/2.0" {
		t.Fatalf("h1 client, h2 server: %d %q", code, body)
	}
}

// TestInspectionUpgrade: WebSocket-style upgrades still pass on HTTP/1.1, with HTTP/2 enabled
// towards the server.
func TestInspectionUpgrade(t *testing.T) {
	z := newInspectFixtureH2(t, testWeb, true)
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	if _, err := fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	_, _ = io.WriteString(c, "hello\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "echo hello\n" {
		t.Fatalf("upgraded stream: %q %v", line, err)
	}
}

// TestInspectionCategoryURL: URL entries of a blocked category apply on the inspected path.
func TestInspectionCategoryURL(t *testing.T) {
	fx := newInspectFixture(t, testWeb)
	fx.cats = []string{"gambling"}
	fx.setPeer("d1", 2)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.cp.mu.Lock()
	fx.cp.categories = testCategories(t)
	fx.cp.mu.Unlock()
	if err := fx.e.syncCategories(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	c := tls.Client(fx.dial(), &tls.Config{ServerName: "example.com", RootCAs: fx.root, MinVersion: tls.VersionTLS12})
	if code, _ := get(t, c, "GET", "example.com", "/poker/table"); code != http.StatusForbidden || !fx.hasRecord("cat:gambling:url") {
		t.Fatalf("category URL: %d", code)
	}
	if code, _ := get(t, c, "GET", "example.com", "/ok"); code != 200 {
		t.Fatalf("other path: %d", code)
	}
}

// TestInspectionDLPImagesAndLegacy checks ADR-0024: images are read by the OCR service, RTF
// and legacy formats by their text; an OCR outage follows BlockUnscanned.
func TestInspectionDLPImagesAndLegacy(t *testing.T) {
	png := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, []byte("fake image data")...)
	ocr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/ocr" || !bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G'}) {
			http.Error(w, "bad", 400)
			return
		}
		_, _ = io.WriteString(w, "Carta di credito\n4111 1111 1111 1111\n")
	}))
	defer ocr.Close()
	web := testWeb
	web.DLP = []policy.DLPRule{{ID: "pci", Detectors: []string{"credit-card"}, Action: policy.ActionBlock, BlockUnscanned: true}}

	z := newInspectFixture(t, web)
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	// No OCR service: an image carries no text and passes.
	if code, _ := post(t, c, "", string(png)); code != 200 {
		t.Fatalf("image without OCR: %d", code)
	}
	// RTF is read by its text without OCR.
	if code, _ := post(t, c, "", `{\rtf1\ansi Carta 4111 1111 1111 1111\par}`); code != http.StatusForbidden {
		t.Fatalf("rtf: %d", code)
	}

	z.e.cfg.OCRURL = ocr.URL
	if code, _ := post(t, c, "", string(png)); code != http.StatusForbidden || !z.hasRecord("dlp:pci") {
		t.Fatalf("image with OCR: %d", code)
	}
	// An image inside a ZIP is read too.
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	f, _ := zw.Create("scan.png")
	_, _ = f.Write(png)
	_ = zw.Close()
	if code, _ := post(t, c, "", zb.String()); code != http.StatusForbidden {
		t.Fatalf("image in zip: %d", code)
	}
	// OCR down: the image cannot be read, BlockUnscanned blocks it.
	z.e.cfg.OCRURL = "http://127.0.0.1:1"
	if code, _ := post(t, c, "", string(png)); code != http.StatusForbidden || !z.hasRecord("dlp:pci:unscanned") {
		t.Fatalf("OCR down: %d", code)
	}
}

// TestInspectionDLPBrotliZstd (issue #14): br and zstd bodies are decoded and scanned.
func TestInspectionDLPBrotliZstd(t *testing.T) {
	web := testWeb
	web.DLP = []policy.DLPRule{{ID: "pci", Detectors: []string{"credit-card"}, Action: policy.ActionBlock}}
	z := newInspectFixture(t, web)
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	_, _ = bw.Write([]byte("pan 4111 1111 1111 1111"))
	_ = bw.Close()
	zw, _ := zstd.NewWriter(nil)
	for name, up := range map[string]struct{ hdr, body string }{
		"br":   {"Content-Encoding: br\r\n", br.String()},
		"zstd": {"Content-Encoding: zstd\r\n", string(zw.EncodeAll([]byte("pan 4111 1111 1111 1111"), nil))},
	} {
		if code, body := post(t, c, up.hdr, up.body); code != http.StatusForbidden || !strings.Contains(body, "rule dlp:pci)") {
			t.Errorf("%s: %d %q", name, code, body)
		}
	}
}

// TestInspectionDLPDatasets covers ADR-0029 at the Edge: uploads with a protected value or an
// excerpt of a protected document are blocked; a dataset that is not loaded follows
// BlockUnscanned.
func TestInspectionDLPDatasets(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	pack := func(hs []uint64) []byte {
		b := make([]byte, 8*len(hs))
		for i, h := range hs {
			binary.BigEndian.PutUint64(b[8*i:], h)
		}
		return b
	}
	doc := "Project Falcon will acquire Example Industries for 42 euro per share before the end of March."
	web := testWeb
	web.DLP = []policy.DLPRule{
		{ID: "customers", Datasets: []string{"customers"}, Action: policy.ActionBlock},
		{ID: "falcon", Datasets: []string{"falcon"}, MinMatches: 3, Action: policy.ActionBlock},
		{ID: "missing", Datasets: []string{"not-uploaded"}, Domains: []string{"strict.example"}, Action: policy.ActionBlock, BlockUnscanned: true},
	}
	z := newInspectFixture(t, web)
	z.cp.mu.Lock()
	z.cp.datasets = map[string][]api.EdgeDataset{"acme": {
		{Name: "customers", Kind: "values", Key: key, Hashes: pack(dlp.ValueHashes(key, []string{"Mario Rossi", "ACCT-1234"}))},
		{Name: "falcon", Kind: "document", Key: key, Hashes: pack(dlp.ShingleHashes(key, doc))},
	}}
	z.cp.mu.Unlock()
	if err := z.e.syncDatasets(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	c := tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"protected value":  {"note: call MARIO ROSSI about acct-1234", http.StatusForbidden},
		"document excerpt": {"fwd: project falcon will acquire example industries for 42 euro per share", http.StatusForbidden},
		"unrelated":        {"lunch at noon with Anna", 200},
		"one shingle only": {"project falcon will acquire example industries for 42", 200},
	} {
		if code, _ := post(t, c, "", tc.body); code != tc.want {
			t.Errorf("%s: %d want %d", name, code, tc.want)
		}
	}
	if !z.hasRecord("dlp:customers") || !z.hasRecord("dlp:falcon") {
		t.Error("dataset blocks not recorded")
	}
}
