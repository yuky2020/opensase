package edge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestGuard(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("172.18.0.3"), netip.MustParseAddr("203.0.113.200"), EdgeIPv4}
	extra := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	def := newGuard(extra, local, false, true)
	open := newGuard(nil, local, true, false) // -allow-private, DoH list disabled

	tcp := func(port uint16, domain string) policy.Flow {
		return policy.Flow{Protocol: "tcp", DstPort: port, Domain: domain}
	}
	udp := func(port uint16) policy.Flow { return policy.Flow{Protocol: "udp", DstPort: port} }
	tests := []struct {
		name string
		g    *guard
		dst  string
		flow policy.Flow
		rule string // "" = no built-in rule
	}{
		{"cloud metadata", def, "169.254.169.254", tcp(80, ""), RuleBuiltinDeny},
		{"metadata even with -allow-private", open, "169.254.169.254", tcp(80, ""), RuleBuiltinDeny},
		{"loopback", def, "127.0.0.1", tcp(22, ""), RuleBuiltinDeny},
		{"this network", def, "0.1.2.3", tcp(80, ""), RuleBuiltinDeny},
		{"multicast", def, "224.0.0.251", udp(5353), RuleBuiltinDeny},
		{"ipv6 link-local", def, "fe80::1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 loopback", def, "::1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 multicast", def, "ff02::fb", udp(5353), RuleBuiltinDeny},
		{"nat64 well-known", def, "64:ff9b::a9fe:a9fe", tcp(80, ""), RuleBuiltinDeny},
		{"nat64 well-known even with -allow-private", open, "64:ff9b::a00:1", tcp(80, ""), RuleBuiltinDeny},
		{"nat64 local-use", def, "64:ff9b:1::1", tcp(80, ""), RuleBuiltinDeny},
		{"nat64 local-use even with -allow-private", open, "64:ff9b:1::1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 discard-only", def, "100::1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 discard-only even with -allow-private", open, "100::1", tcp(80, ""), RuleBuiltinDeny},
		{"edge interface address", def, "203.0.113.200", tcp(8443, ""), RuleBuiltinDeny},
		{"edge interface address with -allow-private", open, "172.18.0.3", tcp(9443, ""), RuleBuiltinDeny},
		{"docker network (control plane)", def, "172.18.0.2", tcp(9443, ""), RuleBuiltinDeny},
		{"rfc1918", def, "10.1.2.3", tcp(443, ""), RuleBuiltinDeny},
		{"rfc1918 192.168", def, "192.168.1.1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 ula", def, "fd00::1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 benchmarking", def, "2001:2::1", tcp(80, ""), RuleBuiltinDeny},
		{"ipv6 benchmarking allowed by flag", open, "2001:2::1", tcp(80, ""), ""},
		{"private allowed by flag", open, "10.1.2.3", tcp(443, ""), ""},
		{"extra deny cidr", def, "198.51.100.9", tcp(443, ""), RuleBuiltinDeny},
		{"plain dns to a third party", def, "8.8.8.8", udp(53), RuleDNSBypass},
		{"dns over tcp", def, "93.184.215.14", tcp(53, ""), RuleDNSBypass},
		{"dot", def, "1.1.1.1", tcp(853, ""), RuleDNSBypass},
		{"dot over quic", def, "9.9.9.9", udp(853), RuleDNSBypass},
		{"plain dns blocked even without the DoH list", open, "8.8.8.8", udp(53), RuleDNSBypass},
		{"doh by ip", def, "1.1.1.1", tcp(443, ""), RuleDNSBypass},
		{"doh by ip over http3", def, "8.8.4.4", udp(443), RuleDNSBypass},
		{"doh ipv6", def, "2606:4700:4700::1111", tcp(443, ""), RuleDNSBypass},
		{"doh by snooped domain", def, "93.184.215.99", tcp(443, "dns.google"), RuleDNSBypass},
		{"doh subdomain", def, "93.184.215.99", tcp(443, "Mozilla.Cloudflare-DNS.com."), RuleDNSBypass},
		{"doh list disabled", open, "1.1.1.1", tcp(443, ""), ""},
		{"doh ip on another port", def, "1.1.1.1", tcp(80, ""), ""},
		{"lookalike domain", def, "93.184.215.99", tcp(443, "notdns.google.example"), ""},
		{"public https", def, "93.184.215.14", tcp(443, "example.com"), ""},
		{"public ping", def, "93.184.215.14", policy.Flow{Protocol: "icmp"}, ""},
		{"public ipv6 ping", def, "2001:db8::1", policy.Flow{Protocol: "icmpv6"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, hit := tc.g.check(netip.MustParseAddr(tc.dst), tc.flow)
			if tc.rule == "" {
				if hit {
					t.Fatalf("unexpected built-in block %+v", d)
				}
				return
			}
			if !hit || d.RuleID != tc.rule || d.Layer != LayerEdge || d.Action != policy.ActionBlock {
				t.Fatalf("got %+v hit=%v, want %s", d, hit, tc.rule)
			}
		})
	}
}

func TestFilterBuiltinRules(t *testing.T) {
	fx := newFixture(t)
	fx.e.guard = newGuard(nil, []netip.Addr{netip.MustParseAddr("172.18.0.3")}, false, true)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()
	me := d.ip4.String()

	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)
	tests := []struct {
		name string
		pkt  []byte
		pass bool
		rule string
	}{
		{"metadata", ipv4(me, "169.254.169.254", packet.ProtoTCP, tcpSeg(41000, 80, packet.FlagSYN)), false, RuleBuiltinDeny},
		{"edge host address", ipv4(me, "172.18.0.3", packet.ProtoTCP, tcpSeg(41001, 8443, packet.FlagSYN)), false, RuleBuiltinDeny},
		{"third-party dns", ipv4(me, "8.8.8.8", packet.ProtoUDP, udpDgram(41002, 53)), false, RuleDNSBypass},
		{"dot", ipv4(me, "1.1.1.1", packet.ProtoTCP, tcpSeg(41003, 853, packet.FlagSYN)), false, RuleDNSBypass},
		// The tenant policy allows by default; the built-in rule wins over it.
		{"doh", ipv4(me, "1.0.0.1", packet.ProtoTCP, tcpSeg(41004, 443, packet.FlagSYN)), false, RuleDNSBypass},
		{"edge resolver", ipv4(me, EdgeIPv4.String(), packet.ProtoUDP, udpDgram(41005, 53)), true, ""},
		{"public https", ipv4(me, "93.184.215.14", packet.ProtoTCP, tcpSeg(41006, 443, packet.FlagSYN)), true, ""},
	}
	for _, tc := range tests {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{tc.pkt}, 0); err != nil {
			t.Fatal(err)
		}
		if got := ft.nWrites() > before; got != tc.pass {
			t.Errorf("%s: pass=%v", tc.name, got)
		}
		if !tc.pass {
			if _, ok := readOne(t, rd); !ok {
				t.Errorf("%s: no RST/ICMP unreachable", tc.name)
			}
		}
	}
	var got []string
	for _, r := range fx.e.flows.recs {
		if r.Decision.Layer == LayerEdge {
			got = append(got, r.Decision.RuleID+"@"+r.Flow.DstIP)
		}
	}
	want := []string{RuleBuiltinDeny + "@169.254.169.254", RuleBuiltinDeny + "@172.18.0.3", RuleDNSBypass + "@8.8.8.8", RuleDNSBypass + "@1.1.1.1", RuleDNSBypass + "@1.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("edge records %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("edge records %v want %v", got, want)
		}
	}
}

// The Edge -> Control Plane client must refuse a server presenting an edge certificate,
// before sending any request (security review #1, #12).
func TestCPClientChecksServerIdentity(t *testing.T) {
	fx := newFixture(t)
	edgeCert, err := tls.LoadX509KeyPair(filepath.Join(fx.dir, pki.EdgeDir, pki.EdgeCertFile), filepath.Join(fx.dir, pki.EdgeDir, pki.EdgeKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	cpCert, err := tls.LoadX509KeyPair(filepath.Join(fx.dir, pki.CPCertFile), filepath.Join(fx.dir, pki.CPKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(fx.auth.Root.Cert)
	var hits atomic.Int32
	serve := func(cert tls.Certificate, curves []tls.CurveID) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			writeJSON(w, 200, fx.cp.bundle)
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CurvePreferences: curves}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	pq := []tls.CurveID{tls.X25519MLKEM768}
	tests := []struct {
		name string
		srv  *httptest.Server
		ok   bool
	}{
		{"control plane", serve(cpCert, pq), true},
		{"edge cert impersonating the control plane", serve(edgeCert, pq), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			// "localhost" is in both certificates: only the URI check tells them apart.
			c, err := newCPClient(strings.Replace(tc.srv.URL, "127.0.0.1", "localhost", 1), pool, edgeCert)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.PKIBundle(context.Background())
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if !tc.ok && hits.Load() != 0 {
				t.Fatal("request reached the impostor")
			}
		})
	}
}

// Sessions end with the certificate that set them up, unless a renewed certificate rotated
// the session (security review #4).
func TestSessionExpiresWithCertificate(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	fx.setPeer("d2", 1)
	_ = fx.e.syncPeers(context.Background())
	srv := fx.sessionServer()
	wgKey := func() string {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	short := fx.deviceCertValid("acme", "d1", time.Hour)
	k1 := wgKey()
	code, sr, _ := postSession(t, fx.client(&short), srv.URL, api.SessionRequest{WGPublicKey: k1})
	if code != 200 {
		t.Fatal(code)
	}
	renewed := fx.deviceCertValid("acme", "d1", 24*time.Hour) // the CP now lists its serial
	other := fx.deviceCertValid("acme", "d2", time.Hour)
	if code, _, _ := postSession(t, fx.client(&other), srv.URL, api.SessionRequest{WGPublicKey: wgKey()}); code != 200 {
		t.Fatal(code)
	}
	// d1 rotates with its renewed certificate; d2 does not renew.
	if code, _, _ := postSession(t, fx.client(&renewed), srv.URL, api.SessionRequest{WGPublicKey: k1, Epoch: 1, SessionID: sr.SessionID}); code != 200 {
		t.Fatal(code)
	}
	fx.e.expireSessions(time.Now().Add(2 * time.Hour))
	if got := fx.e.liveSessions(); len(got) != 1 || got[0] != "d1" {
		t.Fatalf("live after 2h: %v", got)
	}
	if fx.e.reg.get("d2").hasPeer {
		t.Fatal("expired session kept")
	}
	fx.e.expireSessions(time.Now().Add(25 * time.Hour))
	if got := fx.e.liveSessions(); len(got) != 0 {
		t.Fatalf("live after 25h: %v", got)
	}
	pub, _ := base64.StdEncoding.DecodeString(k1)
	if _, ok := fx.wg.psk(pub); ok {
		t.Fatal("expired WireGuard peer still configured")
	}
}

// Unknown device certificates trigger at most one shared peer sync per interval, then hit a
// negative cache (security review #7).
func TestOnDemandSyncIsBounded(t *testing.T) {
	fx := newFixture(t)
	fx.e.minSync = 300 * time.Millisecond
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	fx.cp.mu.Lock()
	base := fx.cp.peerGets
	fx.cp.mu.Unlock()
	gets := func() int {
		fx.cp.mu.Lock()
		defer fx.cp.mu.Unlock()
		return fx.cp.peerGets - base
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if fx.e.lookupDevice(context.Background(), "ghost") != nil {
				t.Error("ghost found")
			}
		}()
	}
	wg.Wait()
	if n := gets(); n < 1 || n > 2 {
		t.Fatalf("50 concurrent unknown lookups caused %d peer syncs", n)
	}
	n := gets()
	start := time.Now()
	for range 20 {
		fx.e.lookupDevice(context.Background(), "ghost")
	}
	if gets() != n || time.Since(start) > 100*time.Millisecond {
		t.Fatal("negative cache not used")
	}

	// A device enrolled after the last sync is still found (it is not negatively cached).
	fx.setPeer("d-new", 1)
	if fx.e.lookupDevice(context.Background(), "d-new") == nil {
		t.Fatal("newly enrolled device not found")
	}
	// The negative cache expires.
	fx.e.unknown.sweep(time.Now().Add(unknownHold + time.Second))
	if fx.e.unknown.has("ghost", time.Now()) {
		t.Fatal("negative entry not swept")
	}
}

func TestReportSessions(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	srv := fx.sessionServer()
	cert := fx.deviceCert("acme", "d1")
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fx.e.reportLoop(ctx)
	if code, _, _ := postSession(t, fx.client(&cert), srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())}); code != 200 {
		t.Fatal(code)
	}
	waitFor(t, func() bool {
		fx.cp.mu.Lock()
		defer fx.cp.mu.Unlock()
		for _, r := range fx.cp.reported {
			if len(r) == 1 && r[0] == "d1" {
				return true
			}
		}
		return false
	})
}

// TestSupersededCertRefused checks ST-01 and ST-04: only the current certificate serial in
// the peer feed may set up a session or a broker link; a superseded or never-delivered
// certificate is refused even though it chains to the tenant CA.
func TestSupersededCertRefused(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	srv := fx.sessionServer()
	wgKey := func() string {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	old := fx.deviceCert("acme", "d1")
	cur := fx.deviceCert("acme", "d1") // renewal: the feed now lists this serial
	if code, _, _ := postSession(t, fx.client(&old), srv.URL, api.SessionRequest{WGPublicKey: wgKey()}); code != 403 {
		t.Fatalf("superseded cert: %d", code)
	}
	if code, _, _ := postSession(t, fx.client(&cur), srv.URL, api.SessionRequest{WGPublicKey: wgKey()}); code != 200 {
		t.Fatalf("current cert: %d", code)
	}
	// Connectors: same rule on the broker allow-list.
	fx.cp.mu.Lock()
	fx.cp.peers.Connectors = []api.EdgeConnector{{ConnectorID: "c1", TenantID: "acme", Group: "default"}}
	fx.cp.mu.Unlock()
	oldC := fx.connectorCert("acme", "c1")
	curC := fx.connectorCert("acme", "c1")
	_ = fx.e.syncPeers(context.Background())
	id := pki.Identity{Kind: pki.PeerConnector, TenantID: "acme", ConnectorID: "c1"}
	if fx.e.connectorAllowed(context.Background(), id, oldC.Leaf.SerialNumber.String()) {
		t.Fatal("superseded connector cert allowed")
	}
	if !fx.e.connectorAllowed(context.Background(), id, curC.Leaf.SerialNumber.String()) {
		t.Fatal("current connector cert refused")
	}
}

// TestSupersededSessionExpires checks ST-10: a session set up with a certificate the device has
// since renewed is removed once the mismatch outlasts the grace period, but survives it within
// the grace period (the device rotates onto the new certificate).
func TestSupersededSessionExpires(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	srv := fx.sessionServer()
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	old := fx.deviceCert("acme", "d1")
	if code, _, _ := postSession(t, fx.client(&old), srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())}); code != 200 {
		t.Fatal(code)
	}
	fx.deviceCert("acme", "d1") // renewed: the feed now lists the new serial
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fx.e.reg.mu.Lock()
	fx.e.expireSupersededLocked(now.Add(fx.e.supersededGrace() - time.Second))
	within := fx.e.reg.devices["d1"].hasPeer
	fx.e.expireSupersededLocked(now.Add(fx.e.supersededGrace() + 2*time.Second))
	after := fx.e.reg.devices["d1"].hasPeer
	fx.e.reg.mu.Unlock()
	if !within || after {
		t.Fatalf("hasPeer within grace %v, after grace %v; want true, false", within, after)
	}
}
