package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

func TestResolveEndpointIPv6Only(t *testing.T) {
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")
	v4 := netip.MustParseAddr("198.51.100.1")

	tests := []struct {
		name      string
		hostport  string
		prefer    netip.Addr
		lookupIPs []netip.Addr
		lookupErr error
		want      string
		wantErr   string
	}{
		{
			name:      "AAAA only without preference",
			hostport:  "edge.example:51820",
			lookupIPs: []netip.Addr{v6a},
			want:      "[2001:db8::1]:51820",
		},
		{
			name:      "AAAA only with IPv6 preference",
			hostport:  "edge.example:51820",
			prefer:    v6b,
			lookupIPs: []netip.Addr{v6a},
			want:      "[2001:db8::1]:51820",
		},
		{
			name:      "AAAA only falls back when IPv4 preferred",
			hostport:  "edge.example:51820",
			prefer:    v4,
			lookupIPs: []netip.Addr{v6a},
			want:      "[2001:db8::1]:51820",
		},
		{
			name:     "IPv6 literal bypasses DNS",
			hostport: "[2001:db8::2]:51820",
			want:     "[2001:db8::2]:51820",
		},
		{
			name:     "IPv6 literal strips zone",
			hostport: "[fe80::1%eth0]:51820",
			want:     "[fe80::1]:51820",
		},
		{
			name:     "IPv4-mapped IPv6 literal unmaps",
			hostport: "[::ffff:198.51.100.1]:51820",
			want:     "198.51.100.1:51820",
		},
		{
			name:      "DNS error propagated",
			hostport:  "edge.example:51820",
			lookupErr: errors.New("no such host"),
			wantErr:   "no such host",
		},
		{
			name:      "empty DNS answer fails",
			hostport:  "edge.example:51820",
			lookupIPs: nil,
			wantErr:   "no addresses found",
		},
		{
			name:     "missing port fails",
			hostport: "edge.example",
			wantErr:  "invalid WireGuard endpoint",
		},
		{
			name:     "out of range port fails",
			hostport: "edge.example:70000",
			wantErr:  "invalid WireGuard endpoint port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Engine{
				hosts: &hostCache{
					cache: make(map[string][]netip.Addr),
					lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
						if tt.lookupErr != nil {
							return nil, tt.lookupErr
						}
						return tt.lookupIPs, nil
					},
				},
			}
			got, err := e.resolveEndpointFor(context.Background(), tt.hostport, tt.prefer)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveEndpointFor(%q, %v) err = %v, want substring %q", tt.hostport, tt.prefer, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEndpointFor(%q, %v) unexpected err: %v", tt.hostport, tt.prefer, err)
			}
			if got != tt.want {
				t.Fatalf("resolveEndpointFor(%q, %v) = %q, want %q", tt.hostport, tt.prefer, got, tt.want)
			}
		})
	}
}

func TestResolveEndpointFamilyPreference(t *testing.T) {
	v4a := netip.MustParseAddr("198.51.100.1")
	v4b := netip.MustParseAddr("198.51.100.2")
	v4other := netip.MustParseAddr("198.51.100.99")
	v4mapped := netip.MustParseAddr("::ffff:198.51.100.1")
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")
	v6other := netip.MustParseAddr("2001:db8::99")

	tests := []struct {
		name   string
		ips    []netip.Addr
		prefer netip.Addr
		want   string
	}{
		{
			name:   "dual-stack A first prefers AAAA when session used IPv6",
			ips:    []netip.Addr{v4a, v6a},
			prefer: v6other,
			want:   "[2001:db8::1]:51820",
		},
		{
			name:   "dual-stack AAAA first prefers A when session used IPv4",
			ips:    []netip.Addr{v6a, v4a},
			prefer: v4other,
			want:   "198.51.100.1:51820",
		},
		{
			name:   "dual-stack A first keeps A when session used IPv4",
			ips:    []netip.Addr{v4a, v6a},
			prefer: v4other,
			want:   "198.51.100.1:51820",
		},
		{
			name:   "dual-stack AAAA first keeps AAAA when session used IPv6",
			ips:    []netip.Addr{v6a, v4a},
			prefer: v6other,
			want:   "[2001:db8::1]:51820",
		},
		{
			name:   "exact IPv6 session match wins over earlier AAAA",
			ips:    []netip.Addr{v4a, v6a, v6b},
			prefer: v6b,
			want:   "[2001:db8::2]:51820",
		},
		{
			name:   "exact IPv4 session match wins over earlier A",
			ips:    []netip.Addr{v6a, v4a, v4b},
			prefer: v4b,
			want:   "198.51.100.2:51820",
		},
		{
			name:   "IPv6 session falls back to A when no AAAA",
			ips:    []netip.Addr{v4a},
			prefer: v6other,
			want:   "198.51.100.1:51820",
		},
		{
			name:   "IPv4 session falls back to AAAA when no A",
			ips:    []netip.Addr{v6a},
			prefer: v4other,
			want:   "[2001:db8::1]:51820",
		},
		{
			name:   "no preference preserves resolver order when AAAA is first",
			ips:    []netip.Addr{v6a, v4a},
			prefer: netip.Addr{},
			want:   "[2001:db8::1]:51820",
		},
		{
			name:   "no preference preserves resolver order when A is first",
			ips:    []netip.Addr{v4a, v6a},
			prefer: netip.Addr{},
			want:   "198.51.100.1:51820",
		},
		{
			name:   "IPv4-mapped entry is treated as IPv4 when IPv6 preferred",
			ips:    []netip.Addr{v4mapped, v6a},
			prefer: v6other,
			want:   "[2001:db8::1]:51820",
		},
		{
			name:   "IPv4-mapped entry unmaps when IPv4 preferred",
			ips:    []netip.Addr{v6a, v4mapped},
			prefer: v4other,
			want:   "198.51.100.1:51820",
		},
		{
			name:   "invalid zero entries are skipped",
			ips:    []netip.Addr{{}, v6a},
			prefer: netip.Addr{},
			want:   "[2001:db8::1]:51820",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Engine{
				hosts: &hostCache{
					cache: make(map[string][]netip.Addr),
					lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
						return tt.ips, nil
					},
				},
			}
			var got string
			var err error
			if !tt.prefer.IsValid() {
				got, err = e.resolveEndpoint(context.Background(), "edge.example:51820")
			} else {
				got, err = e.resolveEndpointFor(context.Background(), "edge.example:51820", tt.prefer)
			}
			if err != nil {
				t.Fatalf("resolve failed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddrFromNetAddr(t *testing.T) {
	tests := []struct {
		name   string
		addr   net.Addr
		want   netip.Addr
		wantOK bool
	}{
		{
			name:   "nil",
			addr:   nil,
			wantOK: false,
		},
		{
			name:   "TCP IPv4",
			addr:   &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
			want:   netip.MustParseAddr("198.51.100.1"),
			wantOK: true,
		},
		{
			name:   "TCP IPv6",
			addr:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
			want:   netip.MustParseAddr("2001:db8::1"),
			wantOK: true,
		},
		{
			name:   "TCP IPv4-mapped IPv6 unmaps",
			addr:   &net.TCPAddr{IP: net.ParseIP("::ffff:198.51.100.1"), Port: 443},
			want:   netip.MustParseAddr("198.51.100.1"),
			wantOK: true,
		},
		{
			name:   "TCP IPv6 strips zone",
			addr:   &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 443, Zone: "eth0"},
			want:   netip.MustParseAddr("fe80::1"),
			wantOK: true,
		},
		{
			name:   "UDP fallback",
			addr:   &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 51820},
			want:   netip.MustParseAddr("2001:db8::2"),
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := addrFromNetAddr(tt.addr)
			if ok != tt.wantOK {
				t.Fatalf("addrFromNetAddr(%v) ok = %v, want %v", tt.addr, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("addrFromNetAddr(%v) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestSetupSessionEndpointFamily(t *testing.T) {
	rootCA, err := pki.NewRootCA("test root")
	if err != nil {
		t.Fatal(err)
	}
	tenantCA, err := rootCA.NewTenantCA("t1")
	if err != nil {
		t.Fatal(err)
	}
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dev-1"},
	}, devKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	devCertPEM, _, err := tenantCA.SignDeviceCSR(csrPEM, "t1", "dev-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	devKeyDER, err := x509.MarshalPKCS8PrivateKey(devKey)
	if err != nil {
		t.Fatal(err)
	}
	devKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: devKeyDER})
	devTLSCert, err := tls.X509KeyPair(devCertPEM, devKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	edgeCertPEM, edgeKeyPEM, err := rootCA.IssueServerCert(pki.ServerCertOptions{
		Kind:     pki.KindEdge,
		ID:       "edge-1",
		DNSNames: []string{"edge.test"},
		IPs:      []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	})
	if err != nil {
		t.Fatal(err)
	}
	edgeTLSCert, err := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(rootCA.Cert)
	en := &enrollment{ca: caPool}
	en.cert.Store(&devTLSCert)
	edgeWGKey := base64.StdEncoding.EncodeToString(edgeWGPub(t))

	v4 := netip.MustParseAddr("198.51.100.1")
	v6 := netip.MustParseAddr("2001:db8::1")

	tests := []struct {
		name         string
		network      string
		listenAddr   string
		sessionDNS   []netip.Addr
		wgDNS        []netip.Addr
		wantEndpoint string
	}{
		{
			name:         "IPv4 session selects A over earlier AAAA",
			network:      "tcp4",
			listenAddr:   "127.0.0.1:0",
			sessionDNS:   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			wgDNS:        []netip.Addr{v6, v4},
			wantEndpoint: "198.51.100.1:51820",
		},
		{
			name:         "IPv4 session falls back to AAAA when no A",
			network:      "tcp4",
			listenAddr:   "127.0.0.1:0",
			sessionDNS:   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			wgDNS:        []netip.Addr{v6},
			wantEndpoint: "[2001:db8::1]:51820",
		},
		{
			name:         "IPv6 session selects AAAA over earlier A",
			network:      "tcp6",
			listenAddr:   "[::1]:0",
			sessionDNS:   []netip.Addr{netip.MustParseAddr("::1")},
			wgDNS:        []netip.Addr{v4, v6},
			wantEndpoint: "[2001:db8::1]:51820",
		},
		{
			name:         "IPv6 session falls back to A when no AAAA",
			network:      "tcp6",
			listenAddr:   "[::1]:0",
			sessionDNS:   []netip.Addr{netip.MustParseAddr("::1")},
			wgDNS:        []netip.Addr{v4},
			wantEndpoint: "198.51.100.1:51820",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen(tt.network, tt.listenAddr)
			if err != nil {
				if tt.network == "tcp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("POST /v1/session", func(w http.ResponseWriter, r *http.Request) {
				var req api.SessionRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				resp := api.SessionResponse{
					SessionID:      "sess-1",
					Epoch:          req.Epoch,
					TunnelIPv4:     "100.64.0.7/32",
					TunnelIPv6:     "fd7a:5a5e::7/128",
					DNSServers:     []string{"100.64.0.1", "fd7a:5a5e::1"},
					EdgeWGKey:      edgeWGKey,
					WGEndpoint:     "wg.edge.test:51820",
					RotateAfterSec: 600,
					MTU:            1280,
				}
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			})

			srv := httptest.NewUnstartedServer(mux)
			_ = srv.Listener.Close()
			srv.Listener = ln
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{edgeTLSCert},
				ClientAuth:   tls.VerifyClientCertIfGiven,
				ClientCAs:    caPool,
			}
			pqsession.Harden(tlsCfg)
			srv.TLS = tlsCfg
			srv.StartTLS()
			t.Cleanup(srv.Close)

			_, port, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}

			e := &Engine{
				hosts: &hostCache{
					cache: make(map[string][]netip.Addr),
					lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
						switch host {
						case "edge.test":
							return tt.sessionDNS, nil
						case "wg.edge.test":
							return tt.wgDNS, nil
						default:
							return nil, fmt.Errorf("unexpected lookup %q", host)
						}
					},
				},
			}

			edge := api.EdgeInfo{
				ID:         "edge-1",
				SessionURL: "https://" + net.JoinHostPort("edge.test", port),
			}
			sess, err := e.setupSession(context.Background(), en, edge, nil)
			if err != nil {
				t.Fatalf("setupSession: %v", err)
			}
			defer sess.wipe()

			if sess.endpoint != tt.wantEndpoint {
				t.Fatalf("endpoint = %q, want %q", sess.endpoint, tt.wantEndpoint)
			}
		})
	}
}
