// Command edge runs an OpenSASE Edge (needs CAP_NET_ADMIN and /dev/net/tun).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yuky2020/opensase/internal/edge"
	"github.com/yuky2020/opensase/pkg/pki"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edge:", err)
		os.Exit(1)
	}
}

func run() error {
	control := flag.String("control-url", "https://controlplane:9443", "Control Plane URL")
	pkiDir := flag.String("pki", "pki/edge", "Edge PKI directory (opensasectl pki init writes <pki>/edge): root.crt, edge.crt, edge.key, edge-wg.key")
	listen := flag.String("listen", ":8443", "session-setup listen address")
	wgPort := flag.Int("wg-port", 51820, "WireGuard UDP port")
	wgEndpoint := flag.String("wg-endpoint", "edge:51820", "WireGuard endpoint returned to clients")
	tunName := flag.String("tun", "wg0", "TUN interface name")
	mtu := flag.Int("mtu", 1280, "tunnel MTU")
	upstream := flag.String("upstream-dns", "1.1.1.1:53", "upstream DNS resolver")
	rotate := flag.Duration("rotate", 10*time.Minute, "PSK rotation interval returned to clients")
	denyCIDRs := flag.String("deny-cidrs", "", "extra comma-separated CIDRs tunnel clients may not reach (on top of the built-in deny list)")
	allowPrivate := flag.Bool("allow-private", false, "let tunnel clients reach private ranges (RFC 1918, CGNAT, ULA); link-local, loopback, multicast and the Edge's own addresses stay denied")
	allowDoH := flag.Bool("allow-doh", false, "disable the built-in DNS-over-HTTPS endpoint blocklist (plain DNS and DoT to other resolvers stay blocked)")
	ocrURL := flag.String("ocr", "", "OCR service URL for DLP on images (ADR-0024), e.g. http://ocr:8090")
	icapURL := flag.String("icap", "", "ICAP malware scanning service icap://host[:port]/service, instead of -clamd (issue #25)")
	clamdAddr := flag.String("clamd", "", "ClamAV daemon host:port for malware scanning on the inspected path (ADR-0020)")
	inspectListen := flag.String("inspect-listen", "off", "TLS inspection listener for tunnel TCP to ports 80/443 the kernel REDIRECTs to it (ADR-0018; \"off\" disables)")
	ztnaListen := flag.String("ztna-listen", "0.0.0.0:15001", "ZTNA broker listener for TCP the kernel REDIRECTs from the tunnel to 100.96.0.0/12 (\"off\" disables)")
	brokerListen := flag.String("broker-listen", ":8444", "Connector listener (mTLS, ALPN opensase-broker/1; \"off\" disables)")
	tenant := flag.String("tenant", "", "Private Edge: serve only this tenant (must match the edge registration, opensasectl edge add -tenant)")
	stateDir := flag.String("state-dir", "", "cache the last good Control Plane state here, so the Edge starts and keeps enforcing while the Control Plane is unreachable")
	flowLog := flag.String("flow-log", "", "also append every flow record to this local JSONL file (rotated to FILE.1 at 64 MiB)")
	opsListen := flag.String("ops-listen", "", "serve /metrics, /healthz and /readyz on this plain-HTTP address (issue #73), e.g. 127.0.0.1:9091; keep it reachable only by monitoring")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()
	var deny []netip.Prefix
	for _, c := range strings.Split(*denyCIDRs, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("-deny-cidrs: %w", err)
		}
		deny = append(deny, p)
	}

	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	rootPEM, err := os.ReadFile(filepath.Join(*pkiDir, pki.RootCertFile))
	if err != nil {
		return err
	}
	roots, err := pki.ParseCertsPEM(rootPEM)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*pkiDir, pki.EdgeCertFile), filepath.Join(*pkiDir, pki.EdgeKeyFile))
	if err != nil {
		return fmt.Errorf("load edge certificate: %w", err)
	}
	wgPriv, _, err := pki.LoadWireGuardKey(filepath.Join(*pkiDir, pki.EdgeWGKeyFile))
	if err != nil {
		return fmt.Errorf("load wireguard key: %w", err)
	}
	defer clear(wgPriv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return edge.Run(ctx, edge.Config{
		ControlURL: *control, Root: roots[0], Cert: cert, WGPrivateKey: wgPriv,
		ListenAddr: *listen, OpsListen: *opsListen, WGPort: *wgPort, WGEndpoint: *wgEndpoint, TUNName: *tunName,
		MTU: *mtu, Upstream: *upstream, RotateAfter: *rotate, Logger: log,
		DenyCIDRs: deny, AllowPrivate: *allowPrivate, AllowDoH: *allowDoH,
		ZTNAListen: *ztnaListen, BrokerListen: *brokerListen, InspectListen: *inspectListen, ClamdAddr: *clamdAddr, ICAPURL: *icapURL, OCRURL: *ocrURL,
		TenantID: *tenant, StateDir: *stateDir, FlowLogPath: *flowLog,
	})
}
