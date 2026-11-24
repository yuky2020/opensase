// Command opensase-client is a headless Linux Client. It runs the same Go core as
// the Android app (mobile.Engine) on a Linux TUN, with a stub platform (no UID lookup, so
// app rules never match). It is meant for end-to-end tests in a container with NET_ADMIN:
//
//	OPENSASE_PROVISIONING_KEY=PK opensase-client -state /var/lib/opensase -control https://cp:8443 -enroll -routes
//
// The provisioning key is read from -key-file, else from $OPENSASE_PROVISIONING_KEY, else
// from -key (deprecated: visible in ps and docker inspect).
//
// Without -routes it only prints the ip commands needed to route traffic into the tunnel.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yuky2020/opensase/internal/clientnet"
	"github.com/yuky2020/opensase/mobile"
)

// envProvisioningKey holds the provisioning key; it is removed from the environment after
// reading so child processes (ip) do not inherit it.
const envProvisioningKey = "OPENSASE_PROVISIONING_KEY"

type options struct {
	state, control, key, keyFile, name, ca, network, tunName string
	gateway                                                  string
	geneveListen, geneveCIDRs, healthListen                  string
	enroll, routes, verbose, renewNow                        bool
	gatewayRouted                                            bool
	statusEvery                                              time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.state, "state", "/var/lib/opensase-client", "state directory (keys, certificate, cached snapshot)")
	flag.StringVar(&o.control, "control", "", "Control Plane URL, e.g. https://cp:8443 (optionally #sha256=<CA fingerprint>)")
	flag.StringVar(&o.key, "key", "", "provisioning key (deprecated: visible in ps; use -key-file or $"+envProvisioningKey+")")
	flag.StringVar(&o.keyFile, "key-file", "", "file containing the provisioning key (used with -enroll)")
	flag.BoolVar(&o.renewNow, "renew-now", false, "renew the device certificate right after the tunnel is up (tests)")
	flag.BoolVar(&o.enroll, "enroll", false, "enroll if the state directory has no identity yet")
	flag.StringVar(&o.name, "name", hostname(), "device name sent at enrollment")
	flag.StringVar(&o.ca, "ca", "", "PEM file trusted for the enrollment request (copied to <state>/bootstrap-ca.pem)")
	flag.StringVar(&o.network, "network", "ethernet", "network type: wifi, cellular, roaming, ethernet, unknown")
	flag.StringVar(&o.tunName, "tun", clientnet.DefaultTUNName(), "TUN interface name")
	flag.BoolVar(&o.routes, "routes", false, "configure the TUN address and default routes with ip(8) (needs NET_ADMIN)")
	flag.StringVar(&o.gateway, "gateway", "", "Workload Gateway mode (ADR-0015): comma-separated IPv4 subnets whose traffic is forwarded into the tunnel (implies -routes; needs iptables and the net.ipv4.ip_forward sysctl)")
	flag.BoolVar(&o.gatewayRouted, "gateway-routed", false, "routed mode (per-workload identity): do not masquerade gateway subnets; requires -gateway")
	flag.StringVar(&o.geneveListen, "geneve-listen", "", "GENEVE ingress listen address, e.g. :6081 (requires -gateway)")
	flag.StringVar(&o.geneveCIDRs, "geneve-cidrs", "", "GENEVE ingress subnets, comma-separated IPv4 prefixes (requires -geneve-listen; must be within -gateway)")
	flag.StringVar(&o.healthListen, "health-listen", "", "HTTP health check listen address, e.g. :8080 (requires -gateway)")
	flag.BoolVar(&o.verbose, "v", false, "debug logging")
	flag.DurationVar(&o.statusEvery, "status-every", 30*time.Second, "print status JSON at this interval (0 = never)")
	flag.Parse()

	level := slog.LevelInfo
	if o.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	if err := run(o, log); err != nil {
		log.Error("opensase-client failed", "err", err)
		os.Exit(1)
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return defaultHostname
	}
	return h
}

// stubPlatform implements mobile.Platform for Linux: no UID attribution, nothing to protect
// (bypass is done with host routes), events printed as JSON lines on stdout.
type stubPlatform struct {
	verbose bool
	onState func(state string)
}

func (stubPlatform) ConnectionOwnerUID(int, string, int, string, int) int { return -1 }
func (stubPlatform) PackagesForUID(int) string                            { return "" }
func (stubPlatform) Protect(int) bool                                     { return true }
func (p stubPlatform) OnEvent(kind, payload string) {
	if kind == "state" && p.onState != nil {
		var s struct {
			State string `json:"state"`
		}
		if json.Unmarshal([]byte(payload), &s) == nil {
			p.onState(s.State)
		}
	}
	switch kind {
	case "log":
		return // already printed by the slog handler
	case "stats":
		if !p.verbose {
			return
		}
	}
	fmt.Printf("{\"event\":%q,\"payload\":%s}\n", kind, payload)
}

func parseGatewayFlags(o options) (gwCIDRs []netip.Prefix, gnvCIDRs []netip.Prefix, err error) {
	if !gatewaySupported() && (o.gateway != "" || o.geneveListen != "" || o.gatewayRouted || o.geneveCIDRs != "" || o.healthListen != "") {
		return nil, nil, errors.New("gateway mode (-gateway, -geneve-listen, -gateway-routed) is only supported on Linux")
	}
	if o.gatewayRouted && o.gateway == "" {
		return nil, nil, errors.New("-gateway-routed requires -gateway")
	}
	if o.geneveListen != "" && o.gateway == "" {
		return nil, nil, errors.New("-geneve-listen requires -gateway")
	}
	if o.healthListen != "" && o.gateway == "" {
		return nil, nil, errors.New("-health-listen requires -gateway")
	}
	if o.geneveListen != "" && o.geneveCIDRs == "" {
		return nil, nil, errors.New("-geneve-listen requires -geneve-cidrs")
	}
	if o.geneveCIDRs != "" && o.geneveListen == "" {
		return nil, nil, errors.New("-geneve-cidrs requires -geneve-listen")
	}
	if o.gateway != "" {
		if gwCIDRs, err = parseGatewayCIDRs(o.gateway); err != nil {
			return nil, nil, err
		}
	}
	if o.geneveCIDRs != "" {
		if gnvCIDRs, err = parseGatewayCIDRs(o.geneveCIDRs); err != nil {
			return nil, nil, err
		}
		if err := validateGeneveCIDRs(gwCIDRs, gnvCIDRs); err != nil {
			return nil, nil, err
		}
	}
	return gwCIDRs, gnvCIDRs, nil
}

func run(o options, log *slog.Logger) error {
	gwCIDRs, gnvCIDRs, err := parseGatewayFlags(o)
	if err != nil {
		return err
	}
	if o.gateway != "" {
		o.routes = true
		if o.gatewayRouted {
			log.Warn("routed mode active: Control Plane must authorise the CIDRs (opensasectl device-routes) or the Edge drops the traffic")
		}
	}
	if err := os.MkdirAll(o.state, 0o700); err != nil {
		return err
	}
	if o.ca != "" {
		pemBytes, err := os.ReadFile(o.ca) //nolint:gosec // G304: -ca is an operator-supplied flag
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(o.state, "bootstrap-ca.pem"), pemBytes, 0o600); err != nil { //nolint:gosec // G703: -state is an operator-supplied flag
			return err
		}
	}
	var tunnelUp atomic.Bool
	eng, err := mobile.NewEngine(o.state, stubPlatform{
		verbose: o.verbose,
		onState: func(st string) {
			tunnelUp.Store(st == mobile.StateConnected)
		},
	})
	if err != nil {
		return err
	}
	eng.SetLogHandler(log.Handler())

	if !eng.IsEnrolled() {
		key, src, err := provisioningKey(o, os.Getenv, os.ReadFile)
		if err != nil {
			return err
		}
		if src == "-key" {
			log.Warn("provisioning key passed with -key is visible to other users (ps, docker inspect); use -key-file or $" + envProvisioningKey)
		}
		if !o.enroll || o.control == "" || key == "" {
			return errors.New("not enrolled: run with -enroll -control URL and -key-file FILE or $" + envProvisioningKey)
		}
		if err := eng.Enroll(o.control, key, o.name); err != nil {
			return err
		}
	}
	if err := os.Unsetenv(envProvisioningKey); err != nil {
		log.Warn("clear provisioning key from environment", "err", err)
	}

	cfgJSON, err := eng.TunnelConfig()
	if err != nil {
		return fmt.Errorf("session setup: %w", err)
	}
	var tc struct {
		IPv4 string   `json:"ipv4"`
		IPv6 string   `json:"ipv6"`
		DNS  []string `json:"dns"`
		MTU  int      `json:"mtu"`
	}
	if err := json.Unmarshal([]byte(cfgJSON), &tc); err != nil {
		return err
	}
	dev, err := clientnet.CreateTUN(o.tunName, tc.MTU)
	if err != nil {
		return fmt.Errorf("create TUN %s: %w", o.tunName, err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return err
	}

	netCfg := clientnet.Config{
		Dev:    name,
		IPv4:   tc.IPv4,
		IPv6:   tc.IPv6,
		MTU:    tc.MTU,
		Bypass: eng.BypassHosts(),
		DNS:    tc.DNS,
	}

	if o.routes {
		undo, err := clientnet.Configure(context.Background(), dev, netCfg, log)
		if err != nil {
			dev.Close()
			return err
		}
		if undo != nil {
			defer undo()
		}
	} else {
		clientnet.PrintRouteInstructions(netCfg)
	}

	if err := eng.StartDevice(dev, o.network); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if gwCIDRs != nil {
		cleanup, err := setupGatewayPlatform(ctx, gatewayConfig{
			name:          name,
			gwCIDRs:       gwCIDRs,
			gnvCIDRs:      gnvCIDRs,
			dns:           tc.DNS,
			geneveListen:  o.geneveListen,
			gatewayRouted: o.gatewayRouted,
		}, log)
		if err != nil {
			eng.Stop()
			return fmt.Errorf("workload gateway: %w", err)
		}
		defer cleanup()
	}
	if o.healthListen != "" {
		healthSrv, err := startHealthServer(ctx, o.healthListen, tunnelUp.Load, log)
		if err != nil {
			eng.Stop()
			return fmt.Errorf("health server: %w", err)
		}
		defer healthSrv.Close()
		log.Info("health server active", "listen", o.healthListen)
	}
	fmt.Println(eng.Status())
	if o.renewNow {
		renewNow(eng, log)
	}
	var tick <-chan time.Time
	if o.statusEvery > 0 {
		t := time.NewTicker(o.statusEvery)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			eng.Stop()
			return nil
		case <-tick:
			fmt.Println(eng.Status())
		}
	}
}

// renewer is the part of mobile.Engine used by renewNow.
type renewer interface {
	RenewNow(ctx context.Context) error
	Status() string
}

// renewNow renews the device certificate once. A failure is logged only: the tunnel keeps
// running on the current (still valid) certificate and the engine's renewal loop retries
// with backoff.
func renewNow(eng renewer, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.RenewNow(ctx); err != nil {
		log.Warn("certificate renewal failed; keeping the current certificate, will retry", "err", err)
		return
	}
	log.Info("certificate renewed (-renew-now)")
	fmt.Println(eng.Status())
}

// provisioningKey returns the key and where it came from: -key-file, then the environment,
// then -key.
func provisioningKey(o options, getenv func(string) string, readFile func(string) ([]byte, error)) (key, src string, err error) {
	if o.keyFile != "" {
		b, err := readFile(o.keyFile)
		if err != nil {
			return "", "", fmt.Errorf("read -key-file: %w", err)
		}
		k := strings.TrimSpace(string(b))
		clear(b)
		if k == "" {
			return "", "", errors.New("-key-file is empty")
		}
		return k, "-key-file", nil
	}
	if k := strings.TrimSpace(getenv(envProvisioningKey)); k != "" {
		return k, "env", nil
	}
	if o.key != "" {
		return o.key, "-key", nil
	}
	return "", "", nil
}
