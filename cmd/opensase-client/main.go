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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/mobile"
)

// envProvisioningKey holds the provisioning key; it is removed from the environment after
// reading so child processes (ip) do not inherit it.
const envProvisioningKey = "OPENSASE_PROVISIONING_KEY"

type options struct {
	state, control, key, keyFile, name, ca, network, tunName string
	enroll, routes, verbose, renewNow                        bool
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
	flag.StringVar(&o.tunName, "tun", "osase0", "TUN interface name")
	flag.BoolVar(&o.routes, "routes", false, "configure the TUN address and default routes with ip(8) (needs NET_ADMIN)")
	flag.BoolVar(&o.verbose, "v", false, "debug logging")
	flag.DurationVar(&o.statusEvery, "status-every", 30*time.Second, "print status JSON at this interval (0 = never)")
	flag.Parse()

	level := slog.LevelInfo
	if o.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err := run(o, log); err != nil {
		log.Error("opensase-client failed", "err", err)
		os.Exit(1)
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "linux-client"
	}
	return h
}

// stubPlatform implements mobile.Platform for Linux: no UID attribution, nothing to protect
// (bypass is done with host routes), events printed as JSON lines on stdout.
type stubPlatform struct{ verbose bool }

func (stubPlatform) ConnectionOwnerUID(int, string, int, string, int) int { return -1 }
func (stubPlatform) PackagesForUID(int) string                            { return "" }
func (stubPlatform) Protect(int) bool                                     { return true }
func (p stubPlatform) OnEvent(kind, payload string) {
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

func run(o options, log *slog.Logger) error {
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
	eng, err := mobile.NewEngine(o.state, stubPlatform{verbose: o.verbose})
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
	dev, err := tun.CreateTUN(o.tunName, tc.MTU)
	if err != nil {
		return fmt.Errorf("create TUN %s (needs NET_ADMIN and /dev/net/tun): %w", o.tunName, err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return err
	}

	cmds, err := routeCommands(context.Background(), name, tc.IPv4, tc.IPv6, tc.MTU, eng.BypassHosts())
	if err != nil {
		dev.Close()
		return err
	}
	if o.routes {
		for _, c := range cmds {
			if err := runIP(context.Background(), c, log); err != nil && !c.optional {
				dev.Close()
				return err
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "# Routes are not configured (no -routes). Run:")
		for _, c := range cmds {
			fmt.Fprintln(os.Stderr, "ip "+strings.Join(c.args, " "))
		}
	}
	if len(tc.DNS) > 0 {
		fmt.Fprintf(os.Stderr, "# DNS: point /etc/resolv.conf at %s to use the tunnel resolver (DNS policy applies to all UDP/53 anyway)\n", strings.Join(tc.DNS, ", "))
	}

	if err := eng.StartDevice(dev, o.network); err != nil {
		return err
	}
	fmt.Println(eng.Status())
	if o.renewNow {
		renewNow(eng, log)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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

type ipCmd struct {
	args     []string
	optional bool // IPv6 steps: tolerated when IPv6 is disabled in the container
}

// routeCommands builds the ip(8) commands: interface address, host routes for the bypass
// hosts via the current IPv4 default gateway, then 0.0.0.0/1 + 128.0.0.0/1 (and ::/1 +
// 8000::/1) into the TUN, which override the default route without deleting it.
func routeCommands(ctx context.Context, dev, ipv4, ipv6 string, mtu int, bypass []string) ([]ipCmd, error) {
	var cmds []ipCmd
	add := func(optional bool, args ...string) { cmds = append(cmds, ipCmd{args: args, optional: optional}) }
	if ipv4 == "" {
		return nil, errors.New("session returned no tunnel IPv4 address")
	}
	add(false, "address", "replace", ipv4, "dev", dev)
	if ipv6 != "" {
		add(true, "-6", "address", "replace", ipv6, "dev", dev)
	}
	add(false, "link", "set", "dev", dev, "mtu", fmt.Sprint(mtu), "up")

	gw, gwDev, err := defaultGateway(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range bypass {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
		if err != nil {
			// Not fatal: the Edge must work while the Control Plane is unreachable (ADR-0014).
			// The session is already up, so the Edge host resolved; an unresolvable Control
			// Plane host just gets no bypass route, and reaches it through the tunnel later.
			slog.WarnContext(ctx, "bypass host does not resolve; no bypass route", "host", h, "err", err)
			continue
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				if gw != "" {
					add(false, "route", "replace", ip4.String()+"/32", "via", gw, "dev", gwDev)
				} else {
					add(false, "route", "replace", ip4.String()+"/32", "dev", gwDev)
				}
			}
		}
	}
	add(false, "route", "replace", "0.0.0.0/1", "dev", dev)
	add(false, "route", "replace", "128.0.0.0/1", "dev", dev)
	if ipv6 != "" {
		add(true, "-6", "route", "replace", "::/1", "dev", dev)
		add(true, "-6", "route", "replace", "8000::/1", "dev", dev)
	}
	return cmds, nil
}

// defaultGateway parses `ip -4 route show default`.
func defaultGateway(ctx context.Context) (gw, dev string, err error) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route show default: %w", err)
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			if dev == "" {
				dev = f[i+1]
			}
		}
	}
	if dev == "" {
		return "", "", errors.New("no IPv4 default route to reach the Control Plane and Edge")
	}
	return gw, dev, nil
}

func runIP(ctx context.Context, c ipCmd, log *slog.Logger) error {
	out, err := exec.CommandContext(ctx, "ip", c.args...).CombinedOutput() //nolint:gosec // G204: fixed binary; args built by routeCommands from the session config
	if err != nil {
		lvl := slog.LevelError
		if c.optional {
			lvl = slog.LevelWarn
		}
		log.Log(ctx, lvl, "ip command failed", "cmd", "ip "+strings.Join(c.args, " "), "err", err, "out", strings.TrimSpace(string(out)))
		return fmt.Errorf("ip %s: %w", strings.Join(c.args, " "), err)
	}
	log.Info("configured", "cmd", "ip "+strings.Join(c.args, " "))
	return nil
}
