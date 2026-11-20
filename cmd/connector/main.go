// Command connector runs an OpenSASE Connector (ADR-0013): outbound-only, it keeps a
// PQ TLS broker connection to every Edge and dials the private apps of its group.
//
//	connector -control https://cp:9443#sha256=<root fingerprint> -key-file /run/secrets/connector_key -state /var/lib/opensase-connector
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/yuky2020/opensase/internal/connector"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(1)
	}
}

func run() error {
	control := flag.String("control", "", "Control Plane URL, e.g. https://cp:9443 (optionally #sha256=<root CA fingerprint> for the first contact)")
	keyFile := flag.String("key-file", "", "file holding the connector provisioning key (first enrollment only; or env OPENSASE_CONNECTOR_KEY)")
	state := flag.String("state", "/var/lib/opensase-connector", "state directory (0700): connector key, certificate, root CA")
	allowLoopback := flag.Bool("allow-loopback", false, "let apps resolve to loopback addresses (tests only)")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()
	if *control == "" {
		return errors.New("-control is required")
	}
	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	// The key never comes from the command line (visible in ps).
	key := os.Getenv("OPENSASE_CONNECTOR_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("-key-file: %w", err)
		}
		if k := strings.TrimSpace(string(b)); k != "" {
			key = k
		}
		clear(b)
	}
	if *allowLoopback {
		log.Warn("-allow-loopback set: apps may resolve to loopback (tests only)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := connector.New(ctx, connector.Config{
		ControlURL: *control, ProvisioningKey: key, StateDir: *state,
		AllowLoopback: *allowLoopback, Logger: log,
	})
	if err != nil {
		return err
	}
	return c.Run(ctx)
}
