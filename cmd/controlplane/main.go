// Command controlplane runs the OpenSASE Control Plane.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/yuky2020/opensase/internal/controlplane"
	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "controlplane:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":9443", "HTTPS listen address")
	dbPath := flag.String("db", envOr("OPENSASE_DB", "controlplane.db"), "SQLite database path, or a postgres:// URL for several replicas (ADR-0033); default $OPENSASE_DB, so a password stays off the command line")
	pkiDir := flag.String("pki", "pki", "PKI directory (see opensasectl pki init)")
	kekFile := flag.String("ca-kek-file", "", "file with the 32-byte key that seals tenant CA keys in the database (default <pki>/ca-kek.key, created if missing); every Control Plane replica must use the same key")
	edgesFile := flag.String("edges", "", "JSON file with []api.EdgeInfo returned at enrollment (default <pki>/edges.json if present)")
	controlURL := flag.String("control-url", "https://controlplane:9443", "Control Plane URL returned to devices")
	maxConns := flag.Int("max-conns", controlplane.DefaultMaxConns, "maximum concurrent connections")
	retention := flag.Duration("flow-retention", controlplane.DefaultFlowRetention, "delete flow records older than this")
	flowRate := flag.Int("flow-rate", controlplane.DefaultFlowRate, "flow records accepted per device per minute")
	catFile := flag.String("categories-file", "", "web category archive (UT1 blacklists.tar.gz) to load and cache downloads in (ADR-0022)")
	catURL := flag.String("categories-url", "", "download the category archive from this URL and refresh it daily (e.g. "+categories.DefaultURL+")")
	portalDir := flag.String("portal-dir", os.Getenv("OPENSASE_PORTAL_DIR"), "serve the admin portal (Flutter web build with index.html) from this directory at /admin/ (or env OPENSASE_PORTAL_DIR)")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()
	if *catURL != "" && *catFile == "" {
		// Downloads need a cache: next to the SQLite database by default, or in the working
		// directory with PostgreSQL (each replica keeps its own copy).
		*catFile = "categories.tar.gz"
		if !store.IsPostgres(*dbPath) {
			*catFile = filepath.Join(filepath.Dir(*dbPath), "categories.tar.gz")
		}
	}

	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	token := os.Getenv("OPENSASE_ADMIN_TOKEN")
	if token == "" {
		return errors.New("OPENSASE_ADMIN_TOKEN must be set")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	auth, err := pki.OpenAuthority(*pkiDir)
	if err != nil {
		return err
	}
	sk, keyID, err := pki.LoadOrCreateSigningKey(filepath.Join(*pkiDir, pki.SnapshotKeyFile))
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*pkiDir, pki.CPCertFile), filepath.Join(*pkiDir, pki.CPKeyFile))
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}
	var edges []api.EdgeInfo
	ef := *edgesFile
	if ef == "" {
		if _, err := os.Stat(filepath.Join(*pkiDir, "edges.json")); err == nil {
			ef = filepath.Join(*pkiDir, "edges.json")
		}
	}
	if ef != "" {
		b, err := os.ReadFile(ef) //nolint:gosec // G304: -edges/-pki-dir are operator-supplied flags
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &edges); err != nil {
			return fmt.Errorf("parse %s: %w", ef, err)
		}
	}
	if *portalDir != "" {
		if st, err := os.Stat(filepath.Join(*portalDir, "index.html")); err != nil || !st.Mode().IsRegular() { //nolint:gosec // G703: the operator chooses the portal directory (flag or env), not a remote client
			return fmt.Errorf("-portal-dir %s: index.html not found", *portalDir)
		}
	}
	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Warn("close store", "err", err)
		}
	}()
	kekPath := *kekFile
	if kekPath == "" {
		kekPath = filepath.Join(*pkiDir, pki.CAKeyEncryptionKeyFile)
	}
	kek, err := pki.LoadOrCreateKEK(kekPath)
	if err != nil {
		return err
	}
	if err := auth.UseStore(ctx, st, kek); err != nil {
		return fmt.Errorf("tenant CAs in the database: %w", err)
	}

	srv, err := controlplane.New(controlplane.Config{
		Store: st, Authority: auth, SigningKey: sk, SigningKeyID: keyID,
		AdminToken: token, Edges: edges, ControlURL: *controlURL, Logger: log,
		MaxConns: *maxConns, FlowRetention: *retention, FlowRate: *flowRate, PortalDir: *portalDir, CategoriesFile: *catFile, CategoriesURL: *catURL,
	})
	if err != nil {
		return err
	}
	log.Info("starting", "snapshotKey", keyID, "edges", len(edges), "portal", *portalDir != "")
	return srv.Run(ctx, *listen, cert)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
