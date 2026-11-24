package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Portable parts of the Workload Gateway options (used by main.go on every platform).

// validateGeneveCIDRs ensures every prefix in gnvCIDRs is contained in at least one gwCIDRs prefix.
func validateGeneveCIDRs(gwCIDRs, gnvCIDRs []netip.Prefix) error {
	for _, gnv := range gnvCIDRs {
		contained := false
		for _, gw := range gwCIDRs {
			if prefixContains(gw, gnv) {
				contained = true
				break
			}
		}
		if !contained {
			return fmt.Errorf("-geneve-cidrs prefix %s is not within -gateway prefixes", gnv)
		}
	}
	return nil
}

// startHealthServer runs an HTTP server for GET /healthz answering 200 "ok" while the tunnel
// is up and 503 otherwise.
func startHealthServer(ctx context.Context, addr string, isTunnelUp func() bool, log *slog.Logger) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if isTunnelUp() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("tunnel down\n"))
		}
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("health server listen %s: %w", addr, err)
	}
	srv.Addr = ln.Addr().String()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health server failed", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		// ctx is done here: shut down on a fresh bounded context.
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	return srv, nil
}

// prefixContains reports whether parent contains child.
func prefixContains(parent, child netip.Prefix) bool {
	return parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}
