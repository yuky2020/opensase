//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
)

const defaultHostname = "linux-client"

func gatewaySupported() bool {
	return true
}

type gatewayConfig struct {
	name          string
	gwCIDRs       []netip.Prefix
	gnvCIDRs      []netip.Prefix
	dns           []string
	geneveListen  string
	gatewayRouted bool
}

func setupGatewayPlatform(ctx context.Context, cfg gatewayConfig, log *slog.Logger) (func(), error) {
	dns := netip.MustParseAddr("100.64.0.1")
	for _, d := range cfg.dns {
		if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
			dns = a
			break
		}
	}
	var gnvCloser func()
	gnvDev := ""
	if cfg.geneveListen != "" {
		gnvDev = geneveTUNName
		gnvIngress, err := startGeneveIngress(ctx, cfg.geneveListen, cfg.gnvCIDRs, log)
		if err != nil {
			return nil, fmt.Errorf("geneve ingress: %w", err)
		}
		gnvCloser = func() { _ = gnvIngress.Close() }
		log.Info("geneve ingress active", "listen", cfg.geneveListen, "tun", geneveTUNName)
	}
	cleanup, err := setupGateway(ctx, cfg.name, cfg.gwCIDRs, dns, log, cfg.gatewayRouted, gnvDev, cfg.gnvCIDRs)
	if err != nil {
		if gnvCloser != nil {
			gnvCloser()
		}
		return nil, fmt.Errorf("workload gateway: %w", err)
	}
	return func() {
		cleanup()
		if gnvCloser != nil {
			gnvCloser()
		}
	}, nil
}
