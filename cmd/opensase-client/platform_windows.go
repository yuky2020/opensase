//go:build windows

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

const defaultHostname = "windows-client"

func gatewaySupported() bool {
	return false
}

type gatewayConfig struct {
	name          string
	gwCIDRs       []netip.Prefix
	gnvCIDRs      []netip.Prefix
	dns           []string
	geneveListen  string
	gatewayRouted bool
}

func setupGatewayPlatform(_ context.Context, _ gatewayConfig, _ *slog.Logger) (func(), error) {
	return nil, errors.New("gateway mode (-gateway, -geneve-listen, -gateway-routed) is only supported on Linux")
}
