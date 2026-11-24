// Package clientnet configures the desktop client's network (routes, DNS, TUN) on Linux
// and Windows (ADR-0032).
package clientnet

import (
	"context"
	"log/slog"

	"golang.zx2c4.com/wireguard/tun"
)

// Config holds network interface and routing parameters.
type Config struct {
	Dev    string
	IPv4   string
	IPv6   string
	MTU    int
	Bypass []string
	DNS    []string
}

// Configure configures the TUN device, addresses, routes, and DNS.
// It returns an undo function that tears down installed routes and settings.
func Configure(ctx context.Context, dev tun.Device, c Config, log *slog.Logger) (undo func(), err error) {
	if log == nil {
		log = slog.Default()
	}
	return configurePlatform(ctx, dev, c, log)
}

// CreateTUN creates a TUN interface with the specified name and MTU.
// On Windows, it verifies that wintun.dll is present next to the executable.
func CreateTUN(name string, mtu int) (tun.Device, error) {
	return createTUNPlatform(name, mtu)
}

// DefaultTUNName returns the default TUN interface name for the current platform.
func DefaultTUNName() string {
	return defaultTUNNamePlatform()
}

// PrintRouteInstructions writes instructions to stderr on how to configure routes manually.
func PrintRouteInstructions(c Config) {
	printRouteInstructionsPlatform(c)
}
