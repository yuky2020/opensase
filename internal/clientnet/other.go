//go:build !linux && !windows

package clientnet

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

func defaultTUNNamePlatform() string {
	return "utun0"
}

func createTUNPlatform(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

func printRouteInstructionsPlatform(_ Config) {
	fmt.Fprintln(os.Stderr, "# Manual route configuration is not supported on this platform.")
}

func configurePlatform(_ context.Context, _ tun.Device, _ Config, _ *slog.Logger) (undo func(), err error) {
	return func() {}, nil
}

func cleanupKillSwitchPlatform(context.Context) error { return nil }
