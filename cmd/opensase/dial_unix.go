//go:build !windows

package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"syscall"
)

const (
	defaultEndpoint = "/run/opensase/opensased.sock"
	daemonStartHint = "systemctl start opensased"
)

func registerEndpointFlag(fs *flag.FlagSet, endpoint *string) {
	fs.StringVar(endpoint, "socket", defaultEndpoint, "path to the local API Unix domain socket")
}

func dialEndpoint(endpoint string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
	}
}

func isNotExist(err error, endpoint string) bool {
	if _, statErr := os.Stat(endpoint); errors.Is(statErr, os.ErrNotExist) {
		return true
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return true
	}
	return false
}
