//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"syscall"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const (
	defaultEndpoint = `\\.\pipe\opensase`
	daemonStartHint = "sc start OpenSASE"
)

func registerEndpointFlag(fs *flag.FlagSet, endpoint *string) {
	fs.StringVar(endpoint, "pipe", defaultEndpoint, "path to the local API Windows named pipe")
}

func dialEndpoint(endpoint string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return winio.DialPipeContext(ctx, endpoint)
	}
}

func isNotExist(err error, _ string) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return true
	}
	return false
}
