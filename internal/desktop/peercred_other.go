//go:build !linux

package desktop

import (
	"context"
	"net"
)

func connContextWithPeerCred(ctx context.Context, _ net.Conn) context.Context {
	return ctx
}

func checkPeerAccess(_ context.Context, _ string) error {
	return nil
}
