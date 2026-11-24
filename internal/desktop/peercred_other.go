//go:build !linux && !windows

package desktop

import (
	"context"
	"net"
	"os"
)

func connContextWithPeerCred(ctx context.Context, _ net.Conn) context.Context {
	return ctx
}

func checkPeerAccess(_ context.Context, _ string) error {
	return nil
}

func allowAdminOp(ctx context.Context) bool {
	if v, ok := ctx.Value(adminOpOverrideKey{}).(bool); ok {
		return v
	}
	return os.Getuid() == 0
}
