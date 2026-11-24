//go:build windows

package desktop

import (
	"context"
	"net"
	"testing"
)

func TestWindowsAllowAdminOp(t *testing.T) {
	ctx := context.Background()
	if allowAdminOp(ctx) {
		t.Errorf("expected unidentified context to be non-admin")
	}

	userCtx := context.WithValue(ctx, roleKey{}, RoleUser)
	if allowAdminOp(userCtx) {
		t.Errorf("expected RoleUser to be non-admin")
	}

	adminCtx := context.WithValue(ctx, roleKey{}, RoleAdmin)
	if !allowAdminOp(adminCtx) {
		t.Errorf("expected RoleAdmin to be admin")
	}

	// Override takes precedence
	overrideCtx := withAdminOpAllowed(userCtx, true)
	if !allowAdminOp(overrideCtx) {
		t.Errorf("expected overridden context to be admin")
	}
}

func TestWindowsConnContextWithPeerCredFallback(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := connContextWithPeerCred(context.Background(), client)
	if allowAdminOp(ctx) {
		t.Errorf("expected in-memory pipe with no windows handle to fallback to non-admin")
	}
	role, ok := ctx.Value(roleKey{}).(Role)
	if !ok || role != RoleUser {
		t.Errorf("expected RoleUser, got %v", role)
	}
}
