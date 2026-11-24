//go:build windows

package desktop

import (
	"context"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sidLocalSystem    = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

type roleKey struct{}

// Role represents the privilege level of the connected client.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type tokenElevation struct {
	TokenIsElevated uint32
}

func getConnHandle(c net.Conn) (windows.Handle, bool) {
	if sc, ok := c.(syscall.Conn); ok {
		if raw, err := sc.SyscallConn(); err == nil {
			var h windows.Handle
			err := raw.Control(func(fd uintptr) {
				h = windows.Handle(fd)
			})
			if err == nil && h != 0 && h != windows.InvalidHandle {
				return h, true
			}
		}
	}
	if fg, ok := c.(interface{ Fd() uintptr }); ok {
		h := windows.Handle(fg.Fd())
		if h != 0 && h != windows.InvalidHandle {
			return h, true
		}
	}
	if hg, ok := c.(interface{ Handle() uintptr }); ok {
		h := windows.Handle(hg.Handle())
		if h != 0 && h != windows.InvalidHandle {
			return h, true
		}
	}
	return 0, false
}

func isTokenElevated(tok windows.Token) bool {
	var elev tokenElevation
	var retLen uint32
	err := windows.GetTokenInformation(
		tok,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elev)), //nolint:gosec // G103: TOKEN_ELEVATION is a plain DWORD struct
		uint32(unsafe.Sizeof(elev)),
		&retLen,
	)
	if err != nil {
		return false
	}
	return elev.TokenIsElevated != 0
}

func checkTokenAdmin(tok windows.Token) bool {
	adminSID, err := windows.StringToSid(sidAdministrators)
	if err != nil {
		return false
	}
	isMember, err := tok.IsMember(adminSID)
	if err != nil {
		return false
	}
	if !isMember {
		systemSID, err := windows.StringToSid(sidLocalSystem)
		if err == nil {
			if isSys, _ := tok.IsMember(systemSID); isSys {
				return true
			}
		}
		return false
	}
	return isTokenElevated(tok)
}

func checkImpersonatedClient(h windows.Handle) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// ImpersonateNamedPipeClient is not wrapped by x/sys/windows.
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	if r, _, err := proc.Call(uintptr(h)); r == 0 {
		return false, err
	}
	defer func() {
		_ = windows.RevertToSelf()
	}()

	var tok windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if err != nil {
		return false, err
	}
	defer func() { _ = tok.Close() }()

	return checkTokenAdmin(tok), nil
}

func isClientAdmin(h windows.Handle) bool {
	// Only the impersonated pipe client's own token counts. A lookup by client process ID
	// is racy (the ID can be reused), so a caller that cannot be impersonated is not an admin.
	admin, err := checkImpersonatedClient(h)
	return err == nil && admin
}

func connContextWithPeerCred(ctx context.Context, c net.Conn) context.Context {
	h, ok := getConnHandle(c)
	if !ok {
		return context.WithValue(ctx, roleKey{}, RoleUser)
	}
	if isClientAdmin(h) {
		return context.WithValue(ctx, roleKey{}, RoleAdmin)
	}
	return context.WithValue(ctx, roleKey{}, RoleUser)
}

func checkPeerAccess(_ context.Context, _ string) error {
	return nil
}

func allowAdminOp(ctx context.Context) bool {
	if v, ok := ctx.Value(adminOpOverrideKey{}).(bool); ok {
		return v
	}
	role, ok := ctx.Value(roleKey{}).(Role)
	if !ok {
		return false
	}
	return role == RoleAdmin
}
