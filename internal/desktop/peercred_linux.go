//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

type peerCredKey struct{}

type peerCred struct {
	uid uint32
	gid uint32
	pid int32
	bad bool // a Unix socket peer whose credentials could not be read: always refused
}

func connContextWithPeerCred(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return context.WithValue(ctx, peerCredKey{}, &peerCred{bad: true})
	}
	var ucred *unix.Ucred
	var optErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, optErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil || optErr != nil || ucred == nil {
		return context.WithValue(ctx, peerCredKey{}, &peerCred{bad: true})
	}
	return context.WithValue(ctx, peerCredKey{}, &peerCred{
		uid: ucred.Uid,
		gid: ucred.Gid,
		pid: ucred.Pid,
	})
}

func checkPeerAccess(ctx context.Context, group string) error {
	cred, ok := ctx.Value(peerCredKey{}).(*peerCred)
	if !ok || cred == nil {
		// Non-Unix connections (e.g. in-memory test listeners without peer credentials)
		return nil
	}
	if cred.bad {
		return errors.New("access denied: peer credentials unavailable")
	}
	// root, and the user the daemon runs as (it can already do everything the daemon does).
	if cred.uid == 0 || cred.uid == uint32(os.Getuid()) { //nolint:gosec // G115: uids fit in uint32
		return nil
	}
	if group == "" {
		return errors.New("access denied: only root is allowed")
	}
	grp, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("group %q not found: %w", group, err)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(cred.uid), 10))
	if err != nil {
		return fmt.Errorf("lookup uid %d: %w", cred.uid, err)
	}
	if u.Gid == grp.Gid {
		return nil
	}
	gids, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("lookup user groups for uid %d: %w", cred.uid, err)
	}
	if slices.Contains(gids, grp.Gid) {
		return nil
	}
	return fmt.Errorf("access denied: uid %d is not a member of group %s", cred.uid, group)
}
