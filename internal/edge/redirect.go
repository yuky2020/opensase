package edge

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"sync"
)

// Per-device inspection redirect (issue #22). Only the tunnel addresses of devices whose
// policy needs the inspection path (TLS inspection on, or web rules for plain HTTP) are
// REDIRECTed to the inspection listener; every other device's web traffic is forwarded by
// the kernel as before, without the userspace proxy.
//
// PREROUTING jumps to the OSASE_INSPECT chain for tunnel TCP to ports 80 and 443 (synthetic
// ZTNA addresses excluded). The chain holds one "-s <addr>/32 -j REDIRECT" rule per device. The
// Edge reconciles it after every peer sync and synchronously when a session is set up, so a
// device's first connection already takes the right path. If the chain cannot be managed
// (no NET_ADMIN), the Edge falls back to redirecting every device: still correct, because
// devices without inspection are spliced.

const inspectChain = "OSASE_INSPECT"

type inspectRedirect struct {
	mu      sync.Mutex
	ipt     func(ctx context.Context, args ...string) error
	port    string
	active  bool                // the chain is managed per device
	applied map[netip.Addr]bool // addresses with a rule in the chain
}

func runIPTables(ctx context.Context, args ...string) error {
	all := append([]string{"-w", "5"}, args...)
	out, err := exec.CommandContext(ctx, "iptables", all...).CombinedOutput() //nolint:gosec // G204: fixed binary; args from Edge config, constants and parsed addresses
	if err != nil {
		return fmt.Errorf("iptables %v: %w: %s", all, err, bytes.TrimSpace(out))
	}
	return nil
}

// setupInspectRedirect prepares the chain and the jump, replacing the blanket REDIRECT rule
// of older Edges and entrypoints. It returns false (fall back to redirecting everyone) if the
// kernel rules cannot be managed.
func (e *Edge) setupInspectRedirect(ctx context.Context, tunName string) bool {
	_, port, err := net.SplitHostPort(e.cfg.InspectListen)
	if err != nil {
		return false
	}
	r := e.redir
	r.port = port
	ipt := r.ipt
	jump := []string{"PREROUTING", "-i", tunName, "!", "-d", SyntheticPrefix.String(), "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", inspectChain}
	blanket := []string{"PREROUTING", "-i", tunName, "!", "-d", SyntheticPrefix.String(), "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "REDIRECT", "--to-ports", port}
	_ = ipt(ctx, "-t", "nat", "-N", inspectChain) // exists after a restart
	if err := ipt(ctx, "-t", "nat", "-F", inspectChain); err != nil {
		e.log.Warn("inspection: per-device redirect unavailable, redirecting every device", "err", err)
		return false
	}
	if ipt(ctx, append([]string{"-t", "nat", "-C"}, jump...)...) != nil {
		if err := ipt(ctx, append([]string{"-t", "nat", "-A"}, jump...)...); err != nil {
			e.log.Warn("inspection: per-device redirect unavailable, redirecting every device", "err", err)
			return false
		}
	}
	// The blanket rule, if present, would send everyone to the listener: remove it.
	for range 4 {
		if ipt(ctx, append([]string{"-t", "nat", "-D"}, blanket...)...) != nil {
			break
		}
	}
	r.mu.Lock()
	r.active, r.applied = true, map[netip.Addr]bool{}
	r.mu.Unlock()
	e.log.Info("inspection: per-device redirect active", "chain", inspectChain, "port", port)
	return true
}

// wantsInspection reports whether a device's web traffic must go through the listener.
func wantsInspection(d *device) bool {
	c := d.compiled.Load()
	return c != nil && d.ip4.IsValid() && (c.InspectEnabled() || c.HasWebRules())
}

// reconcileInspect makes the chain hold exactly the devices that want inspection.
func (e *Edge) reconcileInspect(ctx context.Context) {
	r := e.redir
	if r == nil {
		return
	}
	e.reg.mu.Lock()
	want := map[netip.Addr]bool{}
	for _, d := range e.reg.devices {
		if wantsInspection(d) {
			want[d.ip4] = true
		}
	}
	e.reg.mu.Unlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active {
		return
	}
	rule := func(op string, a netip.Addr) error {
		return r.ipt(ctx, "-t", "nat", op, inspectChain, "-s", netip.PrefixFrom(a, 32).String(), "-p", "tcp", "-j", "REDIRECT", "--to-ports", r.port)
	}
	var add, del []netip.Addr
	for a := range want {
		if !r.applied[a] {
			add = append(add, a)
		}
	}
	for a := range r.applied {
		if !want[a] {
			del = append(del, a)
		}
	}
	slices.SortFunc(add, func(x, y netip.Addr) int { return x.Compare(y) })
	for _, a := range add {
		if err := rule("-A", a); err != nil {
			e.log.Error("inspection redirect not added", "addr", a, "err", err)
			continue
		}
		r.applied[a] = true
	}
	for _, a := range del {
		if err := rule("-D", a); err != nil {
			e.log.Warn("inspection redirect not removed", "addr", a, "err", err)
		}
		delete(r.applied, a)
	}
}
