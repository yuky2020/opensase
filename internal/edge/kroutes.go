package edge

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"slices"
	"sync"
	"time"
)

// kernelRoutes manages kernel routing table entries for routed workload subnets
// on the Edge TUN interface.
type kernelRoutes struct {
	mu        sync.Mutex
	tunName   string
	log       *slog.Logger
	runner    func(ctx context.Context, args ...string) error
	installed map[netip.Prefix]bool
}

func newKernelRoutes(tunName string, log *slog.Logger) *kernelRoutes {
	if log == nil {
		log = slog.Default()
	}
	return &kernelRoutes{
		tunName:   tunName,
		log:       log,
		runner:    defaultIPRunner,
		installed: make(map[netip.Prefix]bool),
	}
}

func defaultIPRunner(ctx context.Context, args ...string) error {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(tctx, "ip", args...).CombinedOutput() //nolint:gosec // G204: fixed binary; args from Edge config and validated prefixes
	if err != nil {
		return fmt.Errorf("ip %v: %w: %s", args, err, bytes.TrimSpace(out))
	}
	return nil
}

// sync reconciles installed kernel routes with the union of wanted IPv4 prefixes.
func (kr *kernelRoutes) sync(ctx context.Context, want []netip.Prefix) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.tunName == "" {
		return
	}

	wantSet := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		if p.IsValid() && p.Addr().Is4() {
			wantSet[p.Masked()] = true
		}
	}

	if kr.installed == nil {
		kr.installed = make(map[netip.Prefix]bool)
	}

	var toAdd, toDel []netip.Prefix
	for p := range wantSet {
		if !kr.installed[p] {
			toAdd = append(toAdd, p)
		}
	}
	for p := range kr.installed {
		if !wantSet[p] {
			toDel = append(toDel, p)
		}
	}

	slices.SortFunc(toAdd, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	slices.SortFunc(toDel, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})

	run := kr.runner
	if run == nil {
		run = defaultIPRunner
	}

	for _, p := range toAdd {
		if err := run(ctx, "route", "replace", p.String(), "dev", kr.tunName); err != nil {
			if kr.log != nil {
				kr.log.Error("kernel route replace failed", "prefix", p, "err", err)
			}
			continue
		}
		kr.installed[p] = true
	}

	for _, p := range toDel {
		if err := run(ctx, "route", "del", p.String(), "dev", kr.tunName); err != nil {
			if kr.log != nil {
				kr.log.Error("kernel route del failed", "prefix", p, "err", err)
			}
			continue
		}
		delete(kr.installed, p)
	}
}

// Sync aliases sync for external or test callers.
func (kr *kernelRoutes) Sync(ctx context.Context, want []netip.Prefix) {
	kr.sync(ctx, want)
}
