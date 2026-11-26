package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

const (
	maxPostureStringLen    = 64
	defaultPostureInterval = 15 * time.Minute
	defaultPostureDelay    = 5 * time.Second
)

func defaultClientVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

func clonePosture(p *api.Posture) *api.Posture {
	if p == nil {
		return nil
	}
	cp := *p
	cp.DiskEncrypted = cloneBool(p.DiskEncrypted)
	cp.ScreenLock = cloneBool(p.ScreenLock)
	cp.Firewall = cloneBool(p.Firewall)
	cp.Managed = cloneBool(p.Managed)
	return &cp
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func postureEqual(a, b *api.Posture) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.OS == b.OS &&
		a.OSVersion == b.OSVersion &&
		a.ClientVersion == b.ClientVersion &&
		boolPtrEqual(a.DiskEncrypted, b.DiskEncrypted) &&
		boolPtrEqual(a.ScreenLock, b.ScreenLock) &&
		boolPtrEqual(a.Firewall, b.Firewall) &&
		boolPtrEqual(a.Managed, b.Managed) &&
		a.BootTime.Equal(b.BootTime)
}

// SetPosture parses postureJSON into api.Posture, validates string lengths, fills
// ClientVersion (if empty) and CollectedAt, stores it under a mutex, and signals the
// posture loop if it differs from the previous one (ignoring CollectedAt).
func (e *Engine) SetPosture(postureJSON string) error {
	var p api.Posture
	if err := json.Unmarshal([]byte(postureJSON), &p); err != nil {
		return fmt.Errorf("mobile: set posture: invalid JSON: %w", err)
	}
	if len(p.OS) > maxPostureStringLen || len(p.OSVersion) > maxPostureStringLen || len(p.ClientVersion) > maxPostureStringLen {
		return fmt.Errorf("mobile: set posture: string field longer than %d bytes", maxPostureStringLen)
	}
	if p.ClientVersion == "" {
		p.ClientVersion = defaultClientVersion()
	}
	p.CollectedAt = time.Now().UTC()

	e.postureMu.Lock()
	prev := e.posture
	differs := !postureEqual(prev, &p)
	e.posture = clonePosture(&p)
	e.postureMu.Unlock()

	if differs {
		if rs := e.running.Load(); rs != nil {
			rs.notifyPosture()
		}
	}
	return nil
}

func (e *Engine) getPosture() *api.Posture {
	e.postureMu.RLock()
	defer e.postureMu.RUnlock()
	return clonePosture(e.posture)
}

func (rs *runState) notifyPosture() {
	select {
	case rs.postureNotify <- struct{}{}:
	default:
	}
}

// postureLoop reports the stored device posture at start, every 15 minutes, and within 5 seconds after a change.
func (e *Engine) postureLoop(rs *runState) {
	defer rs.wg.Done()
	interval := e.postureInterval
	if interval <= 0 {
		interval = defaultPostureInterval
	}
	changeDelay := e.postureDelay
	if changeDelay <= 0 {
		changeDelay = defaultPostureDelay
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Report at start: skip if no posture was set.
	_ = e.sendPosture(rs.ctx, rs)

	var changeTimer *time.Timer
	var changeC <-chan time.Time

	for {
		select {
		case <-rs.ctx.Done():
			if changeTimer != nil {
				changeTimer.Stop()
			}
			return
		case <-rs.postureNotify:
			if changeTimer == nil {
				changeTimer = time.NewTimer(changeDelay)
				changeC = changeTimer.C
			}
		case <-changeC:
			changeTimer = nil
			changeC = nil
			_ = e.sendPosture(rs.ctx, rs)
		case <-ticker.C:
			if changeTimer != nil {
				if !changeTimer.Stop() {
					select {
					case <-changeTimer.C:
					default:
					}
				}
				changeTimer = nil
				changeC = nil
			}
			_ = e.sendPosture(rs.ctx, rs)
		}
	}
}

func (e *Engine) sendPosture(ctx context.Context, rs *runState) error {
	p := e.getPosture()
	if p == nil {
		return nil
	}
	u := joinURL(rs.id.resp.ControlURL, "/v1/posture")
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := doJSON(reqCtx, rs.id.cp, http.MethodPost, u, nil, p, nil)
	if err != nil {
		if ctx.Err() == nil {
			e.log.Warn("posture report failed", "err", err)
		}
		return err
	}
	e.log.Info("posture reported", "os", p.OS, "osVersion", p.OSVersion, "clientVersion", p.ClientVersion)
	return nil
}
