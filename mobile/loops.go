package mobile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

const (
	maxPendingFlows = 10000
	maxFlowBatch    = 1000
)

// backoff is exponential with full jitter.
type backoff struct {
	min, max time.Duration
	cur      time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.min
	} else {
		b.cur = min(b.cur*2, b.max)
	}
	return b.cur/2 + rand.N(b.cur/2+1) //nolint:gosec // G404: retry jitter, not security relevant
}

func (b *backoff) reset() { b.cur = 0 }

// sleep waits for d or until ctx is done; it reports whether ctx is still live.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func snapshotKeys(keys []api.SigningKey) map[string]ed25519.PublicKey {
	m := make(map[string]ed25519.PublicKey, len(keys))
	for _, k := range keys {
		if k.Algorithm == policy.AlgEd25519 && len(k.PublicKey) == ed25519.PublicKeySize {
			m[k.KeyID] = ed25519.PublicKey(k.PublicKey)
		}
	}
	return m
}

// loadCachedSnapshot verifies and installs the persisted envelope (offline start).
func (e *Engine) loadCachedSnapshot() error {
	id := e.en.Load()
	b, err := readStateFile(e.stateDir, fileSnapshot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var env policy.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	_, err = e.installEnvelope(id, &env, false)
	return err
}

// applyEnvelope verifies, installs and persists env. On an unknown signing key it refreshes
// the snapshot keys from GET /v1/pki/ca and retries once. The refresh is only accepted
// over a connection that proved the Control Plane identity (review #1: an Edge
// certificate chains to the same CA and must not be able to install snapshot keys).
func (e *Engine) applyEnvelope(ctx context.Context, id *identity, env *policy.Envelope) (bool, error) {
	changed, err := e.installEnvelope(id, env, true)
	if !errors.Is(err, policy.ErrUnknownKey) {
		return changed, err
	}
	var bundle api.PKIBundle
	httpResp, ferr := doJSON(ctx, id.cp, http.MethodGet, joinURL(id.resp.ControlURL, "/v1/pki/ca"), nil, nil, &bundle)
	if ferr != nil {
		return false, errors.Join(err, ferr)
	}
	// id.cp already enforces this per connection; checked again here because installing
	// snapshot keys is the decision that matters.
	if httpResp.TLS == nil {
		return false, errors.Join(err, errors.New("mobile: /v1/pki/ca without TLS state"))
	}
	if verr := pki.ExpectServer(pki.ServerControlPlane, "")(*httpResp.TLS); verr != nil {
		return false, errors.Join(err, fmt.Errorf("mobile: /v1/pki/ca: %w", verr))
	}
	keys := snapshotKeys(bundle.SnapshotKeys)
	if len(keys) == 0 {
		return false, err
	}
	added, removed := keyDiff(*id.keys.Load(), keys)
	resp := id.resp
	resp.SnapshotKeys = bundle.SnapshotKeys
	if b, merr := json.Marshal(&resp); merr == nil {
		if werr := writeFileAtomic(e.stateDir, fileEnrollment, b); werr != nil {
			return false, werr
		}
	}
	id.keys.Store(&keys)
	// Logged as a Warn "log" event so the app (and the user) can see a trust change.
	e.log.Warn("snapshot signing keys changed", "added", added, "removed", removed, "keys", len(keys))
	return e.installEnvelope(id, env, true)
}

// keyDiff returns the key IDs only in next (added) and only in cur (removed), sorted.
func keyDiff(cur, next map[string]ed25519.PublicKey) (added, removed []string) {
	for k, v := range next {
		if old, ok := cur[k]; !ok || !old.Equal(v) {
			added = append(added, k)
		}
	}
	for k, v := range cur {
		if nv, ok := next[k]; !ok || !nv.Equal(v) {
			removed = append(removed, k)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

// installEnvelope verifies env with the enrolled keys and swaps it in if it is newer.
func (e *Engine) installEnvelope(id *identity, env *policy.Envelope, persist bool) (bool, error) {
	if id == nil {
		return false, errors.New("mobile: not enrolled")
	}
	s, err := policy.Verify(env, *id.keys.Load())
	if err != nil {
		return false, err
	}
	if s.DeviceID != id.resp.DeviceID || s.TenantID != id.resp.TenantID {
		return false, fmt.Errorf("mobile: snapshot for device %q/tenant %q, this is %q/%q", s.DeviceID, s.TenantID, id.resp.DeviceID, id.resp.TenantID)
	}
	c, err := policy.Compile(s)
	if err != nil {
		return false, err
	}
	e.snapMu.Lock()
	if e.snap != nil && s.Version <= e.snap.Version {
		e.snapMu.Unlock()
		return false, nil // same or older: rollback protection
	}
	e.snap, e.snapPayload, e.compiled = s, append([]byte(nil), env.Payload...), c
	e.snapMu.Unlock()

	if rs := e.running.Load(); rs != nil {
		rs.fw.SetPolicy(c, s.Firewall.DefaultAction)
	}
	if persist {
		if b, err := json.Marshal(env); err == nil {
			if err := writeFileAtomic(e.stateDir, fileSnapshot, b); err != nil {
				e.log.Warn("persist snapshot", "err", err)
			}
		}
	}
	stale := s.Stale(time.Now())
	e.emit("snapshot", map[string]any{"version": s.Version, "stale": stale, "issuedAt": s.IssuedAt, "expiresAt": s.ExpiresAt})
	e.log.Info("policy snapshot installed", "version", s.Version, "stale", stale)
	return true, nil
}

func (e *Engine) currentVersion() uint64 {
	e.snapMu.RLock()
	defer e.snapMu.RUnlock()
	if e.snap == nil {
		return 0
	}
	return e.snap.Version
}

// snapshotLoop long-polls GET /v1/snapshot?wait=N with If-None-Match.
func (e *Engine) snapshotLoop(rs *runState) {
	defer rs.wg.Done()
	bo := backoff{min: time.Second, max: time.Minute}
	for rs.ctx.Err() == nil {
		if err := e.pollSnapshot(rs.ctx, rs.id, e.pollWait); err != nil {
			if rs.ctx.Err() != nil {
				return
			}
			e.log.Warn("snapshot poll failed", "err", err)
			e.emitError("snapshot", err)
			if !sleep(rs.ctx, bo.next()) {
				return
			}
			continue
		}
		bo.reset()
	}
}

// pollSnapshot fetches the snapshot; wait > 0 long-polls for up to wait seconds.
func (e *Engine) pollSnapshot(ctx context.Context, id *identity, wait int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(wait)*time.Second+20*time.Second)
	defer cancel()
	hdr := http.Header{}
	if v := e.currentVersion(); v > 0 {
		hdr.Set("If-None-Match", `"`+strconv.FormatUint(v, 10)+`"`)
	}
	u := joinURL(id.resp.ControlURL, "/v1/snapshot")
	if wait > 0 {
		u += "?wait=" + strconv.Itoa(wait)
	}
	var env policy.Envelope
	_, err := doJSON(ctx, id.cp, http.MethodGet, u, hdr, nil, &env)
	var he *httpError
	if errors.As(err, &he) && he.Status == http.StatusNotModified {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = e.applyEnvelope(ctx, id, &env)
	return err
}

// flowLoop uploads flow records every flowInterval (POST /v1/flows), backing off on errors.
func (e *Engine) flowLoop(rs *runState) {
	defer rs.wg.Done()
	bo := backoff{min: e.flowInterval, max: 8 * e.flowInterval}
	wait := e.flowInterval
	for sleep(rs.ctx, wait) {
		if err := e.uploadFlows(rs.ctx, rs); err != nil {
			if rs.ctx.Err() != nil {
				return
			}
			e.log.Warn("flow upload failed", "err", err, "pending", len(rs.pendingFlows))
			wait = bo.next()
			continue
		}
		bo.reset()
		wait = e.flowInterval
	}
}

// uploadFlows sends pending and newly drained records and experience samples. Only the
// flow loop and Stop (after the loop has exited) call it.
func (e *Engine) uploadFlows(ctx context.Context, rs *runState) error {
	rs.pendingFlows = append(rs.pendingFlows, rs.fw.Drain()...)
	if over := len(rs.pendingFlows) - maxPendingFlows; over > 0 {
		rs.pendingFlows = rs.pendingFlows[over:] // keep the newest
	}
	probes := rs.takeSamples(maxSampleBatch)
	if len(rs.pendingFlows) == 0 && len(probes) == 0 {
		return nil
	}
	if len(rs.pendingFlows) == 0 {
		batch := api.FlowBatch{Probes: probes}
		if _, err := doJSON(ctx, rs.id.cp, http.MethodPost, joinURL(rs.id.resp.ControlURL, "/v1/flows"), nil, &batch, nil); err != nil {
			return err
		}
		rs.clearSamples(len(probes))
		return nil
	}
	for len(rs.pendingFlows) > 0 {
		n := min(len(rs.pendingFlows), maxFlowBatch)
		batch := api.FlowBatch{Records: rs.pendingFlows[:n], Probes: probes}
		if _, err := doJSON(ctx, rs.id.cp, http.MethodPost, joinURL(rs.id.resp.ControlURL, "/v1/flows"), nil, &batch, nil); err != nil {
			return err
		}
		if len(probes) > 0 {
			rs.clearSamples(len(probes))
			probes = nil
		}
		rs.pendingFlows = rs.pendingFlows[n:]
	}
	rs.pendingFlows = nil
	return nil
}

const experienceProbes = 5

// experienceLoop collects digital experience samples every experienceInterval (60 s) while a session is up.
func (e *Engine) experienceLoop(rs *runState) {
	defer rs.wg.Done()
	interval := e.experienceInterval
	if interval <= 0 {
		interval = defaultExperienceInterval
	}
	probeTimeout := e.experienceProbeTimeout
	if probeTimeout <= 0 {
		probeTimeout = defaultExperienceProbeTimeout
	}
	for sleep(rs.ctx, interval) {
		if !e.isConnected() {
			continue
		}
		sess := rs.session()
		if sess == nil || sess.edge.ID == "" {
			continue
		}
		var rtts []time.Duration
		for j := 0; j < experienceProbes; j++ {
			if rs.ctx.Err() != nil {
				return
			}
			ctx, cancel := context.WithTimeout(rs.ctx, probeTimeout)
			start := time.Now()
			live, err := e.probeSession(ctx, rs, sess)
			d := time.Since(start)
			cancel()
			if err == nil && live {
				rtts = append(rtts, d)
			}
		}
		unanswered := experienceProbes - len(rtts)
		var dnsTimes []time.Duration
		if rs.dns != nil {
			dnsTimes = rs.dns.TakeDNSTimes()
		}
		netType := ""
		if nt := e.network.Load(); nt != nil {
			netType = string(*nt)
		}
		sample := api.ExperienceSample{
			At:      time.Now().UTC(),
			EdgeID:  sess.edge.ID,
			RTTms:   medianMs(rtts),
			LossPct: lossPct(unanswered, experienceProbes),
			DNSms:   medianMs(dnsTimes),
			Network: netType,
		}
		rs.addExperienceSample(sample)
	}
}

// medianMs returns the median of ds in milliseconds. If ds is empty, it returns 0.
func medianMs(ds []time.Duration) float64 {
	if len(ds) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	slices.Sort(sorted)
	n := len(sorted)
	if n%2 == 1 {
		return float64(sorted[n/2]) / float64(time.Millisecond)
	}
	return (float64(sorted[n/2-1]) + float64(sorted[n/2])) / (2 * float64(time.Millisecond))
}

// lossPct calculates the loss percentage given unanswered probes out of total.
func lossPct(unanswered, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(100*unanswered) / float64(total)
}

// sessionLoop keeps the Edge session alive (review #5):
//   - every RotateAfterSec it rotates the PSK (next epoch on the same session);
//   - if a rotation fails for any reason (409 because the Edge already committed the next
//     epoch, a lost response, a timeout), it falls back to a new session at epoch 0 with a
//     new WireGuard key and a full WireGuard reconfiguration; until that succeeds the
//     current configuration stays in place;
//   - every livenessInterval it checks the WireGuard last handshake: older than
//     livenessTimeout while connected means the tunnel is dead, so the state goes to
//     "connecting" and a new session is set up.
func (e *Engine) sessionLoop(rs *runState) {
	defer rs.wg.Done()
	bo := backoff{min: 5 * time.Second, max: 2 * time.Minute}
	next := time.Now().Add(rs.session().rotateAfter())
	reset := false // the next attempt is a new session, not a rotation
	avoid := ""    // Edge to try last on the next new session (it stopped answering)
	pr := prober{lastRx: time.Now()}
	tick := min(e.livenessInterval, e.probeInterval, sessionTick)
	for {
		wait := tick
		if pr.failures > 0 {
			wait = min(wait, probeRetry)
		}
		if !sleep(rs.ctx, max(0, min(time.Until(next), wait))) {
			return
		}
		now := time.Now()
		if !reset {
			hs, _, rx := peerStats(rs.dev)
			if age := e.handshakeAge(rs, hs, now); age > e.livenessTimeout {
				e.log.Warn("WireGuard handshake is stale; setting up a new session", "age", age.Round(time.Second).String())
				e.setState(StateConnecting, "tunnel down: no WireGuard handshake")
				reset, next, avoid = true, now, rs.session().edge.ID
			} else if why, edgeDown := e.probe(rs, &pr, rx, now); why != "" {
				e.log.Warn("Edge session lost; setting up a new session", "edge", rs.session().edge.ID, "reason", why)
				e.setState(StateConnecting, "tunnel down: "+why)
				reset, next = true, now
				if edgeDown {
					avoid = rs.session().edge.ID
				}
			} else if e.failbackDue(rs, now) {
				if err := e.failback(rs); err != nil {
					e.log.Info("preferred Edge still unavailable", "err", err)
				}
				pr = prober{lastRx: time.Now()}
			}
		}
		if now.Before(next) {
			continue
		}
		var err error
		if !reset {
			if err = e.rotate(rs); err != nil && rs.ctx.Err() == nil {
				e.log.Warn("PSK rotation failed; falling back to a new session", "err", err)
				e.emitError("rotate", err)
				reset = true
			}
		}
		if reset {
			err = e.resetSession(rs, avoid)
		}
		if err != nil {
			if rs.ctx.Err() != nil {
				return
			}
			e.log.Warn("session setup failed; retrying", "err", err)
			e.emitError("session", err)
			next = time.Now().Add(bo.next())
			continue
		}
		reset, avoid = false, ""
		pr = prober{lastRx: time.Now()}
		bo.reset()
		next = time.Now().Add(rs.session().rotateAfter())
	}
}

// prober tracks tunnel activity between session probes (issue #70).
type prober struct {
	rx       uint64    // last received byte count
	lastRx   time.Time // when rx last grew
	lastSent time.Time // last probe
	failures int       // consecutive unanswered probes
}

// probe checks the session when the tunnel has been idle for probeIdle. It returns a reason
// when a new session is needed, and edgeDown when the Edge itself did not answer.
func (e *Engine) probe(rs *runState, p *prober, rx uint64, now time.Time) (why string, edgeDown bool) {
	if rx != p.rx {
		p.rx, p.lastRx, p.failures = rx, now, 0
		return "", false
	}
	interval := e.probeInterval
	if p.failures > 0 {
		interval = min(interval, probeRetry)
	}
	if now.Sub(p.lastRx) < e.probeIdle || now.Sub(p.lastSent) < interval {
		return "", false
	}
	p.lastSent = now
	sess := rs.session()
	ctx, cancel := context.WithTimeout(rs.ctx, e.probeTimeout)
	live, err := e.probeSession(ctx, rs, sess)
	cancel()
	switch {
	case err != nil:
		p.failures++
		e.log.Debug("session probe failed", "edge", sess.edge.ID, "failures", p.failures, "err", err)
		if p.failures >= probeFailures {
			return fmt.Sprintf("Edge %s not answering", sess.edge.ID), true
		}
	case !live:
		return fmt.Sprintf("Edge %s no longer has the session (restarted?)", sess.edge.ID), false
	default:
		p.failures = 0
	}
	return "", false
}

// probeSession asks the session's Edge whether the session is live (GET /v1/session/{id}).
// The probe connection is kept for the next probes, so idle probing does not repeat the
// post-quantum handshake.
func (e *Engine) probeSession(ctx context.Context, rs *runState, sess *session) (bool, error) {
	rs.sessMu.Lock()
	if rs.probeEdge != sess.edge.ID || rs.probeClient == nil {
		if rs.probeClient != nil {
			rs.probeClient.CloseIdleConnections()
		}
		rs.probeClient = &http.Client{Transport: pqTransport(mtlsConfig(rs.id.enrollment, pki.ServerEdge, sess.edge.ID), e.protect, e.hosts, true)}
		rs.probeEdge = sess.edge.ID
	}
	c := rs.probeClient
	rs.sessMu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(sess.edge.SessionURL, "/v1/session/"+url.PathEscape(sess.resp.SessionID)), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("probe: HTTP %d", resp.StatusCode)
	}
}

// closeProbeLocked drops the probe connection. Caller holds sessMu.
func (rs *runState) closeProbeLocked() {
	if rs.probeClient != nil {
		rs.probeClient.CloseIdleConnections()
		rs.probeClient, rs.probeEdge = nil, ""
	}
}

// failbackDue reports whether the client runs on a backup Edge and has been stable there for
// failbackAfter, so it should try the preferred (first) Edge again.
func (e *Engine) failbackDue(rs *runState, now time.Time) bool {
	edges := rs.id.edgeList()
	if len(edges) < 2 {
		return false
	}
	rs.sessMu.Lock()
	defer rs.sessMu.Unlock()
	if rs.sess.edge.ID == edges[0].ID || now.Sub(rs.sessSince) < e.failbackAfter || now.Sub(rs.failbackTried) < e.failbackAfter {
		return false
	}
	rs.failbackTried = now
	return true
}

// failback moves the tunnel back to the preferred Edge if it accepts a new session.
func (e *Engine) failback(rs *runState) error {
	ctx, cancel := context.WithTimeout(rs.ctx, 20*time.Second)
	defer cancel()
	next, err := e.setupSession(ctx, rs.id.enrollment, rs.id.edgeList()[0], nil)
	if err != nil {
		return err
	}
	if err := e.install(rs, next); err != nil {
		return err
	}
	e.log.Info("back on the preferred Edge", "edge", next.edge.ID)
	return nil
}

// session returns the current session.
func (rs *runState) session() *session {
	rs.sessMu.Lock()
	defer rs.sessMu.Unlock()
	return rs.sess
}

// handshakeAge is the time since the last WireGuard handshake (hs, unix seconds; 0 =
// never), counted from the current session's setup if that is more recent.
func (e *Engine) handshakeAge(rs *runState, hs int64, now time.Time) time.Duration {
	rs.sessMu.Lock()
	ref := rs.sessSince
	rs.sessMu.Unlock()
	if t := time.Unix(hs, 0); hs > 0 && t.After(ref) {
		ref = t
	}
	return now.Sub(ref)
}

// resetSession sets up a new session at epoch 0 (new WireGuard key, any Edge, avoid last)
// and reconfigures WireGuard completely. The old configuration is kept if it fails.
func (e *Engine) resetSession(rs *runState, avoid string) error {
	ctx, cancel := context.WithTimeout(rs.ctx, 45*time.Second)
	defer cancel()
	next, err := e.newSession(ctx, rs.id, avoid)
	if err != nil {
		return err
	}
	return e.install(rs, next)
}

// install replaces the running session with next (a new epoch-0 session).
func (e *Engine) install(rs *runState, next *session) error {
	cfg := uapiFull(next)
	err := rs.dev.IpcSetOperation(bytes.NewReader(cfg))
	clear(cfg)
	if err != nil {
		next.wipe()
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	rs.sessMu.Lock()
	old := rs.sess
	rs.sess, rs.sessSince = next, time.Now()
	rs.closeProbeLocked() // a new session may use a renewed certificate or another Edge
	rs.sessMu.Unlock()
	if old.resp.TunnelIPv4 != next.resp.TunnelIPv4 || old.resp.TunnelIPv6 != next.resp.TunnelIPv6 {
		// The TUN interface keeps the old addresses; the app must rebuild it. With a
		// Control Plane that assigns tunnel offsets (issue #70) this does not happen.
		e.log.Warn("tunnel address changed on the new session; reconnect required",
			"old", old.resp.TunnelIPv4, "new", next.resp.TunnelIPv4)
	}
	old.wipe()
	e.log.Info("new session established", "edge", next.edge.ID, "epoch", next.resp.Epoch)
	e.setState(StateConnected, "")
	return nil
}

func (e *Engine) rotate(rs *runState) error {
	rs.sessMu.Lock()
	cur := rs.sess
	rs.sessMu.Unlock()
	ctx, cancel := context.WithTimeout(rs.ctx, 30*time.Second)
	defer cancel()
	next, err := e.setupSession(ctx, rs.id.enrollment, cur.edge, cur)
	if err != nil {
		return err
	}
	cfg := uapiPSK(next)
	err = rs.dev.IpcSetOperation(bytes.NewReader(cfg))
	clear(cfg)
	if err != nil {
		next.wipe()
		return fmt.Errorf("install PSK: %w", err)
	}
	rs.sessMu.Lock()
	rs.sess = next
	rs.sessMu.Unlock()
	cur.wipe()
	e.log.Info("PSK rotated", "epoch", next.resp.Epoch)
	e.emit("state", map[string]any{"state": StateConnected, "epoch": next.resp.Epoch})
	return nil
}

// statsLoop emits "stats" events and a "snapshot" event when the snapshot becomes stale.
func (e *Engine) statsLoop(rs *runState) {
	defer rs.wg.Done()
	for sleep(rs.ctx, e.statsInterval) {
		e.emitRaw("stats", e.AppStats())
		e.snapMu.RLock()
		var stale bool
		var v uint64
		if e.snap != nil {
			stale, v = e.snap.Stale(time.Now()), e.snap.Version
		}
		e.snapMu.RUnlock()
		if stale && !rs.stale.Swap(true) {
			e.emit("snapshot", map[string]any{"version": v, "stale": true})
		} else if !stale {
			rs.stale.Store(false)
		}
	}
}

// cloudDecider implements firewall.Decider with POST /v1/decide.
type cloudDecider struct {
	e  *Engine
	id *identity
}

func (d cloudDecider) Decide(ctx context.Context, f policy.Flow) (policy.Decision, time.Duration, error) {
	var resp api.DecideResponse
	_, err := doJSON(ctx, d.id.cp, http.MethodPost, joinURL(d.id.resp.ControlURL, "/v1/decide"), nil, &api.DecideRequest{Flow: f}, &resp)
	if err != nil {
		return policy.Decision{}, 0, err
	}
	return resp.Decision, time.Duration(resp.TTL) * time.Second, nil
}
