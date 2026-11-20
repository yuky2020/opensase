package controlplane

import (
	"crypto"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

// --- certificate renewal (security review #4) ---

// handleRenew issues a new device certificate for a NEW key and atomically replaces the
// serial on record, so the presented certificate stops working on every other route.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	var req api.RenewRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	csr, err := pki.ParseCSR([]byte(req.CSRPEM))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if k, ok := csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || k.Equal(leaf.PublicKey) {
		writeErr(w, http.StatusBadRequest, "renewal requires a newly generated key")
		return
	}
	ca, err := s.cfg.Authority.TenantCA(p.device.TenantID)
	if err != nil {
		s.internalErr(w, r, "tenant CA", err)
		return
	}
	chain, cert, err := ca.SignDeviceCSR([]byte(req.CSRPEM), p.device.TenantID, p.device.ID, pki.DeviceValidity)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "CSR rejected: device key must be ECDSA P-256")
		return
	}
	err = s.cfg.Store.RenewDeviceCert(r.Context(), p.device.ID, leaf.SerialNumber.String(), cert.SerialNumber.String())
	switch {
	case errors.Is(err, store.ErrRevoked), errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusForbidden, "device revoked")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "certificate was renewed concurrently; use the newest certificate")
		return
	case err != nil:
		s.internalErr(w, r, "renew", err)
		return
	}
	s.log.InfoContext(r.Context(), "device certificate renewed", "tenant", p.device.TenantID, "device", p.device.ID, "notAfter", cert.NotAfter)
	writeJSON(w, http.StatusOK, api.RenewResponse{
		CertificatePEM: string(chain),
		CAPEM:          string(append(s.cfg.Authority.Root.CertPEM(), ca.CertPEM()...)),
	})
}

// --- edge registry and live sessions (security review #9) ---

// EdgeSessions is the body of POST /v1/edge/sessions: the devices that currently have a
// WireGuard peer on the reporting edge, and the connectors with a live broker connection.
type EdgeSessions = api.EdgeSessions

// AdminEdge is the admin view of a registered edge (see the CONTRACT-CHANGE-REQUEST in Handler).
type AdminEdge struct {
	ID        string    `json:"id"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"createdAt,omitzero"`
}

func (s *Server) handleEdgeSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	var b EdgeSessions
	if !decodeJSON(w, r, &b) {
		return
	}
	if len(b.DeviceIDs)+len(b.ConnectorIDs) > maxSessionIDs {
		writeErr(w, http.StatusRequestEntityTooLarge, "too many IDs")
		return
	}
	if err := s.cfg.Store.ReportEdgeSessions(r.Context(), p.id.EdgeID, b.DeviceIDs, s.now(), edgeSessionTTL); err != nil {
		s.internalErr(w, r, "edge sessions", err)
		return
	}
	if err := s.cfg.Store.TouchConnectors(r.Context(), b.ConnectorIDs, s.now()); err != nil {
		s.internalErr(w, r, "connector last seen", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// edgeDevice returns the device an edge acts for, only if it is not revoked and the edge
// reported a live session for it recently.
func (s *Server) edgeDevice(r *http.Request, edgeID, deviceID string) (store.Device, bool, error) {
	d, err := s.cfg.Store.GetDevice(r.Context(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return d, false, nil
	}
	if err != nil {
		return d, false, err
	}
	if d.Revoked {
		return d, false, nil
	}
	ok, err := s.cfg.Store.EdgeHasSession(r.Context(), edgeID, deviceID, s.now().Add(-edgeSessionTTL))
	return d, ok, err
}

func (s *Server) handleCreateEdge(w http.ResponseWriter, r *http.Request) {
	var e AdminEdge
	if !decodeJSON(w, r, &e) {
		return
	}
	if !pki.ValidID(e.ID) || e.Revoked {
		writeErr(w, http.StatusBadRequest, "id must be a valid identifier")
		return
	}
	err := s.cfg.Store.CreateEdge(r.Context(), e.ID)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "edge exists (revoked edge IDs cannot be reused)")
		return
	}
	if err != nil {
		s.internalErr(w, r, "create edge", err)
		return
	}
	s.notify.notify(notifyEdges)
	s.log.InfoContext(r.Context(), "edge registered", "edge", e.ID)
	writeJSON(w, http.StatusCreated, AdminEdge{ID: e.ID})
}

func (s *Server) handleListEdges(w http.ResponseWriter, r *http.Request) {
	es, err := s.cfg.Store.ListEdges(r.Context())
	if err != nil {
		s.internalErr(w, r, "list edges", err)
		return
	}
	out := make([]AdminEdge, 0, len(es))
	for _, e := range es {
		out = append(out, AdminEdge{ID: e.ID, Revoked: e.Revoked, CreatedAt: e.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeEdge(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "e")
	err := s.cfg.Store.RevokeEdge(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "unknown edge")
		return
	}
	if err != nil {
		s.internalErr(w, r, "revoke edge", err)
		return
	}
	s.notify.notify(notifyEdges)
	s.log.InfoContext(r.Context(), "edge revoked", "edge", id)
	w.WriteHeader(http.StatusNoContent)
}

// --- resource limits (security reviews #8, #10) ---

// pollLimiter caps concurrent snapshot long-polls per device.
type pollLimiter struct {
	max int
	mu  sync.Mutex
	n   map[string]int
}

func newPollLimiter(max int) *pollLimiter { return &pollLimiter{max: max, n: map[string]int{}} }

func (l *pollLimiter) acquire(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[id] >= l.max {
		return false
	}
	l.n[id]++
	return true
}

func (l *pollLimiter) release(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[id]--; l.n[id] <= 0 {
		delete(l.n, id)
	}
}

// rateLimiter is a fixed-window counter per key (device ID).
type rateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu sync.Mutex
	m  map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	n     int
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, now: now, m: map[string]*rateWindow{}}
}

// take reserves up to n units for key and returns how many were granted.
func (l *rateLimiter) take(key string, n int) int {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.m[key]
	if !ok || now.Sub(w.start) >= l.window {
		w = &rateWindow{start: now}
		l.m[key] = w
	}
	got := min(n, l.limit-w.n)
	if got <= 0 {
		return 0
	}
	w.n += got
	return got
}

// prune forgets expired windows.
func (l *rateLimiter) prune() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.m {
		if now.Sub(w.start) >= l.window {
			delete(l.m, k)
		}
	}
}

// maxSessionIDs bounds one POST /v1/edge/sessions body (1 MiB body limit applies too).
const maxSessionIDs = 20000

// Bounds applied to device- and edge-reported flow records.
const (
	flowPast      = 24 * time.Hour
	flowFuture    = 5 * time.Minute
	maxFlowBytes  = 1 << 40 // 1 TiB per flow
	maxDomainLen  = 253
	maxStringLen  = 256
	maxRuleIDLen  = 128
	maxDstIPLen   = 45
	maxProtoLen   = 8
	maxNetworkLen = 16
)

func clampTime(t, lo, hi time.Time) time.Time {
	switch {
	case t.Before(lo):
		return lo
	case t.After(hi):
		return hi
	}
	return t
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// sanitizeFlow clamps the times of a reported record to [now-24h, now+5m] (End is never
// before Start), the byte counters to 1 TiB, and the free-form strings to sane lengths.
func sanitizeFlow(rec api.FlowRecord, now time.Time) api.FlowRecord {
	lo, hi := now.Add(-flowPast), now.Add(flowFuture)
	rec.Start = clampTime(rec.Start, lo, hi)
	if !rec.End.IsZero() {
		rec.End = clampTime(rec.End, rec.Start, hi)
	}
	rec.BytesIn, rec.BytesOut = min(rec.BytesIn, maxFlowBytes), min(rec.BytesOut, maxFlowBytes)
	f := &rec.Flow
	f.Domain = truncate(f.Domain, maxDomainLen)
	f.App = truncate(f.App, maxStringLen)
	f.DstIP = truncate(f.DstIP, maxDstIPLen)
	f.Protocol = truncate(f.Protocol, maxProtoLen)
	f.Network = policy.NetworkType(truncate(string(f.Network), maxNetworkLen))
	rec.Decision.RuleID = truncate(rec.Decision.RuleID, maxRuleIDLen)
	rec.Decision.Layer = truncate(rec.Decision.Layer, maxProtoLen*2)
	return rec
}
