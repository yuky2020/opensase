package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/store"
)

// Admin credentials (security finding ST-03). The token in Config.AdminToken is the
// super-admin. Tenant admin tokens are issued per tenant, stored as SHA-256 hashes, and
// administer that tenant only.

const (
	adminTokenPrefix       = "osa_"
	defaultAdminTokenValid = 90 * 24 * time.Hour
	maxAdminTokenValid     = 365 * 24 * time.Hour
	maxAdminTokenName      = 100
)

// adminScope is the authenticated admin of a request.
type adminScope struct {
	tenant  string // "" for the super-admin
	tokenID string
}

func (a adminScope) super() bool { return a.tenant == "" }

func adminFrom(r *http.Request) adminScope {
	a, _ := r.Context().Value(keyAdmin).(adminScope)
	return a
}

// requireAdmin authenticates "Authorization: Bearer <token>". The super-admin token is
// compared in constant time. A tenant admin token is looked up by its SHA-256: the token has
// 256 bits of entropy, so the timing of an index lookup by hash reveals nothing usable.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(s.cfg.AdminToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(tok))
		isSuper := subtle.ConstantTimeCompare(got[:], want[:]) == 1
		var scope adminScope
		authed := false
		switch {
		case !ok || tok == "":
			// no credential
		case isSuper:
			authed = true
		case strings.HasPrefix(tok, adminTokenPrefix):
			t, err := s.cfg.Store.AuthAdminToken(r.Context(), got[:], s.now())
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.internalErr(w, r, "admin token", err)
				return
			}
			if err == nil && t.TenantID != "" {
				authed = true
				scope = adminScope{tenant: t.TenantID, tokenID: t.ID}
			}
		}
		if !authed {
			w.Header().Set("WWW-Authenticate", `Bearer realm="opensase-admin"`)
			writeErr(w, http.StatusUnauthorized, "admin token required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyAdmin, scope)))
	})
}

// requireSuper limits a route to the super-admin.
func requireSuper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminFrom(r).super() {
			writeErr(w, http.StatusForbidden, "super-admin only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireTenantScope limits /tenants/{t}/... to the caller's tenant. Another tenant answers
// 404, exactly like a tenant that does not exist, so tenant IDs cannot be probed.
func requireTenantScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := adminFrom(r); !a.super() && a.tenant != chi.URLParam(r, "t") {
			writeErr(w, http.StatusNotFound, "unknown tenant")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a.super() {
		writeJSON(w, http.StatusOK, api.AdminIdentity{Role: "super"})
		return
	}
	writeJSON(w, http.StatusOK, api.AdminIdentity{Role: "tenant", TenantID: a.tenant, TokenID: a.tokenID})
}

func toAPIAdminToken(t store.AdminToken) api.AdminToken {
	out := api.AdminToken{ID: t.ID, TenantID: t.TenantID, Name: t.Name, CreatedAt: t.CreatedAt.UTC(), ExpiresAt: t.ExpiresAt.UTC(), Revoked: t.Revoked}
	if !t.LastUsed.IsZero() {
		out.LastUsed = t.LastUsed.UTC()
	}
	return out
}

func (s *Server) handleCreateAdminToken(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	var req api.AdminTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > maxAdminTokenName {
		writeErr(w, http.StatusBadRequest, "name is required (at most 100 bytes)")
		return
	}
	validFor := time.Duration(req.ValidFor) * time.Second
	if validFor <= 0 {
		validFor = defaultAdminTokenValid
	}
	validFor = min(validFor, maxAdminTokenValid)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	tok := adminTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	hash := sha256.Sum256([]byte(tok))
	now := s.now().UTC().Truncate(time.Second)
	row := store.AdminToken{ID: uuid.NewString(), TenantID: t, Name: req.Name, Hash: hash[:], CreatedAt: now, ExpiresAt: now.Add(validFor)}
	if err := s.cfg.Store.CreateAdminToken(r.Context(), row); err != nil {
		s.internalErr(w, r, "create admin token", err)
		return
	}
	s.log.InfoContext(r.Context(), "admin token created", "tenant", t, "id", row.ID, "name", row.Name, "expires", row.ExpiresAt, "by", adminFrom(r).actor())
	writeJSON(w, http.StatusCreated, api.AdminTokenCreated{AdminToken: toAPIAdminToken(row), Token: tok})
}

func (s *Server) handleListAdminTokens(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	ts, err := s.cfg.Store.ListAdminTokens(r.Context(), t)
	if err != nil {
		s.internalErr(w, r, "list admin tokens", err)
		return
	}
	out := make([]api.AdminToken, 0, len(ts))
	for _, x := range ts {
		out = append(out, toAPIAdminToken(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeAdminToken(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	err := s.cfg.Store.RevokeAdminToken(r.Context(), t, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "unknown admin token")
		return
	}
	if err != nil {
		s.internalErr(w, r, "revoke admin token", err)
		return
	}
	s.log.InfoContext(r.Context(), "admin token revoked", "tenant", t, "id", id, "by", adminFrom(r).actor())
	w.WriteHeader(http.StatusNoContent)
}

// actor names the admin for audit logs (never the token itself).
func (a adminScope) actor() string {
	if a.super() {
		return "super"
	}
	return "token:" + a.tokenID
}

// auditAdmin records every admin write (anything but GET and HEAD) with its actor, route
// tenant and outcome, after the handler ran. Reads are not recorded. A failed audit write is
// logged but does not fail the request, which has already been answered.
func (s *Server) auditAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		code := sw.code
		if code == 0 {
			code = http.StatusOK
		}
		tenant := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			tenant = rc.URLParam("t")
		}
		e := store.AuditEntry{At: s.now(), Actor: adminFrom(r).actor(), TenantID: tenant, Method: r.Method, Path: r.URL.Path, Status: code}
		if err := s.cfg.Store.AddAudit(context.WithoutCancel(r.Context()), e); err != nil {
			s.log.ErrorContext(r.Context(), "admin audit write failed", "err", err, "method", e.Method, "path", e.Path, "actor", e.Actor)
		}
	})
}

// handleListAudit serves /v1/admin/tenants/{t}/audit (that tenant) and /v1/admin/audit
// (super-admin: everything, or ?tenant=).
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	f := store.AuditFilter{AllTenants: true}
	if t := chi.URLParam(r, "t"); t != "" {
		if _, ok := s.tenantParam(w, r); !ok {
			return
		}
		f = store.AuditFilter{TenantID: t}
	} else if t := r.URL.Query().Get("tenant"); t != "" {
		f = store.AuditFilter{TenantID: t}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}
	es, err := s.cfg.Store.ListAudit(r.Context(), f)
	if err != nil {
		s.internalErr(w, r, "list audit", err)
		return
	}
	out := make([]api.AuditEntry, 0, len(es))
	for _, e := range es {
		out = append(out, api.AuditEntry{ID: e.ID, At: e.At.UTC(), Actor: e.Actor, TenantID: e.TenantID, Method: e.Method, Path: e.Path, Status: e.Status})
	}
	writeJSON(w, http.StatusOK, out)
}
