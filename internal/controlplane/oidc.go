package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/oidc"
	"github.com/yuky2020/opensase/pkg/store"
)

type oidcProviderEntry struct {
	key       string
	provider  *oidc.Provider
	fetchedAt time.Time
}

type pendingOIDCLogin struct {
	tenantID  string
	verifier  string
	nonce     string
	expiresAt time.Time
}

func (s *Server) oidcCallbackURL(r *http.Request) string {
	base := strings.TrimRight(s.cfg.ControlURL, "/")
	if base == "" && r != nil {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/v1/auth/oidc/callback"
}

func (s *Server) getOIDCProvider(ctx context.Context, tenantID string, cfg store.TenantOIDC, redirectURL string) (*oidc.Provider, error) {
	cacheKey := cfg.Issuer + "|" + cfg.ClientID
	s.oidcMu.Lock()
	entry := s.oidcProviders[tenantID]
	if entry != nil && entry.key == cacheKey && s.now().Sub(entry.fetchedAt) < 10*time.Minute {
		prov := entry.provider
		s.oidcMu.Unlock()
		return prov, nil
	}
	s.oidcMu.Unlock()

	oidcCfg := oidc.Config{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"email", "profile", "groups"},
	}

	prov, err := oidc.Discover(ctx, s.oidcClient, oidcCfg)
	if err != nil {
		return nil, err
	}

	s.oidcMu.Lock()
	s.oidcProviders[tenantID] = &oidcProviderEntry{
		key:       cacheKey,
		provider:  prov,
		fetchedAt: s.now(),
	}
	s.oidcMu.Unlock()
	return prov, nil
}

func writeOIDCErrorPage(w http.ResponseWriter, code int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>\n",
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(message))
}

func (s *Server) handleGetTenantOIDC(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	stored, err := s.cfg.Store.GetTenantOIDC(r.Context(), t)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "OIDC is not configured for this tenant")
		return
	}
	if err != nil {
		s.internalErr(w, r, "get tenant oidc", err)
		return
	}
	resp := api.TenantOIDC{
		Issuer:      stored.Issuer,
		ClientID:    stored.ClientID,
		HasSecret:   stored.ClientSecret != "",
		GroupRoles:  stored.GroupRoles,
		RedirectURL: s.oidcCallbackURL(r),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePutTenantOIDC(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	var req api.TenantOIDC
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.Issuer == "" {
		writeErr(w, http.StatusBadRequest, "issuer is required")
		return
	}
	u, err := url.Parse(req.Issuer)
	local := u != nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if err != nil || (u.Scheme != "https" && (u.Scheme != "http" || !local)) {
		writeErr(w, http.StatusBadRequest, "issuer must be https (or http on localhost/127.0.0.1/::1)")
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientID == "" {
		writeErr(w, http.StatusBadRequest, "clientId is required")
		return
	}
	if len(req.GroupRoles) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one group role is required")
		return
	}
	for g, role := range req.GroupRoles {
		if strings.TrimSpace(g) == "" {
			writeErr(w, http.StatusBadRequest, "group name cannot be empty")
			return
		}
		if !validTenantRole(role) {
			writeErr(w, http.StatusBadRequest, "group role must be admin, policy-editor or viewer")
			return
		}
	}

	clientSecret := req.ClientSecret
	if clientSecret == "" {
		if existing, err := s.cfg.Store.GetTenantOIDC(r.Context(), t); err == nil {
			clientSecret = existing.ClientSecret
		}
	}

	row := store.TenantOIDC{
		TenantID:     t,
		Issuer:       req.Issuer,
		ClientID:     req.ClientID,
		ClientSecret: clientSecret,
		GroupRoles:   req.GroupRoles,
		UpdatedAt:    s.now().UTC(),
	}
	if err := s.cfg.Store.PutTenantOIDC(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tenant not found")
			return
		}
		s.internalErr(w, r, "store tenant oidc", err)
		return
	}

	s.oidcMu.Lock()
	delete(s.oidcProviders, t)
	s.oidcMu.Unlock()

	resp := api.TenantOIDC{
		Issuer:      row.Issuer,
		ClientID:    row.ClientID,
		HasSecret:   row.ClientSecret != "",
		GroupRoles:  row.GroupRoles,
		RedirectURL: s.oidcCallbackURL(r),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteTenantOIDC(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	err := s.cfg.Store.DeleteTenantOIDC(r.Context(), t)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "OIDC is not configured for this tenant")
	case err != nil:
		s.internalErr(w, r, "delete tenant oidc", err)
	default:
		s.oidcMu.Lock()
		delete(s.oidcProviders, t)
		s.oidcMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	if tenant == "" {
		writeErr(w, http.StatusBadRequest, "tenant required")
		return
	}
	cfg, err := s.cfg.Store.GetTenantOIDC(r.Context(), tenant)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "OIDC is not configured for this tenant")
		return
	}
	if err != nil {
		s.internalErr(w, r, "get tenant oidc", err)
		return
	}

	redirectURL := s.oidcCallbackURL(r)
	prov, err := s.getOIDCProvider(r.Context(), tenant, cfg, redirectURL)
	if err != nil {
		s.log.ErrorContext(r.Context(), "oidc discovery failed", "tenant", tenant, "err", err)
		writeErr(w, http.StatusBadGateway, "failed to connect to identity provider")
		return
	}

	authReq, err := prov.AuthCodeURL()
	if err != nil {
		s.internalErr(w, r, "oidc auth code url", err)
		return
	}

	s.oidcMu.Lock()
	now := s.now()
	for st, p := range s.oidcPending {
		if !now.Before(p.expiresAt) {
			delete(s.oidcPending, st)
		}
	}
	if len(s.oidcPending) >= 10000 {
		s.oidcMu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "sign-in capacity exceeded")
		return
	}
	s.oidcPending[authReq.State] = pendingOIDCLogin{
		tenantID:  tenant,
		verifier:  authReq.Verifier,
		nonce:     authReq.Nonce,
		expiresAt: now.Add(10 * time.Minute),
	}
	s.oidcMu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authReq.URL, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	s.oidcMu.Lock()
	now := s.now()
	pending, ok := s.oidcPending[state]
	if ok {
		delete(s.oidcPending, state)
	}
	s.oidcMu.Unlock()

	if !ok || state == "" || !now.Before(pending.expiresAt) {
		writeOIDCErrorPage(w, http.StatusBadRequest, "Invalid Request", "The sign-in request is invalid or has expired. Please return to the portal and try again.")
		return
	}

	if code == "" {
		writeOIDCErrorPage(w, http.StatusBadRequest, "Invalid Request", "Missing authorization code.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	cfg, err := s.cfg.Store.GetTenantOIDC(ctx, pending.tenantID)
	if err != nil {
		s.log.ErrorContext(ctx, "oidc get config failed", "tenant", pending.tenantID, "err", err)
		writeOIDCErrorPage(w, http.StatusInternalServerError, "Sign-in Error", "Failed to load tenant configuration.")
		return
	}

	redirectURL := s.oidcCallbackURL(r)
	prov, err := s.getOIDCProvider(ctx, pending.tenantID, cfg, redirectURL)
	if err != nil {
		s.log.ErrorContext(ctx, "oidc get provider failed", "tenant", pending.tenantID, "err", err)
		writeOIDCErrorPage(w, http.StatusBadGateway, "Sign-in Error", "Failed to connect to identity provider.")
		return
	}

	claims, err := prov.Exchange(ctx, code, pending.verifier, pending.nonce)
	if err != nil {
		s.log.ErrorContext(ctx, "oidc exchange failed", "tenant", pending.tenantID, "err", err)
		writeOIDCErrorPage(w, http.StatusBadRequest, "Sign-in Failed", "Identity verification failed.")
		return
	}

	roleRank := func(role string) int {
		switch role {
		case api.TenantRoleAdmin:
			return 3
		case api.TenantRolePolicyEditor:
			return 2
		case api.TenantRoleViewer:
			return 1
		default:
			return 0
		}
	}

	var matchedRole string
	bestRank := 0
	for _, g := range claims.Groups {
		if r, ok := cfg.GroupRoles[g]; ok {
			if rank := roleRank(r); rank > bestRank {
				bestRank = rank
				matchedRole = r
			}
		}
	}

	userActor := claims.Email
	if userActor == "" {
		userActor = claims.Subject
	}

	if bestRank == 0 {
		auditEntry := store.AuditEntry{
			At:       s.now(),
			Actor:    userActor,
			TenantID: pending.tenantID,
			Method:   "oidc.login.denied",
			Path:     "sub=" + claims.Subject + " email=" + claims.Email,
			Status:   http.StatusForbidden,
		}
		if err := s.cfg.Store.AddAudit(context.WithoutCancel(r.Context()), auditEntry); err != nil {
			s.log.ErrorContext(r.Context(), "audit write failed", "err", err)
		}
		writeOIDCErrorPage(w, http.StatusForbidden, "Access Denied", "Your identity provider groups do not grant access to this portal.")
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	tok := adminTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	hash := sha256.Sum256([]byte(tok))
	tokenNow := s.now().UTC().Truncate(time.Second)

	label := "oidc:" + claims.Email
	if claims.Email == "" {
		label = "oidc:" + claims.Subject
	}

	row := store.AdminToken{
		ID:        uuid.NewString(),
		TenantID:  pending.tenantID,
		Name:      label,
		Hash:      hash[:],
		CreatedAt: tokenNow,
		ExpiresAt: tokenNow.Add(1 * time.Hour),
		Role:      matchedRole,
	}
	if err := s.cfg.Store.CreateAdminToken(r.Context(), row); err != nil {
		s.internalErr(w, r, "create admin token", err)
		return
	}

	auditEntry := store.AuditEntry{
		At:       s.now(),
		Actor:    userActor,
		TenantID: pending.tenantID,
		Method:   "oidc.login",
		Path:     "sub=" + claims.Subject + " role=" + matchedRole,
		Status:   http.StatusOK,
	}
	if err := s.cfg.Store.AddAudit(context.WithoutCancel(r.Context()), auditEntry); err != nil {
		s.log.ErrorContext(r.Context(), "audit write failed", "err", err)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	dest := "/admin/#/oidc-signin?token=" + url.QueryEscape(tok)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
