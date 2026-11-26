package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yuky2020/opensase/pkg/oidc"
	"github.com/yuky2020/opensase/pkg/store"
)

// Device enrolment through the identity provider (issue #68). The client opens
// /v1/enroll/oidc/{tenant}/start in a browser with its loopback (desktop) or app (Android)
// return URL. After the sign-in the Control Plane creates a single-use provisioning key for
// the signed-in user, valid enrollGrantTTL, and redirects to the return URL with it; the
// client then enrols with POST /v1/enroll as with any provisioning key.

const (
	enrollGrantTTL = 5 * time.Minute
	appReturnURL   = "opensase://enroll" // Android app link
)

// validReturnTo accepts http://127.0.0.1:PORT/..., http://[::1]:PORT/..., http://localhost:PORT/...
// (RFC 8252 loopback redirect) and the app URL. Anything else could send the key elsewhere.
func validReturnTo(s string) bool {
	if s == appReturnURL || strings.HasPrefix(s, appReturnURL+"?") {
		return true
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleEnrollOIDCStart(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	returnTo := r.URL.Query().Get("return_to")
	cstate := r.URL.Query().Get("state")
	if !validReturnTo(returnTo) || len(cstate) > 128 {
		writeOIDCErrorPage(w, http.StatusBadRequest, "Invalid Request", "The enrolment request has an invalid return address.")
		return
	}
	cfg, err := s.cfg.Store.GetTenantOIDC(r.Context(), tenant)
	if errors.Is(err, store.ErrNotFound) {
		writeOIDCErrorPage(w, http.StatusNotFound, "Not Available", "Sign-in enrolment is not configured for this organisation. Ask your administrator for a provisioning key.")
		return
	}
	if err != nil {
		s.internalErr(w, r, "get tenant oidc", err)
		return
	}
	prov, err := s.getOIDCProvider(r.Context(), tenant, cfg, s.oidcCallbackURL(r))
	if err != nil {
		s.log.ErrorContext(r.Context(), "oidc discovery failed", "tenant", tenant, "err", err)
		writeOIDCErrorPage(w, http.StatusBadGateway, "Sign-in Error", "Failed to connect to the identity provider.")
		return
	}
	authReq, err := prov.AuthCodeURL()
	if err != nil {
		s.internalErr(w, r, "oidc auth code url", err)
		return
	}
	err = s.cfg.Store.PutOIDCPending(r.Context(), store.OIDCPending{
		State: authReq.State, TenantID: tenant, Verifier: authReq.Verifier, Nonce: authReq.Nonce,
		ExpiresAt: s.now().Add(10 * time.Minute), Purpose: "enroll", ReturnTo: returnTo, ClientState: cstate,
	}, s.now(), 10000)
	if errors.Is(err, store.ErrCapacity) {
		writeErr(w, http.StatusServiceUnavailable, "sign-in capacity exceeded")
		return
	}
	if err != nil {
		s.internalErr(w, r, "store oidc sign-in", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authReq.URL, http.StatusFound)
}

// finishEnrollOIDC handles the identity provider callback of a device enrolment.
func (s *Server) finishEnrollOIDC(w http.ResponseWriter, r *http.Request, pending store.OIDCPending, claims *oidc.Claims) {
	ctx := r.Context()
	email := strings.TrimSpace(claims.Email)
	if email == "" {
		writeOIDCErrorPage(w, http.StatusForbidden, "Sign-in Error", "Your identity provider did not send an email address, which enrolment needs.")
		return
	}
	u, err := s.cfg.Store.UserByEmail(ctx, pending.TenantID, email)
	if errors.Is(err, store.ErrNotFound) {
		u = store.User{ID: uuid.NewString(), TenantID: pending.TenantID, Email: email, Name: claims.Name}
		if u.Name == "" {
			u.Name = email
		}
		err = s.cfg.Store.CreateUser(ctx, u)
	}
	if err != nil {
		s.internalErr(w, r, "enrolment user", err)
		return
	}
	if active, err := s.cfg.Store.UserActive(ctx, pending.TenantID, u.ID); err != nil || !active {
		writeOIDCErrorPage(w, http.StatusForbidden, "Access Denied", "Your account is deactivated in this organisation.")
		return
	}
	groups := slices.Clone(claims.Groups)
	slices.Sort(groups)
	if err := s.cfg.Store.SetUserGroups(ctx, pending.TenantID, u.ID, slices.Compact(groups)); err != nil {
		s.internalErr(w, r, "user groups", err)
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	key := provisioningKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	hash := sha256.Sum256([]byte(key))
	if err := s.cfg.Store.CreateProvisioningKey(ctx, store.ProvisioningKey{Hash: hash[:], TenantID: pending.TenantID, UserID: u.ID, MaxUses: 1,
		ExpiresAt: s.now().Add(enrollGrantTTL).UTC().Truncate(time.Second)}); err != nil {
		s.internalErr(w, r, "enrolment key", err)
		return
	}
	if err := s.cfg.Store.AddAudit(context.WithoutCancel(ctx), store.AuditEntry{
		At: s.now(), Actor: email, TenantID: pending.TenantID, Method: "oidc.enroll", Path: "sub=" + claims.Subject, Status: http.StatusOK,
	}); err != nil {
		s.log.ErrorContext(ctx, "audit write failed", "err", err)
	}
	q := url.Values{"code": {key}}
	if pending.ClientState != "" {
		q.Set("state", pending.ClientState)
	}
	sep := "?"
	if strings.Contains(pending.ReturnTo, "?") {
		sep = "&"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, pending.ReturnTo+sep+q.Encode(), http.StatusSeeOther)
}
