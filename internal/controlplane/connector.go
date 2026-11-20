package controlplane

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

// Connectors (ADR-0013).
const (
	// connectorKeyPrefix distinguishes connector provisioning keys ("osc_" + base64url(32
	// random bytes)) from device keys ("osk_").
	connectorKeyPrefix   = "osc_"
	connectorKeyValidity = 24 * time.Hour
	defaultGroup         = "default"
	maxNameLen           = 128
)

// Notifier keys. Device IDs are pki.ValidID values and never contain '/'.
const (
	notifyEdges = "edges/" // the Edge registry changed (all connector configs)
)

func notifyTenant(t string) string     { return "tenant/" + t }
func notifyConnector(c string) string  { return "connector/" + c }
func connectorPollKey(c string) string { return "connector/" + c }

// newKey returns prefix + base64url(32 random bytes) and its SHA-256.
func newKey(prefix string) (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}
	key := prefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return key, sha256.Sum256([]byte(key)), nil
}

// caBundle is root followed by the tenant CA, as returned at enrollment and renewal.
func (s *Server) caBundle(ca *pki.CA) string {
	return string(append(s.cfg.Authority.Root.CertPEM(), ca.CertPEM()...))
}

func (s *Server) handleConnectorEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.ConnectorEnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !strings.HasPrefix(req.ProvisioningKey, connectorKeyPrefix) || req.CSRPEM == "" {
		writeErr(w, http.StatusBadRequest, "provisioningKey and csrPem are required")
		return
	}
	if _, err := pki.ParseCSR([]byte(req.CSRPEM)); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	hash := sha256.Sum256([]byte(req.ProvisioningKey))
	var certPEM []byte
	var ca *pki.CA
	errBadKey := errors.New("bad connector key")
	c, err := s.cfg.Store.EnrollConnector(r.Context(), hash[:], s.now(), func(c store.Connector) (string, error) {
		var err error
		if ca, err = s.cfg.Authority.TenantCA(c.TenantID); err != nil {
			return "", err
		}
		chain, leaf, err := ca.SignConnectorCSR([]byte(req.CSRPEM), c.TenantID, c.ID, pki.DeviceValidity)
		if err != nil {
			return "", errors.Join(errBadKey, err)
		}
		certPEM = chain
		return leaf.SerialNumber.String(), nil
	})
	switch {
	case errors.Is(err, store.ErrKeyInvalid):
		s.log.WarnContext(r.Context(), "connector enrollment rejected: provisioning key invalid")
		writeErr(w, http.StatusForbidden, "provisioning key invalid, expired or used up")
		return
	case errors.Is(err, errBadKey):
		writeErr(w, http.StatusBadRequest, "CSR rejected: connector key must be ECDSA P-256")
		return
	case err != nil:
		s.internalErr(w, r, "connector enroll", err)
		return
	}
	s.log.InfoContext(r.Context(), "connector enrolled", "tenant", c.TenantID, "connector", c.ID, "group", c.Group)
	writeJSON(w, http.StatusOK, api.ConnectorEnrollResponse{
		TenantID:       c.TenantID,
		ConnectorID:    c.ID,
		Group:          c.Group,
		CertificatePEM: string(certPEM),
		CAPEM:          s.caBundle(ca),
		ControlURL:     s.cfg.ControlURL,
	})
}

// handleConnectorRenew mirrors handleRenew for connector certificates.
func (s *Server) handleConnectorRenew(w http.ResponseWriter, r *http.Request) {
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
	c := p.connector
	ca, err := s.cfg.Authority.TenantCA(c.TenantID)
	if err != nil {
		s.internalErr(w, r, "tenant CA", err)
		return
	}
	chain, cert, err := ca.SignConnectorCSR([]byte(req.CSRPEM), c.TenantID, c.ID, pki.DeviceValidity)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "CSR rejected: connector key must be ECDSA P-256")
		return
	}
	err = s.cfg.Store.RenewConnectorCert(r.Context(), c.ID, leaf.SerialNumber.String(), cert.SerialNumber.String())
	switch {
	case errors.Is(err, store.ErrRevoked), errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusForbidden, "connector revoked")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "certificate was renewed concurrently; use the newest certificate")
		return
	case err != nil:
		s.internalErr(w, r, "connector renew", err)
		return
	}
	s.log.InfoContext(r.Context(), "connector certificate renewed", "tenant", c.TenantID, "connector", c.ID, "notAfter", cert.NotAfter)
	writeJSON(w, http.StatusOK, api.RenewResponse{CertificatePEM: string(chain), CAPEM: s.caBundle(ca)})
}

// brokerEdges returns the configured Edges that have a BrokerAddr and are registered and not
// revoked: the Edges a connector must keep a broker connection to.
func (s *Server) brokerEdges(ctx context.Context) ([]api.EdgeInfo, error) {
	reg, err := s.cfg.Store.ListEdges(ctx)
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(reg))
	for _, e := range reg {
		live[e.ID] = !e.Revoked
	}
	out := []api.EdgeInfo{}
	for _, e := range s.cfg.Edges {
		if e.BrokerAddr != "" && live[e.ID] {
			out = append(out, e)
		}
	}
	return out, nil
}

// connectorApps returns the tenant's private apps served by group, without entitlements.
func connectorApps(tp api.TenantPolicy, group string) []policy.PrivateApp {
	out := []policy.PrivateApp{}
	for _, a := range tp.PrivateApps {
		if a.ConnectorGroup == group {
			out = append(out, a.PrivateApp)
		}
	}
	return out
}

// connectorConfig builds the current ConnectorConfig of c. Its Version increases whenever the
// tenant policy is written, the broker Edges change or the group's apps change.
func (s *Server) connectorConfig(ctx context.Context, c store.Connector) (api.ConnectorConfig, error) {
	tp, err := s.tenantPolicy(ctx, c.TenantID)
	if err != nil {
		return api.ConnectorConfig{}, err
	}
	pv, err := s.cfg.Store.TenantPolicyVersion(ctx, c.TenantID)
	if err != nil {
		return api.ConnectorConfig{}, err
	}
	edges, err := s.brokerEdges(ctx)
	if err != nil {
		return api.ConnectorConfig{}, err
	}
	cfg := api.ConnectorConfig{Edges: edges, Apps: connectorApps(tp, c.Group)}
	raw, err := json.Marshal(struct {
		PolicyVersion uint64
		Config        api.ConnectorConfig
	}{pv, cfg})
	if err != nil {
		return api.ConnectorConfig{}, err
	}
	hash := sha256.Sum256(raw)
	if cfg.Version, err = s.cfg.Store.ConnectorConfigVersion(ctx, c.ID, hash[:]); err != nil {
		return api.ConnectorConfig{}, err
	}
	return cfg, nil
}

// handleConnectorConfig serves ConnectorConfig with the ETag / If-None-Match / ?wait= rules
// of /v1/snapshot.
func (s *Server) handleConnectorConfig(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	c := p.connector
	have, hasHave := parseETag(r.Header.Get("If-None-Match"))
	var wait time.Duration
	if ws := r.URL.Query().Get("wait"); ws != "" {
		n, err := strconv.Atoi(ws)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "wait must be a non-negative number of seconds")
			return
		}
		wait = min(time.Duration(n)*time.Second, MaxLongPoll)
	}
	setDeadline(w, wait+longPollSlack)
	var deadline <-chan time.Time
	if wait > 0 {
		key := connectorPollKey(c.ID)
		if !s.polls.acquire(key) {
			writeErr(w, http.StatusTooManyRequests, "too many concurrent config long-polls for this connector")
			return
		}
		defer s.polls.release(key)
		t := time.NewTimer(wait)
		defer t.Stop()
		deadline = t.C
	}
	for {
		// Subscribe before reading so a change between the read and the wait is not lost.
		chTenant := s.notify.wait(notifyTenant(c.TenantID))
		chEdges := s.notify.wait(notifyEdges)
		chSelf := s.notify.wait(notifyConnector(c.ID))
		cur, err := s.cfg.Store.GetConnector(r.Context(), c.ID)
		if err != nil {
			s.internalErr(w, r, "load connector", err)
			return
		}
		if cur.Revoked {
			writeErr(w, http.StatusForbidden, "connector revoked")
			return
		}
		cfg, err := s.connectorConfig(r.Context(), cur)
		if err != nil {
			s.internalErr(w, r, "connector config", err)
			return
		}
		w.Header().Set("ETag", etag(cfg.Version))
		if !hasHave || cfg.Version != have {
			writeJSON(w, http.StatusOK, cfg)
			return
		}
		if deadline == nil {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		select {
		case <-chTenant:
		case <-chEdges:
		case <-chSelf:
		case <-deadline:
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
	}
}

// --- admin: connectors, tenants, users ---

func toAdminConnector(c store.Connector) api.AdminConnector {
	return api.AdminConnector{ID: c.ID, TenantID: c.TenantID, Name: c.Name, Group: c.Group, Revoked: c.Revoked, CreatedAt: c.CreatedAt, LastSeen: c.LastSeen}
}

func (s *Server) handleCreateConnector(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	var req api.AdminConnectorRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Group == "" {
		req.Group = defaultGroup
	}
	if req.Name == "" || len(req.Name) > maxNameLen {
		writeErr(w, http.StatusBadRequest, "name must be 1-128 characters")
		return
	}
	if !pki.ValidID(req.Group) {
		writeErr(w, http.StatusBadRequest, "group must match [a-zA-Z0-9][a-zA-Z0-9._-]*")
		return
	}
	key, hash, err := newKey(connectorKeyPrefix)
	if err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	c, err := s.cfg.Store.CreateConnector(r.Context(), store.Connector{ID: uuid.NewString(), TenantID: t, Name: req.Name, Group: req.Group},
		hash[:], s.now().Add(connectorKeyValidity))
	if err != nil {
		s.internalErr(w, r, "create connector", err)
		return
	}
	s.log.InfoContext(r.Context(), "connector created", "tenant", t, "connector", c.ID, "group", c.Group)
	writeJSON(w, http.StatusCreated, api.AdminConnectorCreated{Connector: toAdminConnector(c), ProvisioningKey: key})
}

func (s *Server) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	cs, err := s.cfg.Store.ListConnectors(r.Context(), store.ConnectorFilter{TenantID: t, IncludeRevoked: true})
	if err != nil {
		s.internalErr(w, r, "list connectors", err)
		return
	}
	out := make([]api.AdminConnector, 0, len(cs))
	for _, c := range cs {
		out = append(out, toAdminConnector(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeConnector revokes a connector: its certificate is refused on every route and
// it leaves EdgePeers.Connectors, so Edges drop it at their next peer sync.
func (s *Server) handleRevokeConnector(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "c")
	err := s.cfg.Store.RevokeConnector(r.Context(), t, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "unknown connector")
		return
	}
	if err != nil {
		s.internalErr(w, r, "revoke connector", err)
		return
	}
	s.notify.notify(notifyConnector(id))
	s.log.InfoContext(r.Context(), "connector revoked", "tenant", t, "connector", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := s.cfg.Store.ListTenants(r.Context())
	if err != nil {
		s.internalErr(w, r, "list tenants", err)
		return
	}
	out := make([]api.AdminTenant, 0, len(ts))
	for _, t := range ts {
		out = append(out, api.AdminTenant{ID: t.ID, Name: t.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	us, err := s.cfg.Store.ListUsers(r.Context(), t)
	if err != nil {
		s.internalErr(w, r, "list users", err)
		return
	}
	out := make([]api.AdminUser, 0, len(us))
	for _, u := range us {
		out = append(out, api.AdminUser{ID: u.ID, Email: u.Email, Name: u.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- admin portal (static Flutter web build) ---

// portalCSP allows only same-origin resources. 'wasm-unsafe-eval' is required by Flutter's
// CanvasKit/skwasm renderers; 'unsafe-inline' styles by the Flutter engine's injected styles.
const portalCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"

// portalHandler serves dir at /admin/. Unknown paths without a file extension get index.html
// (client-side routes); unknown paths with an extension get 404. Directories are never listed.
// No client certificate is needed: the portal calls /v1/admin with the Bearer token.
func portalHandler(dir string) http.Handler {
	fsys := os.DirFS(dir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", portalCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/admin")), "/")
		if name == "" {
			name = "index.html"
		}
		if st, err := fs.Stat(fsys, name); err != nil || !st.Mode().IsRegular() {
			if path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		if name == "index.html" {
			h.Set("Cache-Control", "no-cache")
		}
		http.ServeFileFS(w, r, fsys, name) //nolint:gosec // G703: name is cleaned with path.Clean("/"+...), os.DirFS rejects non-ValidPath names; dir is an operator flag
	})
}
