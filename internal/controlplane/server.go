// Package controlplane implements the OpenSASE Control Plane HTTP API (see pkg/api): tenant
// administration, device enrollment, Policy Snapshot compilation and distribution, the cloud
// decision API, flow collection and the peer feed for Edges.
package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/netutil"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
	"github.com/yuky2020/opensase/pkg/store"
)

// Defaults.
const (
	DefaultSnapshotTTL = 24 * time.Hour
	DecideTTL          = 300 // seconds
	MaxLongPoll        = 60 * time.Second
	maxBody            = 1 << 20
	maxFlowRecords     = 2000

	DefaultMaxConns      = 4096
	DefaultFlowRetention = 7 * 24 * time.Hour
	// DefaultAuditRetention is how long admin audit entries are kept.
	DefaultAuditRetention = 365 * 24 * time.Hour
	DefaultFlowRate       = 1000 // flow records per device per minute
	DefaultEnrollRate     = 30   // enrollment attempts per source IP per minute (ST-05)
	maxLongPollsPerDev    = 2

	// Per-route deadlines (security review #8). The snapshot long-poll gets wait+10s.
	routeTimeout      = 30 * time.Second
	shortRouteTimeout = 15 * time.Second // enroll, renew, admin
	longPollSlack     = 10 * time.Second

	// edgeSessionTTL is how long an edge's report of a live device session stays valid. The
	// edge reports every peer refresh (10s) and right after each session setup.
	edgeSessionTTL = 2 * time.Minute
)

// Config configures a Server.
type Config struct {
	Store          *store.Store
	Authority      *pki.Authority
	SigningKey     ed25519.PrivateKey
	SigningKeyID   string
	AdminToken     string // required; compared in constant time
	Edges          []api.EdgeInfo
	ControlURL     string
	SnapshotTTL    time.Duration // default 24h
	MaxConns       int           // concurrent connections, default 4096
	FlowRetention  time.Duration // flow records older than this are deleted, default 7 days
	AuditRetention time.Duration // admin audit entries older than this are deleted, default 365 days
	FlowRate       int           // flow records accepted per device per minute, default 1000
	EnrollRate     int           // enroll attempts (devices + connectors) per source IP per minute, default 30
	PortalDir      string        // if set, the admin portal (static Flutter web build) is served at /admin/
	// Web categories (ADR-0022). CategoriesFile is the cached category archive (UT1
	// blacklists.tar.gz), loaded at start; CategoriesURL, if set, refreshes it every
	// CategoriesRefresh (default 24h). Without a file, categories are not enforced.
	CategoriesFile    string
	CategoriesURL     string
	CategoriesRefresh time.Duration
	// Scheduled backups (issue #67, SQLite only): every BackupEvery (default 24h) the leader
	// writes the database and an archive of PKIDir to BackupDir, keeping BackupKeep (default
	// 7) of each. Empty BackupDir: no scheduled backups.
	BackupDir          string
	BackupEvery        time.Duration
	BackupKeep         int
	PKIDir             string
	ServerCertNotAfter time.Time        // expiry of the serving certificate, for metrics (issue #73)
	OIDCClient         *http.Client     // optional; default timeout 10s (issue #17)
	ListClient         *http.Client     // downloads blocklists (issue #63); default: public addresses only
	Logger             *slog.Logger     // default slog.Default()
	Now                func() time.Time // default time.Now
}

// Server is the Control Plane. Create it with New.
type Server struct {
	cfg  Config
	log  *slog.Logger
	now  func() time.Time
	pool atomic.Pointer[x509.CertPool]

	notify   *notifier
	compiled *compiledCache

	decideMu sync.Mutex
	decide   map[string]*decideEntry // tenant ID -> compiled cloud-only decision data

	polls       *pollLimiter
	flowLimit   *rateLimiter
	enrollLimit *rateLimiter // failed enroll attempts per source IP (ST-05)

	cats       atomic.Pointer[catState] // web category list (ADR-0022)
	edgeCats   atomic.Pointer[catState] // cats plus downloaded blocklists, served to Edges (issue #63)
	lists      *listState
	listClient *http.Client

	obs     *observer    // metrics (issue #73)
	auditOK atomic.Int32 // last audit chain check: 1 ok, 0 broken, -1 not run yet

	oidcMu        sync.Mutex
	oidcProviders map[string]*oidcProviderEntry // key: tenant ID
	oidcClient    *http.Client
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Authority == nil {
		return nil, errors.New("controlplane: store and authority are required")
	}
	if len(cfg.SigningKey) != ed25519.PrivateKeySize || cfg.SigningKeyID == "" {
		return nil, errors.New("controlplane: snapshot signing key is required")
	}
	if len(cfg.AdminToken) < 16 {
		return nil, errors.New("controlplane: admin token must be at least 16 characters")
	}
	if cfg.SnapshotTTL <= 0 {
		cfg.SnapshotTTL = DefaultSnapshotTTL
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.AuditRetention <= 0 {
		cfg.AuditRetention = DefaultAuditRetention
	}
	if cfg.FlowRetention <= 0 {
		cfg.FlowRetention = DefaultFlowRetention
	}
	if cfg.EnrollRate <= 0 {
		cfg.EnrollRate = DefaultEnrollRate
	}
	if cfg.FlowRate <= 0 {
		cfg.FlowRate = DefaultFlowRate
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		cfg:           cfg,
		log:           cfg.Logger,
		now:           cfg.Now,
		notify:        newNotifier(),
		compiled:      newCompiledCache(),
		decide:        map[string]*decideEntry{},
		polls:         newPollLimiter(maxLongPollsPerDev),
		oidcProviders: make(map[string]*oidcProviderEntry),
	}
	if cfg.OIDCClient != nil {
		s.oidcClient = cfg.OIDCClient
	} else {
		s.oidcClient = &http.Client{Timeout: 10 * time.Second}
	}
	s.flowLimit = newRateLimiter(cfg.FlowRate, time.Minute, cfg.Now)
	s.enrollLimit = newRateLimiter(cfg.EnrollRate, time.Minute, cfg.Now)
	s.pool.Store(cfg.Authority.ClientCAPool())
	s.auditOK.Store(-1)
	s.lists = newListState()
	s.listClient = cfg.ListClient
	if s.listClient == nil {
		s.listClient = publicListClient()
	}
	s.initMetrics()
	return s, nil
}

// TLSConfig returns the PQ-hardened server TLS config. Client certificates are optional at
// the TLS layer (VerifyClientCertIfGiven) and enforced per route, so browsers without a
// certificate can load /admin/ and call /v1/admin with the Bearer token.
func (s *Server) TLSConfig(cert tls.Certificate) *tls.Config {
	base := pqsession.Harden(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		c.ClientCAs = s.pool.Load()
		return c, nil
	}
	return base
}

// Handler returns the HTTP handler with every route of pkg/api.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.logRequests, s.requirePQ, deadline(routeTimeout))
	short := deadline(shortRouteTimeout)

	r.With(short, s.limitEnroll).Post("/v1/enroll", s.handleEnroll)
	r.Get("/v1/pki/ca", s.handlePKI)
	r.Get("/v1/auth/oidc/{tenant}/login", s.handleOIDCLogin)
	r.Get("/v1/auth/oidc/callback", s.handleOIDCCallback)
	r.With(s.limitEnroll).Get("/v1/enroll/oidc/{tenant}/start", s.handleEnrollOIDCStart)
	r.Route("/scim/v2/{tenant}", s.scimRoutes) // issue #68

	r.Group(func(r chi.Router) {
		r.Use(s.requireDevice)
		r.Get("/v1/snapshot", s.handleSnapshot) // sets its own deadline (wait + 10s)
		r.Get("/v1/self/rules", s.handleGetSelfRules)
		r.Get("/v1/edges", s.handleDeviceEdges)
		r.Put("/v1/self/rules", s.handleSelfRules)
	})
	// The superseded certificate of the last renewal is accepted here only (lost response).
	r.With(short, s.requireRole(roleDevice|roleRenewal)).Post("/v1/renew", s.handleRenew)
	r.Group(func(r chi.Router) {
		r.Use(s.requireDeviceOrEdge)
		r.Post("/v1/decide", s.handleDecide)
		r.Post("/v1/flows", s.handleFlows)
	})
	// Connectors (ADR-0013). Connector certificates are accepted on these routes only.
	r.With(short, s.limitEnroll).Post("/v1/connector/enroll", s.handleConnectorEnroll)
	r.With(s.requireRole(roleConnector)).Get("/v1/connector/config", s.handleConnectorConfig) // own deadline
	r.With(short, s.requireRole(roleConnector|roleRenewal)).Post("/v1/connector/renew", s.handleConnectorRenew)
	r.Group(func(r chi.Router) {
		r.Use(s.requireEdge)
		r.Get("/v1/edge/peers", s.handleEdgePeers)
		// The Edge reports the devices with a live session, so that /v1/decide?device= and
		// /v1/flows from that edge are scoped to them (review #9), and its live connectors.
		r.Post("/v1/edge/sessions", s.handleEdgeSessions)
		r.With(short).Post("/v1/edge/inspection-ca", s.handleInspectionCA)
		r.Get("/v1/edge/categories", s.handleEdgeCategories)
		r.Get("/v1/edge/dlp-datasets", s.handleEdgeDatasets)
	})
	r.Route("/v1/admin", func(r chi.Router) {
		r.Use(short, s.requireAdmin, s.auditAdmin)
		r.Get("/whoami", s.handleWhoami)
		r.Get("/info", s.handleAdminInfo)
		r.Get("/saas/catalog", s.handleSaaSCatalog)
		r.Get("/categories", s.handleCategories)
		r.Get("/blocklists", s.handleBlocklists)
		r.Get("/tenants", s.handleListTenants) // filtered to the caller's tenant
		r.Group(func(r chi.Router) {
			r.Use(requireSuper)
			r.Post("/tenants", s.handleCreateTenant)
			// Edge registry (review #9): infrastructure, super-admin only.
			r.Post("/edges", s.handleCreateEdge)
			r.Get("/edges", s.handleListEdges)
			r.Post("/edges/{e}/revoke", s.handleRevokeEdge)
			r.Get("/audit", s.handleListAudit)
			r.Get("/audit/verify", s.handleVerifyAudit)
			r.Get("/status", s.handleAdminStatus)
		})
		r.Route("/tenants/{t}", func(r chi.Router) {
			r.Use(requireTenantScope, requireTenantRole)
			r.Get("/users", s.handleListUsers)
			r.Post("/users", s.handleCreateUser)
			r.Post("/connectors", s.handleCreateConnector)
			r.Get("/connectors", s.handleListConnectors)
			r.Post("/scim-token", s.handleCreateSCIMToken) // admin role only (roleAllows)
			r.Post("/connectors/{c}/revoke", s.handleRevokeConnector)
			r.Post("/provisioning-keys", s.handleCreateKey)
			r.Put("/policy", s.handlePutPolicy)
			r.Get("/policy", s.handleGetPolicy)
			r.Post("/policy-test", s.handlePolicyTest) // read only: every role (roleAllows)
			r.Get("/flows", s.handleListFlows)
			r.Get("/experience", s.handleExperience)
			r.Get("/devices", s.handleListDevices)
			r.Post("/devices/{d}/revoke", s.handleRevokeDevice)
			r.Get("/devices/{d}/routes", s.handleGetDeviceRoutes)
			r.Put("/devices/{d}/routes", s.handlePutDeviceRoutes)
			r.Post("/admin-tokens", s.handleCreateAdminToken)
			r.Get("/admin-tokens", s.handleListAdminTokens)
			r.Post("/admin-tokens/{id}/revoke", s.handleRevokeAdminToken)
			r.Get("/audit", s.handleListAudit)
			r.Get("/inspection-ca", s.handleGetInspectionRoot)
			r.Put("/dlp-datasets/{name}", s.handlePutDataset)
			r.Get("/dlp-datasets", s.handleListDatasets)
			r.Delete("/dlp-datasets/{name}", s.handleDeleteDataset)
			r.Get("/oidc", s.handleGetTenantOIDC)
			r.Put("/oidc", s.handlePutTenantOIDC)
			r.Delete("/oidc", s.handleDeleteTenantOIDC)
		})
	})
	if s.cfg.PortalDir != "" {
		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		})
		r.Handle("/admin/*", portalHandler(s.cfg.PortalDir))
	}
	return r
}

// deadline sets the read and write deadlines of a request (security review #8). Inner
// middleware or handlers may set a different one; the last call wins.
func deadline(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setDeadline(w, d)
			next.ServeHTTP(w, r)
		})
	}
}

func setDeadline(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	t := time.Now().Add(d)
	_ = rc.SetReadDeadline(t)
	_ = rc.SetWriteDeadline(t)
}

// Run serves until ctx is cancelled, with background snapshot and flow maintenance.
func (s *Server) Run(ctx context.Context, addr string, cert tls.Certificate) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln, cert)
}

// Serve is Run on an existing listener. At most Config.MaxConns connections are served at
// once; further connections wait in the accept queue.
func (s *Server) Serve(ctx context.Context, ln net.Listener, cert tls.Certificate) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         s.TLSConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		// Covers reading each request; long-polls extend it per request (deadline middleware).
		ReadTimeout: routeTimeout,
		IdleTimeout: 120 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go s.maintain(ctx)
	go s.refreshCAs(ctx)
	go s.backupLoop(ctx)
	go s.cfg.Store.KeepLeadership(ctx, func(leader bool) { s.log.Info("leadership changed", "leader", leader) })
	go s.cfg.Store.Subscribe(ctx, s.notify.notify, s.notify.notifyAll)
	go s.categoriesLoop(ctx)
	go s.listsLoop(ctx)
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(netutil.LimitListener(ln, s.cfg.MaxConns), "", "") }()
	s.log.Info("control plane listening", "addr", ln.Addr().String(), "kex", "X25519MLKEM768", "maxConns", s.cfg.MaxConns)
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		return err
	}
}

// refreshCAs loads tenant CAs created by other Control Plane replicas into the client CA
// pool, so their devices can connect here within caRefreshInterval (issue #66).
func (s *Server) refreshCAs(ctx context.Context) {
	t := time.NewTicker(caRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.cfg.Authority.Refresh(ctx); err != nil {
			if ctx.Err() == nil {
				s.log.Warn("tenant CA refresh failed", "err", err)
			}
			continue
		}
		s.pool.Store(s.cfg.Authority.ClientCAPool())
	}
}

const caRefreshInterval = 30 * time.Second

// maintain re-signs snapshots before they expire and prunes old versions.
func (s *Server) maintain(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if s.cfg.Store.IsLeader() {
			s.singletonJobs(ctx)
		}
		s.flowLimit.prune()
		s.enrollLimit.prune()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// singletonJobs run on one Control Plane replica, the leader (ADR-0033).
func (s *Server) singletonJobs(ctx context.Context) {
	if err := s.refreshExpiring(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("snapshot refresh failed", "err", err)
	}
	if err := s.cfg.Store.PruneSnapshots(ctx, 5); err != nil && ctx.Err() == nil {
		s.log.Warn("snapshot prune failed", "err", err)
	}
	if n, err := s.cfg.Store.DeleteFlowsBefore(ctx, s.now().Add(-s.cfg.FlowRetention)); err != nil && ctx.Err() == nil {
		s.log.Warn("flow retention failed", "err", err)
	} else if n > 0 {
		s.log.Info("old flow records deleted", "count", n, "retention", s.cfg.FlowRetention)
	}
	if n, err := s.cfg.Store.DeleteExperienceBefore(ctx, s.now().Add(-s.cfg.FlowRetention)); err != nil && ctx.Err() == nil {
		s.log.Warn("experience retention failed", "err", err)
	} else if n > 0 {
		s.log.Info("old experience samples deleted", "count", n, "retention", s.cfg.FlowRetention)
	}
	if _, err := s.cfg.Store.DeleteAuditBefore(ctx, s.now().Add(-s.cfg.AuditRetention)); err != nil && ctx.Err() == nil {
		s.log.Warn("audit retention failed", "err", err)
	}
	s.logAuditHead(ctx)
}

func (s *Server) signingKeys() []api.SigningKey {
	return []api.SigningKey{{
		KeyID:     s.cfg.SigningKeyID,
		Algorithm: "ed25519",
		PublicKey: s.cfg.SigningKey.Public().(ed25519.PublicKey),
	}}
}

func (s *Server) handlePKI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, api.PKIBundle{CAPEM: string(s.cfg.Authority.BundlePEM()), SnapshotKeys: s.signingKeys()})
}

// --- helpers ---

type errorBody struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"` // policy.ValidationError field, for 400s on policy input
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errorBody{Error: msg})
}

// writeValidationErr writes a 400, including the offending field of a policy.ValidationError.
func writeValidationErr(w http.ResponseWriter, err error) {
	body := errorBody{Error: err.Error()}
	var ve *policy.ValidationError
	if errors.As(err, &ve) {
		body.Field = ve.Field
	}
	writeJSON(w, http.StatusBadRequest, body)
}

// decodeJSON decodes exactly one JSON object. A body of `null` is refused: it would decode
// to the zero value and, on PUT policy, silently wipe the tenant policy. So is trailing data.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: a JSON object is required")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return false
	}
	return true
}

func (s *Server) internalErr(w http.ResponseWriter, r *http.Request, msg string, err error) {
	s.log.ErrorContext(r.Context(), msg, "err", err, "path", r.URL.Path)
	writeErr(w, http.StatusInternalServerError, "internal error")
}
