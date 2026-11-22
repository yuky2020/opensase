package controlplane

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"runtime/debug"
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

// Provisioning key format: "osk_" + base64url(32 random bytes).
const provisioningKeyPrefix = "osk_"

var platforms = map[string]bool{"android": true, "linux": true, "windows": true, "macos": true, "ios": true}

// --- device endpoints ---

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !strings.HasPrefix(req.ProvisioningKey, provisioningKeyPrefix) || req.CSRPEM == "" {
		writeErr(w, http.StatusBadRequest, "provisioningKey and csrPem are required")
		return
	}
	if !platforms[req.Platform] {
		writeErr(w, http.StatusBadRequest, "unknown platform")
		return
	}
	if req.DeviceName == "" || len(req.DeviceName) > 128 {
		writeErr(w, http.StatusBadRequest, "deviceName must be 1-128 characters")
		return
	}
	if _, err := pki.ParseCSR([]byte(req.CSRPEM)); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	hash := sha256.Sum256([]byte(req.ProvisioningKey))
	var certPEM, tenantCAPEM []byte
	dev, err := s.cfg.Store.Enroll(r.Context(), hash[:], s.now(), func(e store.Enrollment) (store.Device, error) {
		ca, err := s.cfg.Authority.TenantCA(e.TenantID)
		if err != nil {
			return store.Device{}, err
		}
		id := uuid.NewString()
		pemChain, leaf, err := ca.SignDeviceCSR([]byte(req.CSRPEM), e.TenantID, id, pki.DeviceValidity)
		if err != nil {
			return store.Device{}, err
		}
		certPEM, tenantCAPEM = pemChain, ca.CertPEM()
		return store.Device{ID: id, Name: req.DeviceName, Platform: req.Platform, CertSerial: leaf.SerialNumber.String()}, nil
	})
	if errors.Is(err, store.ErrKeyInvalid) {
		s.log.WarnContext(r.Context(), "enrollment rejected: provisioning key invalid")
		writeErr(w, http.StatusForbidden, "provisioning key invalid, expired or used up")
		return
	}
	if err != nil {
		s.internalErr(w, r, "enroll", err)
		return
	}
	if _, err := s.compileDevices(r.Context(), dev.TenantID, []store.Device{dev}); err != nil {
		s.internalErr(w, r, "initial snapshot", err)
		return
	}
	edges, err := s.edgesFor(r.Context(), dev.TenantID, false)
	if err != nil {
		s.internalErr(w, r, "edges", err)
		return
	}
	s.log.InfoContext(r.Context(), "device enrolled", "tenant", dev.TenantID, "user", dev.UserID, "device", dev.ID, "platform", dev.Platform)
	writeJSON(w, http.StatusOK, api.EnrollResponse{
		TenantID:       dev.TenantID,
		UserID:         dev.UserID,
		DeviceID:       dev.ID,
		CertificatePEM: string(certPEM),
		// Root (anchors the Control Plane and Edge server certs) followed by the tenant CA, so
		// that clients verifying the device cert against CAPEM alone succeed.
		CAPEM:        string(append(s.cfg.Authority.Root.CertPEM(), tenantCAPEM...)),
		Edges:        edges,
		SnapshotKeys: s.signingKeys(),
		ControlURL:   s.cfg.ControlURL,
	})
}

func etag(v uint64) string { return `"` + strconv.FormatUint(v, 10) + `"` }

// parseETag accepts `"7"`, `W/"7"` and `7`.
func parseETag(h string) (uint64, bool) {
	h = strings.TrimPrefix(strings.TrimSpace(h), "W/")
	v, err := strconv.ParseUint(strings.Trim(h, `"`), 10, 64)
	return v, err == nil
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
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
		if !s.polls.acquire(p.device.ID) {
			writeErr(w, http.StatusTooManyRequests, "too many concurrent snapshot long-polls for this device")
			return
		}
		defer s.polls.release(p.device.ID)
		t := time.NewTimer(wait)
		defer t.Stop()
		deadline = t.C
	}
	for {
		// Subscribe before reading so an update between the read and the wait is not lost.
		ch := s.notify.wait(p.device.ID)
		rec, err := s.cfg.Store.LatestSnapshot(r.Context(), p.device.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalErr(w, r, "load snapshot", err)
			return
		}
		if err == nil && (!hasHave || rec.Version != have) {
			w.Header().Set("ETag", etag(rec.Version))
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(rec.Envelope)
			return
		}
		if err == nil && rec.Version == have && deadline == nil {
			w.Header().Set("ETag", etag(rec.Version))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if deadline == nil {
			writeErr(w, http.StatusNotFound, "no snapshot yet")
			return
		}
		select {
		case <-ch:
		case <-deadline:
			if err == nil {
				w.Header().Set("ETag", etag(rec.Version))
			}
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
	}
}

// handleGetSelfRules returns the stored, unmerged user layer (empty if none was set).
func (s *Server) handleGetSelfRules(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	ur, err := s.cfg.Store.GetUserRules(r.Context(), p.device.TenantID, p.device.UserID)
	if errors.Is(err, store.ErrNotFound) {
		ur, err = api.UserRules{}, nil
	}
	if err != nil {
		s.internalErr(w, r, "load user rules", err)
		return
	}
	if ur.Rules == nil {
		ur.Rules = []policy.Rule{}
	}
	if ur.Apps == nil {
		ur.Apps = map[string]policy.AppPolicy{}
	}
	writeJSON(w, http.StatusOK, ur)
}

func (s *Server) handleSelfRules(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	var ur api.UserRules
	if !decodeJSON(w, r, &ur) {
		return
	}
	tp, err := s.tenantPolicy(r.Context(), p.device.TenantID)
	if err != nil {
		s.internalErr(w, r, "load tenant policy", err)
		return
	}
	if !tp.AllowUserRules {
		writeErr(w, http.StatusForbidden, "tenant does not allow user rules")
		return
	}
	for i := range ur.Rules {
		ur.Rules[i].Source = policy.SourceUser
	}
	if err := validateUserRules(tp, ur); err != nil {
		writeValidationErr(w, err)
		return
	}
	if err := s.cfg.Store.PutUserRules(r.Context(), p.device.TenantID, p.device.UserID, ur); err != nil {
		s.internalErr(w, r, "store user rules", err)
		return
	}
	devs, err := s.cfg.Store.ListDevices(r.Context(), store.DeviceFilter{TenantID: p.device.TenantID, UserID: p.device.UserID})
	if err != nil {
		s.internalErr(w, r, "list devices", err)
		return
	}
	recs, err := s.compileDevices(r.Context(), p.device.TenantID, devs)
	if err != nil {
		s.internalErr(w, r, "recompile", err)
		return
	}
	rec := recs[p.device.ID]
	w.Header().Set("ETag", etag(rec.Version))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rec.Envelope)
}

// handleDecide evaluates the device snapshot; if the verdict is still "ask", the tenant's
// cloud-only data (DecideBlockDomains, DecideBlockCIDRs, DecideDefault) decides.
//
// CONTRACT-CHANGE-REQUEST: Edges call this route with their edge certificate and
// "?device=<id>" to resolve "ask" verdicts for tunnel traffic (edgeMode evaluation). The
// endpoint list in pkg/api documents device mTLS only.
func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	var req api.DecideRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	dev, edgeMode := p.device, false
	if p.id.Kind == pki.PeerEdge {
		d, live, err := s.edgeDevice(r, p.id.EdgeID, r.URL.Query().Get("device"))
		if err != nil {
			s.internalErr(w, r, "edge device", err)
			return
		}
		if !live {
			writeErr(w, http.StatusForbidden, "device has no live session on this edge")
			return
		}
		dev, edgeMode = d, true
		req.Flow.App, req.Flow.UID, req.Flow.Network = "", 0, ""
	}
	rec, err := s.cfg.Store.LatestSnapshot(r.Context(), dev.ID)
	if err != nil {
		s.internalErr(w, r, "load snapshot", err)
		return
	}
	c, err := s.compiled.get(rec)
	if err != nil {
		s.internalErr(w, r, "compile snapshot", err)
		return
	}
	d := c.Evaluate(req.Flow, edgeMode)
	if d.Action == policy.ActionAsk {
		de, err := s.decideFor(r.Context(), dev.TenantID)
		if err != nil {
			s.internalErr(w, r, "decide data", err)
			return
		}
		d = de.cloudDecide(req.Flow)
	}
	now := s.now()
	// CONTRACT-CHANGE-REQUEST: FlowRecord.Where documents "device"|"edge"; cloud decisions are
	// recorded with Where="cloud". Decision records count against the device's flow rate.
	req.Flow = sanitizeFlow(api.FlowRecord{Flow: req.Flow}, now).Flow
	// When rate limited the verdict is still returned; only the record is dropped.
	if s.flowLimit.take(dev.ID, 1) == 1 {
		rec := api.FlowRecord{Start: now, Flow: req.Flow, Decision: d, Where: "cloud", DeviceID: dev.ID}
		if err := s.cfg.Store.InsertFlows(r.Context(), dev.TenantID, []api.FlowRecord{rec}); err != nil {
			s.log.WarnContext(r.Context(), "record decision", "err", err)
		}
	}
	writeJSON(w, http.StatusOK, api.DecideResponse{Decision: d, TTL: DecideTTL})
}

// handleFlows stores flow records. Devices may only report their own flows; Edges report
// flows of any device they serve (the tenant is taken from the device).
//
// CONTRACT-CHANGE-REQUEST: pkg/api lists POST /v1/flows as device mTLS only; Edges post
// their Where="edge" records here with the edge certificate.
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	var b api.FlowBatch
	if !decodeJSON(w, r, &b) {
		return
	}
	if len(b.Records) > maxFlowRecords {
		writeErr(w, http.StatusRequestEntityTooLarge, "too many records")
		return
	}
	now := s.now()
	byTenant := map[string][]api.FlowRecord{}
	byDevice := map[string]int{} // records per device in this batch, for the rate limit
	dropped := 0
	if p.id.Kind == pki.PeerDevice {
		for _, rec := range b.Records {
			rec = sanitizeFlow(rec, now)
			s.tagCategories(&rec)
			rec.DeviceID, rec.Where = p.device.ID, "device"
			byTenant[p.device.TenantID] = append(byTenant[p.device.TenantID], rec)
		}
		byDevice[p.device.ID] = len(b.Records)
	} else {
		// An edge may only report flows of devices with a live session on it.
		tenants := map[string]string{} // device -> tenant, "" if not allowed
		for _, rec := range b.Records {
			t, ok := tenants[rec.DeviceID]
			if !ok {
				d, live, err := s.edgeDevice(r, p.id.EdgeID, rec.DeviceID)
				if err != nil {
					s.internalErr(w, r, "edge device", err)
					return
				}
				if live {
					t = d.TenantID
				}
				tenants[rec.DeviceID] = t
			}
			if t == "" {
				dropped++
				continue
			}
			rec = sanitizeFlow(rec, now)
			s.tagCategories(&rec)
			rec.Where = "edge"
			byTenant[t] = append(byTenant[t], rec)
			byDevice[rec.DeviceID]++
		}
	}
	// Per-device rate limit: keep the first granted records of each device.
	granted := map[string]int{}
	for d, n := range byDevice {
		granted[d] = s.flowLimit.take(d, n)
		dropped += n - granted[d]
	}
	for t, recs := range byTenant {
		kept := recs[:0]
		for _, rec := range recs {
			if granted[rec.DeviceID] > 0 {
				granted[rec.DeviceID]--
				kept = append(kept, rec)
			}
		}
		byTenant[t] = kept
	}
	if dropped > 0 {
		s.log.WarnContext(r.Context(), "flow records dropped (rate limit or no live session)", "count", dropped)
	}
	for t, recs := range byTenant {
		if err := s.cfg.Store.InsertFlows(r.Context(), t, recs); err != nil {
			s.internalErr(w, r, "store flows", err)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// A Private Edge (ADR-0014) gets only the devices and connectors of its tenant.
func (s *Server) handleEdgePeers(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	edge, err := s.cfg.Store.GetEdge(r.Context(), p.id.EdgeID)
	if err != nil {
		s.internalErr(w, r, "edge", err)
		return
	}
	scoped := func(tenantID string) bool { return edge.TenantID == "" || edge.TenantID == tenantID }
	act, err := s.cfg.Store.ActiveSnapshots(r.Context())
	if err != nil {
		s.internalErr(w, r, "active snapshots", err)
		return
	}
	cs, err := s.cfg.Store.ListConnectors(r.Context(), store.ConnectorFilter{EnrolledOnly: true})
	if err != nil {
		s.internalErr(w, r, "list connectors", err)
		return
	}
	out := api.EdgePeers{Devices: make([]api.EdgeDevice, 0, len(act)), Connectors: make([]api.EdgeConnector, 0, len(cs))}
	for _, c := range cs {
		if !scoped(c.TenantID) {
			continue
		}
		out.Connectors = append(out.Connectors, api.EdgeConnector{ConnectorID: c.ID, TenantID: c.TenantID, Group: c.Group, CertSerial: c.CertSerial})
	}
	for _, a := range act {
		if !scoped(a.Device.TenantID) {
			continue
		}
		var env policy.Envelope
		if err := json.Unmarshal(a.Snapshot.Envelope, &env); err != nil {
			s.internalErr(w, r, "decode envelope", err)
			return
		}
		out.Devices = append(out.Devices, api.EdgeDevice{DeviceID: a.Device.ID, TenantID: a.Device.TenantID, Snapshot: env, CertSerial: a.Device.CertSerial})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- admin endpoints ---

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var t api.AdminTenant
	if !decodeJSON(w, r, &t) {
		return
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if !pki.ValidID(t.ID) || t.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required and id must match [a-zA-Z0-9][a-zA-Z0-9._-]*")
		return
	}
	err := s.cfg.Store.CreateTenant(r.Context(), store.Tenant{ID: t.ID, Name: t.Name})
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "tenant exists")
		return
	}
	if err != nil {
		s.internalErr(w, r, "create tenant", err)
		return
	}
	if _, err := s.cfg.Authority.TenantCA(t.ID); err != nil {
		s.internalErr(w, r, "tenant CA", err)
		return
	}
	s.pool.Store(s.cfg.Authority.ClientCAPool())
	s.log.InfoContext(r.Context(), "tenant created", "tenant", t.ID)
	writeJSON(w, http.StatusCreated, t)
}

// tenantParam loads {t}; it writes 404 and returns false if the tenant does not exist.
func (s *Server) tenantParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	t := chi.URLParam(r, "t")
	if _, err := s.cfg.Store.GetTenant(r.Context(), t); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "unknown tenant")
		} else {
			s.internalErr(w, r, "get tenant", err)
		}
		return "", false
	}
	return t, true
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	var u api.AdminUser
	if !decodeJSON(w, r, &u) {
		return
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if !pki.ValidID(u.ID) || u.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required and id must be a valid identifier")
		return
	}
	err := s.cfg.Store.CreateUser(r.Context(), store.User{ID: u.ID, TenantID: t, Email: u.Email, Name: u.Name})
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "user exists")
		return
	}
	if err != nil {
		s.internalErr(w, r, "create user", err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	var req api.ProvisioningKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.MaxUses < 1 {
		req.MaxUses = 1
	}
	validFor := time.Duration(req.ValidFor) * time.Second
	if validFor <= 0 {
		validFor = 24 * time.Hour
	}
	validFor = min(validFor, 30*24*time.Hour)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	key := provisioningKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	hash := sha256.Sum256([]byte(key))
	exp := s.now().Add(validFor).UTC().Truncate(time.Second)
	err := s.cfg.Store.CreateProvisioningKey(r.Context(), store.ProvisioningKey{Hash: hash[:], TenantID: t, UserID: req.UserID, MaxUses: req.MaxUses, ExpiresAt: exp})
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "unknown user")
		return
	}
	if err != nil {
		s.internalErr(w, r, "create key", err)
		return
	}
	s.log.InfoContext(r.Context(), "provisioning key created", "tenant", t, "user", req.UserID, "maxUses", req.MaxUses, "expires", exp)
	writeJSON(w, http.StatusCreated, api.ProvisioningKey{Key: key, UserID: req.UserID, ExpiresAt: exp})
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	var tp api.TenantPolicy
	if !decodeJSON(w, r, &tp) {
		return
	}
	normalizePrivateApps(tp.PrivateApps)
	err := validateTenantPolicy(tp)
	if err == nil {
		err = s.validateCategories(tp.Categories)
	}
	if err != nil {
		writeValidationErr(w, err)
		return
	}
	for i := range tp.Rules {
		tp.Rules[i].Source = policy.SourceTenant
	}
	// Optimistic concurrency (issue #19): with If-Match, the policy must not have changed
	// since the client read it. The check and the write are one critical section.
	s.policyMu.Lock()
	if want := r.Header.Get("If-Match"); want != "" && want != "*" {
		cur, err := s.tenantPolicy(r.Context(), t)
		if err != nil {
			s.policyMu.Unlock()
			s.internalErr(w, r, "load policy", err)
			return
		}
		if policyETag(cur) != want {
			s.policyMu.Unlock()
			w.Header().Set("ETag", policyETag(cur))
			writeErr(w, http.StatusPreconditionFailed, "the policy changed since it was read; reload it and apply the change again")
			return
		}
	}
	err = s.cfg.Store.PutTenantPolicy(r.Context(), t, tp)
	s.policyMu.Unlock()
	if err != nil {
		s.internalErr(w, r, "store policy", err)
		return
	}
	w.Header().Set("ETag", policyETag(tp))
	s.invalidateDecide(t)
	s.notify.notify(notifyTenant(t)) // connector configs (ADR-0013)
	devs, err := s.cfg.Store.ListDevices(r.Context(), store.DeviceFilter{TenantID: t})
	if err != nil {
		s.internalErr(w, r, "list devices", err)
		return
	}
	if _, err := s.compileDevices(r.Context(), t, devs); err != nil {
		s.internalErr(w, r, "recompile", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	tp, err := s.tenantPolicy(r.Context(), t)
	if err != nil {
		s.internalErr(w, r, "load policy", err)
		return
	}
	w.Header().Set("ETag", policyETag(tp))
	writeJSON(w, http.StatusOK, tp)
}

// policyETag is a strong validator of a tenant policy: a hash of its JSON form.
func policyETag(tp api.TenantPolicy) string {
	b, _ := json.Marshal(tp)
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:12]) + `"`
}

// handleAdminInfo describes the Control Plane to admin clients (issue #19): the control URL
// with the root pin that enrollment QR codes need, and the build version.
func (s *Server) handleAdminInfo(w http.ResponseWriter, _ *http.Request) {
	sum := sha256.Sum256(s.cfg.Authority.Root.Cert.Raw)
	pin := hex.EncodeToString(sum[:])
	control := s.cfg.ControlURL
	if i := strings.IndexByte(control, '#'); i >= 0 {
		control = control[:i]
	}
	if control != "" {
		control += "#sha256=" + pin
	}
	info := api.AdminInfo{ControlURL: control, RootSHA256: pin, Version: buildVersion()}
	if s.categoryState() != nil {
		info.Features = append(info.Features, "categories")
	}
	info.Features = append(info.Features, "tenant-roles", "policy-etag")
	writeJSON(w, http.StatusOK, info)
}

// buildVersion is the VCS revision of the binary, or "dev".
func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return s.Value[:12]
		}
	}
	if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func (s *Server) handleListFlows(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	recs, err := s.cfg.Store.ListFlows(r.Context(), t, limit)
	if err != nil {
		s.internalErr(w, r, "list flows", err)
		return
	}
	writeJSON(w, http.StatusOK, api.FlowBatch{Records: recs})
}

// AdminDevice is the admin view of a device (see the CONTRACT-CHANGE-REQUEST in Handler).
type AdminDevice struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	devs, err := s.cfg.Store.ListDevices(r.Context(), store.DeviceFilter{TenantID: t, IncludeRevoked: true})
	if err != nil {
		s.internalErr(w, r, "list devices", err)
		return
	}
	out := make([]AdminDevice, 0, len(devs))
	for _, d := range devs {
		out = append(out, AdminDevice{ID: d.ID, UserID: d.UserID, Name: d.Name, Platform: d.Platform, Revoked: d.Revoked, CreatedAt: d.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	d := chi.URLParam(r, "d")
	err := s.cfg.Store.RevokeDevice(r.Context(), t, d)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "unknown device")
		return
	}
	if err != nil {
		s.internalErr(w, r, "revoke", err)
		return
	}
	s.notify.notify(d)
	s.log.InfoContext(r.Context(), "device revoked", "tenant", t, "device", d)
	w.WriteHeader(http.StatusNoContent)
}
