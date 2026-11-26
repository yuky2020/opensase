package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/metrics"
	"github.com/yuky2020/opensase/pkg/store"
)

// Operations endpoints (issue #73): /metrics (Prometheus text format), /healthz (the process
// runs) and /readyz (it can serve: database, PKI, categories). They are served by OpsHandler
// on a separate listener that should only be reachable by the operator's monitoring.

// edgeReportWindow is how recent an Edge's session report must be to count as reporting.
const edgeReportWindow = 5 * time.Minute

type observer struct {
	reg         *metrics.Registry
	requests    *metrics.Counter
	enrollFails *metrics.Counter
	compileFail *metrics.Counter
}

func (s *Server) initMetrics() {
	r := metrics.New()
	s.obs = &observer{
		reg:         r,
		requests:    r.NewCounter("opensase_cp_http_requests_total", "HTTP requests by status class.", "class"),
		enrollFails: r.NewCounter("opensase_cp_enroll_failures_total", "Failed device and Connector enrolments."),
		compileFail: r.NewCounter("opensase_cp_snapshot_failures_total", "Policy snapshots that could not be compiled or signed."),
	}
	r.NewGaugeValue("opensase_cp_leader", "1 if this replica runs the singleton jobs (ADR-0033).", func() float64 {
		if s.cfg.Store.IsLeader() {
			return 1
		}
		return 0
	})
	r.NewGaugeValue("opensase_cp_devices", "Enrolled, non-revoked devices.", func() float64 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := s.cfg.Store.CountActiveDevices(ctx)
		if err != nil {
			return -1
		}
		return float64(n)
	})
	r.NewGauge("opensase_cp_edge_sessions", "Devices with a live session, per Edge, from the Edges' last reports.", func() []metrics.Sample {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		counts, err := s.cfg.Store.EdgeSessionCounts(ctx, s.now().Add(-edgeReportWindow))
		if err != nil {
			return nil
		}
		var out []metrics.Sample
		for _, e := range s.cfg.Edges {
			out = append(out, metrics.Sample{Labels: map[string]string{"edge": e.ID}, Value: float64(counts[e.ID])})
		}
		return out
	})
	r.NewGaugeValue("opensase_cp_category_list_age_seconds", "Age of the loaded web category list; -1 if none.", func() float64 {
		c := s.categoryState()
		if c == nil {
			return -1
		}
		return s.now().Sub(c.loadedAt).Seconds()
	})
	r.NewGaugeValue("opensase_cp_audit_chain_ok", "1 if the last audit chain check passed, 0 if it failed, -1 before the first check.", func() float64 {
		return float64(s.auditOK.Load())
	})
	r.NewGauge("opensase_cp_certificate_expiry_seconds", "Seconds until the Control Plane certificates expire.", func() []metrics.Sample {
		var out []metrics.Sample
		if !s.cfg.ServerCertNotAfter.IsZero() {
			out = append(out, metrics.Sample{Labels: map[string]string{"cert": "controlplane"}, Value: s.cfg.ServerCertNotAfter.Sub(s.now()).Seconds()})
		}
		out = append(out, metrics.Sample{Labels: map[string]string{"cert": "root"}, Value: s.cfg.Authority.Root.Cert.NotAfter.Sub(s.now()).Seconds()})
		return out
	})
}

// OpsHandler serves /metrics, /healthz and /readyz (issue #73).
func (s *Server) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", s.obs.reg.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if msg := s.notReady(r.Context()); msg != "" {
			http.Error(w, msg, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

// notReady returns why the Control Plane cannot serve yet, or "".
func (s *Server) notReady(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.cfg.Store.Ping(ctx); err != nil {
		return "database unreachable"
	}
	if s.cfg.CategoriesURL != "" && s.categoryState() == nil {
		return "web category list not loaded yet"
	}
	return ""
}

// countRequest records a finished request (called by logRequests).
func (s *Server) countRequest(code int) {
	class := "5xx"
	switch {
	case code < 300:
		class = "2xx"
	case code < 400:
		class = "3xx"
	case code < 500:
		class = "4xx"
	}
	s.obs.requests.Inc(class)
}

// handleAdminStatus reports the deployment health for the portal status page (issue #73).
func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.now()
	counts, err := s.cfg.Store.EdgeSessionCounts(ctx, now.Add(-edgeReportWindow))
	if err != nil {
		s.internalErr(w, r, "edge sessions", err)
		return
	}
	reporting, err := s.cfg.Store.EdgesReportingSince(ctx, now.Add(-edgeReportWindow))
	if err != nil {
		s.internalErr(w, r, "edge reports", err)
		return
	}
	st := api.AdminStatus{Leader: s.cfg.Store.IsLeader(), CategoryListAgeSec: -1, AuditChain: "unknown"}
	for _, e := range s.cfg.Edges {
		st.Edges = append(st.Edges, api.EdgeStatus{ID: e.ID, Region: e.Region, Sessions: counts[e.ID], Reporting: reporting[e.ID]})
		st.DevicesOnline += counts[e.ID]
	}
	if st.DevicesEnrolled, err = s.cfg.Store.CountActiveDevices(ctx); err != nil {
		s.internalErr(w, r, "devices", err)
		return
	}
	conns, err := s.cfg.Store.ListConnectors(ctx, store.ConnectorFilter{})
	if err != nil {
		s.internalErr(w, r, "connectors", err)
		return
	}
	st.ConnectorsTotal = len(conns)
	for _, c := range conns {
		if !c.LastSeen.IsZero() && now.Sub(c.LastSeen) < edgeReportWindow {
			st.ConnectorsOnline++
		}
	}
	st.Certificates = append(st.Certificates, api.CertExpiry{Name: "root", NotAfter: s.cfg.Authority.Root.Cert.NotAfter})
	if !s.cfg.ServerCertNotAfter.IsZero() {
		st.Certificates = append(st.Certificates, api.CertExpiry{Name: "controlplane", NotAfter: s.cfg.ServerCertNotAfter})
	}
	switch s.auditOK.Load() {
	case 1:
		st.AuditChain = "ok"
	case 0:
		st.AuditChain = "broken"
	}
	if c := s.categoryState(); c != nil {
		st.CategoryListAgeSec = int64(now.Sub(c.loadedAt).Seconds())
	}
	writeJSON(w, http.StatusOK, st)
}
