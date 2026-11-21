package controlplane

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/store"
)

// TLS inspection CAs (ADR-0018). The Control Plane keeps each tenant's inspection root; an
// Edge gets a 7-day intermediate for its own key, only for a tenant it serves that has
// inspection turned on.

// handleInspectionCA signs an Edge's inspection intermediate.
func (s *Server) handleInspectionCA(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	var req api.InspectionCARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !pki.ValidID(req.TenantID) {
		writeErr(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	edge, err := s.cfg.Store.GetEdge(r.Context(), p.id.EdgeID)
	if err != nil {
		s.internalErr(w, r, "edge", err)
		return
	}
	// A Private Edge serves only its tenant (ADR-0014).
	if edge.TenantID != "" && edge.TenantID != req.TenantID {
		writeErr(w, http.StatusForbidden, "edge does not serve this tenant")
		return
	}
	tp, err := s.cfg.Store.GetTenantPolicy(r.Context(), req.TenantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusForbidden, "inspection is off for this tenant")
		return
	case err != nil:
		s.internalErr(w, r, "tenant policy", err)
		return
	}
	if !tp.Web.Inspect {
		writeErr(w, http.StatusForbidden, "inspection is off for this tenant")
		return
	}
	chain, cert, err := s.cfg.Authority.SignInspectionCSR([]byte(req.CSR), req.TenantID, p.id.EdgeID, 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	s.log.InfoContext(r.Context(), "inspection intermediate issued", "tenant", req.TenantID, "edge", p.id.EdgeID, "expires", cert.NotAfter)
	writeJSON(w, http.StatusOK, api.InspectionCAResponse{Chain: string(chain), ExpiresAt: cert.NotAfter})
}

// handleGetInspectionRoot returns the tenant's inspection root (PEM), creating it on first
// use, for the admin to install on the tenant's devices.
func (s *Server) handleGetInspectionRoot(w http.ResponseWriter, r *http.Request) {
	t := chi.URLParam(r, "t")
	if _, err := s.cfg.Store.GetTenant(r.Context(), t); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tenant not found")
			return
		}
		s.internalErr(w, r, "tenant", err)
		return
	}
	ca, err := s.cfg.Authority.InspectionCA(t)
	if err != nil {
		s.internalErr(w, r, "inspection CA", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="opensase-inspection-`+t+`.crt"`)
	_, _ = w.Write(ca.CertPEM()) //nolint:gosec // G705: a PEM certificate we generated, served as a download, not HTML
}
