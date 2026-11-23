package controlplane

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/store"
)

func (s *Server) handleGetDeviceRoutes(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	devID := chi.URLParam(r, "d")
	dev, err := s.cfg.Store.GetDevice(r.Context(), devID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && dev.TenantID != t) {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		s.internalErr(w, r, "get device", err)
		return
	}

	prefixes, err := s.cfg.Store.DeviceRoutes(r.Context(), devID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalErr(w, r, "get device routes", err)
		return
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	writeJSON(w, http.StatusOK, api.DeviceRoutes{CIDRs: out})
}

func (s *Server) handlePutDeviceRoutes(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	devID := chi.URLParam(r, "d")
	dev, err := s.cfg.Store.GetDevice(r.Context(), devID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && dev.TenantID != t) {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		s.internalErr(w, r, "get device", err)
		return
	}

	var req api.DeviceRoutes
	if !decodeJSON(w, r, &req) {
		return
	}
	prefixes := make([]netip.Prefix, 0, len(req.CIDRs))
	for _, s := range req.CIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid CIDR: "+err.Error())
			return
		}
		prefixes = append(prefixes, p.Masked())
	}

	if err := s.cfg.Store.SetDeviceRoutes(r.Context(), t, devID, prefixes); err != nil {
		switch {
		case errors.Is(err, store.ErrRouteOverlap):
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, store.ErrInvalidRoute):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, http.StatusNotFound, "device not found")
		default:
			s.internalErr(w, r, "set device routes", err)
		}
		return
	}

	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	writeJSON(w, http.StatusOK, api.DeviceRoutes{CIDRs: out})
}
