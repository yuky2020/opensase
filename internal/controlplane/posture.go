package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

var (
	validRequireNames = []string{"diskEncryption", "screenLock", "firewall", "managed"}
	versionRegexp     = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}$`)
)

type postureError struct {
	msg string
}

func (e *postureError) Error() string { return e.msg }

// compareVersions compares dotted numeric versions a and b.
// Missing parts are 0; non-numeric parts compare as 0; "v" prefix is ignored.
// Returns -1 if a < b, 0 if a == b, and 1 if a > b.
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	maxLen := max(len(partsA), len(partsB))
	for i := 0; i < maxLen; i++ {
		valA := 0
		if i < len(partsA) {
			if n, err := strconv.Atoi(partsA[i]); err == nil {
				valA = n
			}
		}
		valB := 0
		if i < len(partsB) {
			if n, err := strconv.Atoi(partsB[i]); err == nil {
				valB = n
			}
		}
		if valA < valB {
			return -1
		}
		if valA > valB {
			return 1
		}
	}
	return 0
}

// postureFailing evaluates device posture p against posture policy pp and returns the
// names of failed checks in fixed order: "osVersion", "clientVersion", "diskEncryption",
// "screenLock", "firewall", "managed".
// Firewall applies only when p.OS is "windows". A nil pointer fails a required check.
// A nil report fails every required check plus osVersion/clientVersion when a minimum is set.
func postureFailing(pp api.PosturePolicy, p *api.Posture) []string {
	var failing []string

	if p == nil {
		if len(pp.MinOSVersion) > 0 {
			failing = append(failing, "osVersion")
		}
		if pp.MinClientVersion != "" {
			failing = append(failing, "clientVersion")
		}
		for _, name := range validRequireNames {
			if slices.Contains(pp.Require, name) {
				failing = append(failing, name)
			}
		}
		return failing
	}

	// 1. osVersion
	if minOS, ok := pp.MinOSVersion[p.OS]; ok && minOS != "" {
		if compareVersions(p.OSVersion, minOS) < 0 {
			failing = append(failing, "osVersion")
		}
	}

	// 2. clientVersion
	if pp.MinClientVersion != "" {
		if compareVersions(p.ClientVersion, pp.MinClientVersion) < 0 {
			failing = append(failing, "clientVersion")
		}
	}

	// 3. require in fixed order: diskEncryption, screenLock, firewall, managed
	for _, req := range validRequireNames {
		if !slices.Contains(pp.Require, req) {
			continue
		}
		switch req {
		case "diskEncryption":
			if p.DiskEncrypted == nil || !*p.DiskEncrypted {
				failing = append(failing, "diskEncryption")
			}
		case "screenLock":
			if p.ScreenLock == nil || !*p.ScreenLock {
				failing = append(failing, "screenLock")
			}
		case "firewall":
			if p.OS == "windows" {
				if p.Firewall == nil || !*p.Firewall {
					failing = append(failing, "firewall")
				}
			}
		case "managed":
			if p.Managed == nil || !*p.Managed {
				failing = append(failing, "managed")
			}
		}
	}

	return failing
}

// validatePosturePolicy checks pp:
//   - Require values only from the four names, no duplicates
//   - minOsVersion keys only android, windows, linux, macos, ios
//   - versions match ^v?[0-9]+(\.[0-9]+){0,3}$
//   - remediationDomains use the same domain syntax as rule domains (reuses policy.Compile)
func validatePosturePolicy(pp api.PosturePolicy) error {
	seenReq := make(map[string]bool, len(pp.Require))
	for i, req := range pp.Require {
		field := fmt.Sprintf("posture.require[%d]", i)
		if !slices.Contains(validRequireNames, req) {
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("unknown check %q", req)}
		}
		if seenReq[req] {
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("duplicate check %q", req)}
		}
		seenReq[req] = true
	}

	for os, v := range pp.MinOSVersion {
		field := fmt.Sprintf("posture.minOsVersion[%s]", os)
		if !platforms[os] {
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("unknown platform %q", os)}
		}
		if !versionRegexp.MatchString(v) {
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("invalid version %q", v)}
		}
	}

	if pp.MinClientVersion != "" {
		if !versionRegexp.MatchString(pp.MinClientVersion) {
			return &policy.ValidationError{Field: "posture.minClientVersion", Msg: fmt.Sprintf("invalid version %q", pp.MinClientVersion)}
		}
	}

	if len(pp.RemediationDomains) > 0 {
		_, err := policy.Compile(&policy.Snapshot{
			SchemaVersion: policy.CurrentSchemaVersion,
			TenantID:      "t",
			DeviceID:      "d",
			Firewall: policy.FirewallPolicy{
				DefaultAction: policy.ActionBlock,
				Rules: []policy.Rule{
					{
						ID:       "remediation",
						Source:   policy.SourceTenant,
						Priority: 1,
						Action:   policy.ActionAllow,
						Match:    policy.Match{Domains: pp.RemediationDomains},
					},
				},
			},
		})
		if err != nil {
			var ve *policy.ValidationError
			if errors.As(err, &ve) {
				field := strings.Replace(ve.Field, "firewall.rules[0].match.domains", "posture.remediationDomains", 1)
				return &policy.ValidationError{Field: field, Msg: ve.Msg}
			}
			return err
		}
	}

	return nil
}

// handlePosture receives advisory device posture (POST /v1/posture, ADR-0035).
func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	if p.id.Kind != pki.PeerDevice {
		writeErr(w, http.StatusForbidden, "device certificate required")
		return
	}
	// Reports share the device's flow rate under their own key, so a looping client cannot
	// turn them into a stream of store writes.
	if s.flowLimit.take("posture:"+p.device.ID, 1) == 0 {
		writeErr(w, http.StatusTooManyRequests, "too many posture reports")
		return
	}
	var rep api.Posture
	if !decodeJSONLimit(w, r, &rep, 16<<10) {
		return
	}
	if len(rep.OS) > 64 || len(rep.OSVersion) > 64 || len(rep.ClientVersion) > 64 {
		writeErr(w, http.StatusBadRequest, "string field longer than 64 bytes")
		return
	}
	now := s.now().UTC()
	if rep.CollectedAt.IsZero() {
		rep.CollectedAt = now
	}
	tp, err := s.tenantPolicy(r.Context(), p.device.TenantID)
	if err != nil {
		s.internalErr(w, r, "tenant policy", err)
		return
	}
	failing := postureFailing(tp.Posture, &rep)

	prev, err := s.cfg.Store.DevicePosture(r.Context(), p.device.ID)
	hadPrev := (err == nil)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalErr(w, r, "load previous posture", err)
		return
	}

	if err := s.cfg.Store.SetDevicePosture(r.Context(), p.device.TenantID, p.device.ID, rep, failing, now); err != nil {
		s.internalErr(w, r, "store posture", err)
		return
	}

	changed := !hadPrev || !slices.Equal(prev.Failing, failing)
	if changed {
		if _, err := s.compileDevices(r.Context(), p.device.TenantID, []store.Device{p.device}); err != nil {
			s.internalErr(w, r, "recompile snapshot after posture change", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetDevicePosture returns the last posture report of a device (GET /v1/admin/tenants/{t}/devices/{d}/posture).
func (s *Server) handleGetDevicePosture(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	d := chi.URLParam(r, "d")
	dev, err := s.cfg.Store.GetDevice(r.Context(), d)
	if errors.Is(err, store.ErrNotFound) || (err == nil && dev.TenantID != t) {
		writeErr(w, http.StatusNotFound, "unknown device")
		return
	}
	if err != nil {
		s.internalErr(w, r, "load device", err)
		return
	}
	posture, err := s.cfg.Store.DevicePosture(r.Context(), d)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no posture report")
		return
	}
	if err != nil {
		s.internalErr(w, r, "load device posture", err)
		return
	}
	writeJSON(w, http.StatusOK, posture)
}
