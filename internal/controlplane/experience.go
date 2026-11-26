package controlplane

import (
	"context"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

func (s *Server) handleExperience(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	now := s.now()
	since := now.Add(-24 * time.Hour)
	minSince := now.Add(-30 * 24 * time.Hour)
	if sStr := r.URL.Query().Get("since"); sStr != "" {
		sec, err := strconv.ParseInt(sStr, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid since parameter")
			return
		}
		since = time.Unix(sec, 0)
	}
	if since.Before(minSince) {
		since = minSince
	}
	deviceID := r.URL.Query().Get("device")
	rows, err := s.cfg.Store.ExperienceSince(r.Context(), t, since, deviceID)
	if err != nil {
		s.internalErr(w, r, "load experience", err)
		return
	}
	summaries := aggregateExperience(rows)
	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) validateProbe(ctx context.Context, pr api.ExperienceSample, now time.Time) bool {
	if pr.At.Before(now.Add(-24*time.Hour)) || pr.At.After(now.Add(5*time.Minute)) {
		return false
	}
	if !s.isKnownEdge(ctx, pr.EdgeID) {
		return false
	}
	if !(pr.RTTms >= 0 && pr.RTTms <= 60000) {
		return false
	}
	if !(pr.DNSms >= 0 && pr.DNSms <= 60000) {
		return false
	}
	if !(pr.LossPct >= 0 && pr.LossPct <= 100) {
		return false
	}
	switch policy.NetworkType(pr.Network) {
	case "", policy.NetworkWiFi, policy.NetworkCellular, policy.NetworkRoaming, policy.NetworkEthernet, policy.NetworkUnknown:
	default:
		return false
	}
	return true
}

func (s *Server) isKnownEdge(ctx context.Context, edgeID string) bool {
	if edgeID == "" {
		return false
	}
	for _, e := range s.cfg.Edges {
		if e.ID == edgeID {
			return true
		}
	}
	e, err := s.cfg.Store.GetEdge(ctx, edgeID)
	return err == nil && !e.Revoked
}

func nearestRankPercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	n := int(math.Ceil((p / 100.0) * float64(len(sorted))))
	if n < 1 {
		n = 1
	}
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[n-1]
}

type expGroupKey struct {
	deviceID string
	edgeID   string
}

func aggregateExperience(rows []store.ExperienceRow) []api.ExperienceSummary {
	if len(rows) == 0 {
		return []api.ExperienceSummary{}
	}
	groups := map[expGroupKey][]store.ExperienceRow{}
	for _, r := range rows {
		k := expGroupKey{deviceID: r.DeviceID, edgeID: r.EdgeID}
		groups[k] = append(groups[k], r)
	}
	summaries := make([]api.ExperienceSummary, 0, len(groups))
	for k, group := range groups {
		var lossSum float64
		var last time.Time
		var rtts []float64
		var dnss []float64
		for _, smp := range group {
			if smp.At.After(last) {
				last = smp.At
			}
			lossSum += smp.LossPct
			if smp.RTTms > 0 {
				rtts = append(rtts, smp.RTTms)
			}
			if smp.DNSms > 0 {
				dnss = append(dnss, smp.DNSms)
			}
		}
		slices.Sort(rtts)
		slices.Sort(dnss)
		count := len(group)
		var rttP50, rttP95, dnsP50 float64
		if len(rtts) > 0 {
			rttP50 = nearestRankPercentile(rtts, 50)
			rttP95 = nearestRankPercentile(rtts, 95)
		}
		if len(dnss) > 0 {
			dnsP50 = nearestRankPercentile(dnss, 50)
		}
		summaries = append(summaries, api.ExperienceSummary{
			DeviceID: k.deviceID,
			EdgeID:   k.edgeID,
			Samples:  count,
			RTTp50:   rttP50,
			RTTp95:   rttP95,
			LossPct:  lossSum / float64(count),
			DNSp50:   dnsP50,
			Last:     last,
		})
	}
	slices.SortFunc(summaries, func(a, b api.ExperienceSummary) int {
		if c := strings.Compare(a.DeviceID, b.DeviceID); c != 0 {
			return c
		}
		return strings.Compare(a.EdgeID, b.EdgeID)
	})
	return summaries
}
