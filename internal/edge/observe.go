package edge

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/metrics"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Operations endpoints of the Edge (issue #73): /metrics, /healthz, /readyz on
// Config.OpsListen, plain HTTP, for the operator's monitoring only.

type edgeObserver struct {
	reg        *metrics.Registry
	dnsQueries *metrics.Counter
	blocks     *metrics.Counter
	syncFails  *metrics.Counter
}

func (e *Edge) initMetrics() {
	r := metrics.New()
	e.obs = &edgeObserver{
		reg:        r,
		dnsQueries: r.NewCounter("opensase_edge_dns_queries_total", "DNS queries answered by the Edge resolver."),
		blocks:     r.NewCounter("opensase_edge_blocks_total", "Blocked flows and queries, by enforcement layer.", "layer"),
		syncFails:  r.NewCounter("opensase_edge_peer_sync_failures_total", "Failed peer and trust syncs with the Control Plane."),
	}
	r.NewGaugeValue("opensase_edge_sessions", "Devices with a live tunnel session on this Edge.", func() float64 {
		return float64(len(e.liveSessions()))
	})
	r.NewGaugeValue("opensase_edge_devices", "Devices in the last peer feed.", func() float64 {
		e.reg.mu.Lock()
		defer e.reg.mu.Unlock()
		return float64(len(e.reg.devices))
	})
	r.NewGaugeValue("opensase_edge_peer_sync_age_seconds", "Seconds since the last successful peer sync; -1 before the first.", func() float64 {
		t := e.lastSyncOK.Load()
		if t == 0 {
			return -1
		}
		return time.Since(time.Unix(0, t)).Seconds()
	})
	r.NewGaugeValue("opensase_edge_flow_backlog", "Flow records waiting for upload to the Control Plane.", func() float64 {
		return float64(e.flows.pending())
	})
	r.NewGaugeValue("opensase_edge_certificate_expiry_seconds", "Seconds until the Edge certificate expires.", func() float64 {
		if l := e.cfg.Cert.Leaf; l != nil {
			return time.Until(l.NotAfter).Seconds()
		}
		return -1
	})
	e.flows.onAdd = func(recs []api.FlowRecord) {
		for _, rec := range recs {
			if rec.Decision.Action == policy.ActionBlock {
				e.obs.blocks.Inc(rec.Decision.Layer)
			}
		}
	}
}

func (e *Edge) opsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", e.obs.reg.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !e.ready.Load() {
			http.Error(w, "no peer feed or cached state yet", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

// serveOps runs the ops listener until ctx ends.
func (e *Edge) serveOps(ctx context.Context) {
	if e.cfg.OpsListen == "" {
		return
	}
	srv := &http.Server{Addr: e.cfg.OpsListen, Handler: e.opsHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	e.log.Info("ops endpoints", "addr", e.cfg.OpsListen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		e.log.Error("ops listener stopped", "addr", e.cfg.OpsListen, "err", err)
	}
}
