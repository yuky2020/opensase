package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// Edge list and order (issue #71). The list comes from enrolment and is refreshed from
// GET /v1/edges, so Edges added later are used. Within one priority the client prefers the
// Edge with the lowest TCP connect time to its session URL, which also picks the nearest
// region.

const (
	fileEdges          = "edges.json" // api.DeviceEdges, newer than the enrolment's list
	edgesRefresh       = time.Hour
	edgeLatencyTimeout = 2 * time.Second
	latencyBucket      = 10 * time.Millisecond
)

// edgeList returns the Edges in the order sessions should try them.
func (id *identity) edgeList() []api.EdgeInfo {
	if l := id.edges.Load(); l != nil {
		return *l
	}
	return id.resp.Edges
}

// loadEdges restores the last refreshed Edge list, if any.
func (e *Engine) loadEdges(id *identity) {
	js, err := readStateFile(e.stateDir, fileEdges)
	if err != nil {
		return
	}
	var de api.DeviceEdges
	if json.Unmarshal(js, &de) == nil && len(de.Edges) > 0 {
		id.edges.Store(&de.Edges)
	}
}

// refreshEdges fetches the Edge list, orders it by priority and latency, stores it for the
// next sessions and persists it.
func (e *Engine) refreshEdges(ctx context.Context, id *identity) error {
	var de api.DeviceEdges
	if _, err := doJSON(ctx, id.cp, http.MethodGet, joinURL(id.resp.ControlURL, "/v1/edges"), nil, nil, &de); err != nil {
		return err
	}
	if len(de.Edges) == 0 {
		return errors.New("mobile: the Control Plane returned no Edges")
	}
	ordered := e.orderEdges(ctx, de.Edges)
	id.edges.Store(&ordered)
	js, err := json.Marshal(api.DeviceEdges{Edges: ordered})
	if err != nil {
		return err
	}
	return writeFileAtomic(e.stateDir, fileEdges, js)
}

// orderEdges sorts edges by priority, then by measured connect latency (unreachable last),
// keeping the Control Plane's order for ties.
func (e *Engine) orderEdges(ctx context.Context, edges []api.EdgeInfo) []api.EdgeInfo {
	rtt := make([]time.Duration, len(edges))
	var wg sync.WaitGroup
	for i, ed := range edges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rtt[i] = e.connectTime(ctx, ed.SessionURL)
		}()
	}
	wg.Wait()
	idx := make([]int, len(edges))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ea, eb := edges[idx[a]], edges[idx[b]]
		if ea.Priority != eb.Priority {
			return ea.Priority < eb.Priority
		}
		// Latencies within latencyBucket count as equal, so close Edges keep the
		// Control Plane's order instead of flapping with every measurement.
		return rtt[idx[a]]/latencyBucket < rtt[idx[b]]/latencyBucket
	})
	out := make([]api.EdgeInfo, len(edges))
	for i, j := range idx {
		out[i] = edges[j]
	}
	return out
}

// connectTime measures a TCP connect to the host of sessionURL outside the tunnel; it
// returns a large value when the Edge does not answer.
func (e *Engine) connectTime(ctx context.Context, sessionURL string) time.Duration {
	const unreachable = time.Hour
	u, err := url.Parse(sessionURL)
	if err != nil || u.Host == "" {
		return unreachable
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, edgeLatencyTimeout)
	defer cancel()
	start := time.Now()
	c, err := dialer(e.protect).DialContext(ctx, "tcp", host)
	if err != nil {
		return unreachable
	}
	d := time.Since(start)
	_ = c.Close()
	return d
}

// edgesLoop refreshes the Edge list at start and every edgesRefresh while the tunnel runs.
func (e *Engine) edgesLoop(rs *runState) {
	defer rs.wg.Done()
	for {
		ctx, cancel := context.WithTimeout(rs.ctx, 30*time.Second)
		err := e.refreshEdges(ctx, rs.id)
		cancel()
		if err != nil && rs.ctx.Err() == nil && !errors.Is(err, os.ErrNotExist) {
			e.log.Warn("Edge list refresh failed; keeping the current list", "err", err)
		}
		if !sleep(rs.ctx, edgesRefresh) {
			return
		}
	}
}
