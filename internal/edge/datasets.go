package edge

import (
	"context"
	"encoding/binary"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/dlp"
)

// DLP datasets at the Edge (ADR-0029): the datasets the DLP rules of its devices name, per
// tenant, fetched from the Control Plane and refreshed every few minutes.

const datasetRefresh = 5 * time.Minute

type datasetCache struct {
	mu     sync.RWMutex
	sets   map[string]map[string]*dlp.Dataset // tenant -> name -> dataset
	wanted map[string]string                  // tenant -> names joined, last fetched
	at     map[string]time.Time
}

func newDatasetCache() *datasetCache {
	return &datasetCache{sets: map[string]map[string]*dlp.Dataset{}, wanted: map[string]string{}, at: map[string]time.Time{}}
}

func (c *datasetCache) get(tenant, name string) *dlp.Dataset {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sets[tenant][name]
}

// wantedDatasets is, per tenant, the sorted dataset names of its devices' policies.
func (e *Edge) wantedDatasets() map[string][]string {
	e.reg.mu.Lock()
	defer e.reg.mu.Unlock()
	out := map[string][]string{}
	for _, d := range e.reg.devices {
		c, v := d.compiled.Load(), d.ztna.Load()
		if c == nil || v == nil {
			continue
		}
		for _, n := range c.DLPDatasets() {
			if !slices.Contains(out[v.tenant], n) {
				out[v.tenant] = append(out[v.tenant], n)
			}
		}
	}
	for t := range out {
		slices.Sort(out[t])
	}
	return out
}

// syncDatasets fetches the datasets whose set changed or that are due for a refresh.
func (e *Edge) syncDatasets(ctx context.Context, now time.Time) error {
	want := e.wantedDatasets()
	c := e.datasets
	var firstErr error
	for tenant, names := range want {
		key := strings.Join(names, ",")
		c.mu.RLock()
		same, fresh := c.wanted[tenant] == key, now.Sub(c.at[tenant]) < datasetRefresh
		c.mu.RUnlock()
		if same && fresh {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, time.Minute)
		resp, err := e.cp.Datasets(fctx, tenant, names)
		cancel()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sets := map[string]*dlp.Dataset{}
		for _, d := range resp.Datasets {
			if len(d.Hashes)%8 != 0 || len(d.Key) == 0 || (d.Kind != dlp.KindValues && d.Kind != dlp.KindDocument) {
				continue
			}
			hs := make([]uint64, len(d.Hashes)/8)
			for i := range hs {
				hs[i] = binary.BigEndian.Uint64(d.Hashes[8*i:])
			}
			if !slices.IsSorted(hs) {
				slices.Sort(hs)
			}
			sets[d.Name] = &dlp.Dataset{Name: d.Name, Kind: d.Kind, Key: d.Key, Hashes: hs}
		}
		c.mu.Lock()
		c.sets[tenant], c.wanted[tenant], c.at[tenant] = sets, key, now
		c.mu.Unlock()
		e.log.Info("dlp datasets updated", "tenant", tenant, "datasets", len(sets))
	}
	c.mu.Lock()
	for t := range c.sets {
		if _, ok := want[t]; !ok {
			delete(c.sets, t)
			delete(c.wanted, t)
			delete(c.at, t)
		}
	}
	c.mu.Unlock()
	return firstErr
}

func (e *Edge) datasetLoop(ctx context.Context) {
	t := time.NewTicker(catSyncInterval)
	defer t.Stop()
	for {
		if err := e.syncDatasets(ctx, time.Now()); err != nil && ctx.Err() == nil {
			e.log.Warn("dlp dataset sync failed; keeping the current ones", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
