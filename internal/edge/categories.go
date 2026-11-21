package edge

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Web categories (ADR-0022). The Edge fetches from the Control Plane only the categories that
// the tenants of its devices block, and refreshes them when that set changes or hourly. Until
// a list arrives, categories are not enforced (fail open): a category list is a coarse
// filter, and blocking all web traffic while it loads would be worse.

const (
	catSyncInterval = 30 * time.Second
	catRefresh      = time.Hour
)

// catSet is the category data in force.
type catSet struct {
	db    *categories.DB
	names []string // sorted
	etag  string
	at    time.Time
}

// category reports the first category of the device's policy that name belongs to.
// DNS AllowDomains of the tenant override categories.
func (e *Edge) category(c *policy.Compiled, name string) (string, bool) {
	want := c.Categories()
	if len(want) == 0 {
		return "", false
	}
	cs := e.cats.Load()
	if cs == nil || c.DNSAllows(name) {
		return "", false
	}
	return cs.db.Lookup(name, want)
}

// wantedCategories is the sorted union of the categories in the devices' policies.
func (e *Edge) wantedCategories() []string {
	e.reg.mu.Lock()
	defer e.reg.mu.Unlock()
	var out []string
	for _, d := range e.reg.devices {
		if c := d.compiled.Load(); c != nil {
			for _, n := range c.Categories() {
				if !slices.Contains(out, n) {
					out = append(out, n)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// syncCategories fetches the wanted categories when they changed or are due for a refresh.
func (e *Edge) syncCategories(ctx context.Context, now time.Time) error {
	want := e.wantedCategories()
	cur := e.cats.Load()
	if len(want) == 0 {
		if cur != nil {
			e.cats.Store(nil)
		}
		return nil
	}
	same := cur != nil && slices.Equal(cur.names, want)
	if same && now.Sub(cur.at) < catRefresh {
		return nil
	}
	etag := ""
	if same {
		etag = cur.etag
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	body, newTag, notModified, err := e.cp.Categories(ctx, want, etag)
	if err != nil {
		return err
	}
	if notModified {
		e.cats.Store(&catSet{db: cur.db, names: cur.names, etag: cur.etag, at: now})
		return nil
	}
	db, err := categories.Decode(bytes.NewReader(body))
	if err != nil {
		return err
	}
	e.cats.Store(&catSet{db: db, names: want, etag: newTag, at: now})
	e.log.Info("web categories updated", "categories", strings.Join(want, ","), "bytes", len(body))
	return nil
}

func (e *Edge) categoryLoop(ctx context.Context) {
	t := time.NewTicker(catSyncInterval)
	defer t.Stop()
	for {
		if err := e.syncCategories(ctx, time.Now()); err != nil && ctx.Err() == nil {
			e.log.Warn("web category sync failed; keeping the current list", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
