package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Blocklists from URLs (issue #63). The Control Plane downloads every list that a tenant
// policy names, turns it into an extra category and serves it to the Edges with the web
// categories; snapshots add the list categories to the tenant's blocked categories. Each
// replica downloads on its own.

// BuiltinList is a list an admin enables with one switch.
type BuiltinList struct {
	ID, Title, URL, Licence string
}

// BuiltinLists is the built-in catalog.
var BuiltinLists = []BuiltinList{
	{ID: "malware", Title: "Malware distribution sites (URLhaus, abuse.ch)", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Licence: "CC0"},
}

const (
	listsRefresh  = 6 * time.Hour
	listsDownload = 2 * time.Minute
	maxListsTotal = 32 // per tenant
)

var listIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// listCategory is the category name of a tenant's custom list, or of a built-in list.
func listCategory(tenantID, id string) string {
	n := "t-" + tenantID + "-" + id
	if categories.ValidName(n) {
		return n
	}
	h := sha256.Sum256([]byte(tenantID + "/" + id))
	return "t-" + hex.EncodeToString(h[:12])
}

func builtinCategory(id string) string { return "builtin-" + id }

// listCategories returns the category names a tenant's lists add to its snapshots.
func listCategories(tenantID string, tp api.TenantPolicy) []string {
	var out []string
	for _, l := range tp.CustomLists {
		out = append(out, listCategory(tenantID, l.ID))
	}
	for _, id := range tp.BuiltinLists {
		out = append(out, builtinCategory(id))
	}
	return out
}

// validateLists checks the list fields of a tenant policy.
func validateLists(tp api.TenantPolicy) error {
	if len(tp.CustomLists)+len(tp.BuiltinLists) > maxListsTotal {
		return &policy.ValidationError{Field: "customLists", Msg: fmt.Sprintf("at most %d lists", maxListsTotal)}
	}
	seen := map[string]bool{}
	for i, l := range tp.CustomLists {
		f := fmt.Sprintf("customLists[%d]", i)
		if !listIDRe.MatchString(l.ID) || seen[l.ID] {
			return &policy.ValidationError{Field: f + ".id", Msg: "id must be unique and match [a-z0-9-]{1,32}"}
		}
		seen[l.ID] = true
		u, err := url.Parse(l.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(l.URL) > 2048 {
			return &policy.ValidationError{Field: f + ".url", Msg: "an https:// URL without credentials is required"}
		}
	}
	for i, id := range tp.BuiltinLists {
		if !slices.ContainsFunc(BuiltinLists, func(b BuiltinList) bool { return b.ID == id }) {
			return &policy.ValidationError{Field: fmt.Sprintf("builtinLists[%d]", i), Msg: fmt.Sprintf("unknown built-in list %q", id)}
		}
	}
	return nil
}

// listSource is one list to download.
type listSource struct{ name, title, url string }

type listEntry struct {
	cat     *categories.Category
	etag    string
	fetched time.Time
}

// listState holds the downloaded lists.
type listState struct {
	mu      sync.Mutex
	entries map[string]*listEntry // category name
	kick    chan struct{}
}

func newListState() *listState {
	return &listState{entries: map[string]*listEntry{}, kick: make(chan struct{}, 1)}
}

// kickLists asks the list loop to refresh now (after a policy change).
func (s *Server) kickLists() {
	select {
	case s.lists.kick <- struct{}{}:
	default:
	}
}

// wantedLists collects the lists every tenant policy names.
func (s *Server) wantedLists(ctx context.Context) ([]listSource, error) {
	tenants, err := s.cfg.Store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	byName := map[string]listSource{}
	for _, t := range tenants {
		tp, err := s.tenantPolicy(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range tp.CustomLists {
			n := listCategory(t.ID, l.ID)
			byName[n] = listSource{name: n, title: l.Title, url: l.URL}
		}
		for _, id := range tp.BuiltinLists {
			for _, b := range BuiltinLists {
				if b.ID == id {
					byName[builtinCategory(id)] = listSource{name: builtinCategory(id), title: b.Title, url: b.URL}
				}
			}
		}
	}
	out := make([]listSource, 0, len(byName))
	for _, l := range byName {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// listsLoop refreshes the lists at start, every listsRefresh and after policy changes.
func (s *Server) listsLoop(ctx context.Context) {
	t := time.NewTicker(listsRefresh)
	defer t.Stop()
	force := true
	for {
		if err := s.refreshLists(ctx, force); err != nil && ctx.Err() == nil {
			s.log.Warn("blocklist refresh failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			force = true
		case <-s.lists.kick:
			force = false // only lists not downloaded yet
		}
	}
}

// refreshLists downloads the wanted lists (all of them when force, else only new ones),
// drops lists no policy names any more and publishes the result.
func (s *Server) refreshLists(ctx context.Context, force bool) error {
	want, err := s.wantedLists(ctx)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	var errs []error
	for _, src := range want {
		keep[src.name] = true
		s.lists.mu.Lock()
		cur := s.lists.entries[src.name]
		s.lists.mu.Unlock()
		if cur != nil && !force {
			continue
		}
		etag := ""
		if cur != nil {
			etag = cur.etag
		}
		cat, newTag, err := s.downloadList(ctx, src, etag)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
			continue
		}
		if cat == nil { // not modified
			continue
		}
		s.lists.mu.Lock()
		s.lists.entries[src.name] = &listEntry{cat: cat, etag: newTag, fetched: s.now()}
		s.lists.mu.Unlock()
		s.log.Info("blocklist loaded", "list", src.name, "domains", cat.Len())
	}
	s.lists.mu.Lock()
	for n := range s.lists.entries {
		if !keep[n] {
			delete(s.lists.entries, n)
		}
	}
	s.lists.mu.Unlock()
	s.publishCategories()
	return errors.Join(errs...)
}

// downloadList fetches one list. It returns a nil category when the server answers 304.
func (s *Server) downloadList(ctx context.Context, src listSource, etag string) (*categories.Category, string, error) {
	ctx, cancel := context.WithTimeout(ctx, listsDownload)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "OpenSASE-ControlPlane")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.listClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, nil
	case http.StatusOK:
	default:
		return nil, "", fmt.Errorf("GET: %s", resp.Status)
	}
	cat, err := categories.ParseList(src.name, src.title, io.LimitReader(resp.Body, 1<<30))
	if err != nil {
		return nil, "", err
	}
	return cat, resp.Header.Get("ETag"), nil
}

// publishCategories makes the category data served to Edges the web category list plus the
// downloaded lists.
func (s *Server) publishCategories() {
	base := s.cats.Load()
	s.lists.mu.Lock()
	var extra []*categories.Category
	var names []string
	for n, e := range s.lists.entries {
		extra = append(extra, e.cat)
		names = append(names, n+"@"+e.fetched.UTC().Format(time.RFC3339))
	}
	s.lists.mu.Unlock()
	if base == nil && len(extra) == 0 {
		s.edgeCats.Store(nil)
		return
	}
	sort.Strings(names)
	h := sha256.Sum256([]byte(strings.Join(names, ",")))
	view := &catState{version: "l" + hex.EncodeToString(h[:4]), loadedAt: s.now()}
	var db *categories.DB
	if base != nil {
		db, view.version, view.loadedAt = base.db, base.version+"-"+view.version, base.loadedAt
	}
	view.db = db.With(extra...)
	s.edgeCats.Store(view)
}

// publicListClient returns an HTTP client that only connects to public addresses, so a
// tenant admin cannot make the Control Plane fetch from internal services (SSRF).
func publicListClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		a := ap.Addr().Unmap()
		if !a.IsGlobalUnicast() || a.IsPrivate() || isCGNAT(a) {
			return fmt.Errorf("blocklist URL resolves to a non-public address %s", a)
		}
		return nil
	}}
	tr := &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, Proxy: http.ProxyFromEnvironment}
	return &http.Client{Transport: tr, Timeout: listsDownload, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 5 {
			return errors.New("blocklist redirect must stay on https (at most 5)")
		}
		return nil
	}}
}

func isCGNAT(a netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// handleBlocklists lists the built-in blocklists (admin).
func (s *Server) handleBlocklists(w http.ResponseWriter, _ *http.Request) {
	out := make([]api.BuiltinBlocklist, 0, len(BuiltinLists))
	for _, b := range BuiltinLists {
		out = append(out, api.BuiltinBlocklist{ID: b.ID, Title: b.Title, URL: b.URL, Licence: b.Licence})
	}
	writeJSON(w, http.StatusOK, out)
}
