package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Web categories (ADR-0022). The Control Plane loads a public category list (UT1 by default),
// keeps a cached copy of the archive, refreshes it, and serves to each Edge only the
// categories it asks for. Devices never receive the list: their snapshots name the
// categories the tenant blocks.

// Category list defaults and bounds.
const (
	DefaultCategoriesRefresh = 24 * time.Hour
	maxCategoriesDownload    = 256 << 20
	categoriesDownloadTime   = 15 * time.Minute
)

// catState is one loaded list.
type catState struct {
	db       *categories.DB
	version  string // short SHA-256 of the archive
	loadedAt time.Time
}

func (s *Server) categoryState() *catState { return s.cats.Load() }

// loadCategoryFile parses the archive at path and makes it current.
func (s *Server) loadCategoryFile(path string) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen cache path
	if err != nil {
		return err
	}
	db, err := categories.ParseUT1(bytes.NewReader(b))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	s.cats.Store(&catState{db: db, version: hex.EncodeToString(sum[:6]), loadedAt: s.now()})
	s.publishCategories()
	s.log.Info("web categories loaded", "categories", len(db.Names()), "version", hex.EncodeToString(sum[:6]), "file", path)
	return nil
}

// categoriesLoop loads the cached archive, then downloads updates from CategoriesURL at
// CategoriesRefresh. It returns when ctx is done.
func (s *Server) categoriesLoop(ctx context.Context) {
	file := s.cfg.CategoriesFile
	if file == "" {
		return
	}
	if err := s.loadCategoryFile(file); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("cached category list not loaded", "file", file, "err", err)
	}
	if s.cfg.CategoriesURL == "" {
		return
	}
	refresh := s.cfg.CategoriesRefresh
	if refresh <= 0 {
		refresh = DefaultCategoriesRefresh
	}
	for {
		changed, err := s.downloadCategories(ctx, file)
		switch {
		case err != nil:
			s.log.Warn("category list download failed; keeping the current one", "url", s.cfg.CategoriesURL, "err", err)
		case changed:
			if err := s.loadCategoryFile(file); err != nil {
				s.log.Error("downloaded category list not loaded", "err", err)
			}
		}
		wait := refresh
		if err != nil {
			wait = min(refresh, time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// downloadCategories fetches the archive if it changed since the cached copy, and replaces
// the cache atomically. It reports whether the file changed.
func (s *Server) downloadCategories(ctx context.Context, file string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, categoriesDownloadTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.CategoriesURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "OpenSASE-ControlPlane")
	if st, err := os.Stat(file); err == nil {
		req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	default:
		return false, fmt.Errorf("GET %s: %s", s.cfg.CategoriesURL, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".categories-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxCategoriesDownload+1))
	if err == nil && n > maxCategoriesDownload {
		err = errors.New("category archive larger than 256 MiB")
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	// Validate before replacing the working copy.
	f, err := os.Open(tmp.Name())
	if err != nil {
		return false, err
	}
	_, perr := categories.ParseUT1(f)
	_ = f.Close()
	if perr != nil {
		return false, fmt.Errorf("downloaded archive: %w", perr)
	}
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		_ = os.Chtimes(tmp.Name(), lm, lm)
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		return false, err
	}
	return true, nil
}

// handleCategories lists the loaded categories (admin).
func (s *Server) handleCategories(w http.ResponseWriter, _ *http.Request) {
	out := api.CategoryCatalog{Source: categories.SourceName, Licence: categories.SourceLicence, URL: categories.SourceURL, Categories: []api.WebCategory{}}
	if st := s.categoryState(); st != nil {
		out.Version, out.LoadedAt = st.version, st.loadedAt
		for _, n := range st.db.Names() {
			c, _ := st.db.Get(n)
			out.Categories = append(out.Categories, api.WebCategory{Name: c.Name, Title: c.Title, Description: c.Description, Type: c.Type, Domains: c.Len(), URLs: c.URLs(), Aliases: c.Aliases})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleEdgeCategories sends an Edge the categories it asks for, in the pkg/categories wire
// format.
func (s *Server) handleEdgeCategories(w http.ResponseWriter, r *http.Request) {
	st := s.edgeCats.Load()
	if st == nil {
		writeErr(w, http.StatusServiceUnavailable, "no category list loaded")
		return
	}
	var names []string
	for _, n := range strings.Split(r.URL.Query().Get("names"), ",") {
		if n = strings.TrimSpace(n); categories.ValidName(n) && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 || len(names) > 256 {
		writeErr(w, http.StatusBadRequest, "names: 1..256 category names")
		return
	}
	slices.Sort(names)
	etag := `"` + st.version + "-" + hex.EncodeToString(func() []byte { h := sha256.Sum256([]byte(strings.Join(names, ","))); return h[:6] }()) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	setDeadline(w, 2*time.Minute) // up to tens of MB
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := st.db.Encode(w, names); err != nil {
		s.log.WarnContext(r.Context(), "send categories", "err", err)
	}
}

// validateCategories checks a tenant's category names against the loaded list, when there is
// one: unknown names and allow lists ("white") are refused.
func (s *Server) validateCategories(names []string) error {
	st := s.categoryState()
	for i, n := range names {
		field := fmt.Sprintf("categories[%d]", i)
		if !categories.ValidName(n) {
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("invalid category name %q", n)}
		}
		if st == nil {
			continue
		}
		c, ok := st.db.Get(n)
		switch {
		case !ok:
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("unknown category %q", n)}
		case c.Type == "white":
			return &policy.ValidationError{Field: field, Msg: fmt.Sprintf("%q is an allow list, not a category to block", n)}
		}
	}
	return nil
}
