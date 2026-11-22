package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/policy"
)

func testCategoryArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"blacklists/gambling/domains":      "casino.example\n",
		"blacklists/liste_blanche/domains": "school.example\n",
		"blacklists/global_usage":          "NAME:\tgambling\nDEFAULT_TYPE: black\nNAME EN: Gambling\n\nNAME:\tliste_blanche\nDEFAULT_TYPE: white\n",
	} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return b.Bytes()
}

// TestWebCategories checks ADR-0022 on the Control Plane: the list is loaded from its cache
// file, policies are validated against it, and Edges get only the categories they ask for.
func TestWebCategories(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	ec := e.edgeCert()
	edge := e.client(&ec)
	tp := examplePolicy()
	tp.Categories = []string{"gambling"}
	// Without a list, names are only checked for syntax.
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)
	if resp, _ := e.do(edge, "GET", "/v1/edge/categories?names=gambling", nil, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no list: %d", resp.StatusCode)
	}

	file := filepath.Join(t.TempDir(), "categories.tar.gz")
	if err := os.WriteFile(file, testCategoryArchive(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.s.loadCategoryFile(file); err != nil {
		t.Fatal(err)
	}
	var cat api.CategoryCatalog
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/categories", nil, 200), &cat)
	if cat.Version == "" || len(cat.Categories) != 2 || cat.Categories[0].Name != "gambling" || cat.Categories[0].Domains != 1 || cat.Licence != "CC BY-SA 4.0" {
		t.Fatalf("catalog %+v", cat)
	}
	for _, bad := range [][]string{{"nope"}, {"liste_blanche"}, {"Bad Name"}} {
		tp.Categories = bad
		if b := e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 400); !strings.Contains(string(b), "categories[0]") {
			t.Errorf("%v: %s", bad, b)
		}
	}

	resp, body := e.do(edge, "GET", "/v1/edge/categories?names=gambling,nope", nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") == "" {
		t.Fatalf("edge categories: %d", resp.StatusCode)
	}
	db, err := categories.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := db.Lookup("www.casino.example", []string{"gambling"}); !ok || n != "gambling" {
		t.Fatal("decoded list does not match")
	}
	if r2, _ := e.do(edge, "GET", "/v1/edge/categories?names=gambling,nope", nil, map[string]string{"If-None-Match": resp.Header.Get("ETag")}); r2.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", r2.StatusCode)
	}
	if r3, _ := e.do(edge, "GET", "/v1/edge/categories", nil, nil); r3.StatusCode != http.StatusBadRequest {
		t.Fatalf("no names: %d", r3.StatusCode)
	}
	_, dcert := e.enroll(key)
	if r4, _ := e.do(e.client(&dcert), "GET", "/v1/edge/categories?names=gambling", nil, nil); r4.StatusCode != http.StatusForbidden {
		t.Fatalf("device cert: %d", r4.StatusCode)
	}
}

func TestCategoriesDownload(t *testing.T) {
	archive := testCategoryArchive(t)
	mod := time.Date(2026, 11, 21, 19, 0, 0, 0, time.UTC)
	gets := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets++
		http.ServeContent(w, r, "blacklists.tar.gz", mod, bytes.NewReader(archive))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "categories.tar.gz")
	s := &Server{cfg: Config{CategoriesURL: srv.URL, CategoriesFile: file}}
	if changed, err := s.downloadCategories(context.Background(), file); err != nil || !changed {
		t.Fatalf("first download: %v %v", changed, err)
	}
	if changed, err := s.downloadCategories(context.Background(), file); err != nil || changed {
		t.Fatalf("second download (304): %v %v", changed, err)
	}
	// A broken archive never replaces the good one.
	archive = []byte("not a tarball")
	mod = mod.Add(time.Hour)
	if _, err := s.downloadCategories(context.Background(), file); err == nil {
		t.Fatal("broken archive accepted")
	}
	if b, _ := os.ReadFile(file); bytes.Equal(b, archive) {
		t.Fatal("broken archive replaced the cache")
	}
	if gets != 3 {
		t.Fatalf("gets %d", gets)
	}
}

// TestFlowCategories covers issue #27: flow records are tagged with their web categories by
// the Control Plane, and categories sent by the reporter are ignored.
func TestFlowCategories(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	file := filepath.Join(t.TempDir(), "categories.tar.gz")
	if err := os.WriteFile(file, testCategoryArchive(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.s.loadCategoryFile(file); err != nil {
		t.Fatal(err)
	}
	_, cert := e.enroll(key)
	dev := e.client(&cert)
	now := time.Now()
	recs := api.FlowBatch{Records: []api.FlowRecord{
		{Start: now, Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.9", DstPort: 443, Domain: "www.casino.example"}, Categories: []string{"spoofed"}},
		{Start: now, Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.9", DstPort: 443, Domain: "school.example"}},
		{Start: now, Flow: policy.Flow{Protocol: "tcp", DstIP: "203.0.113.9", DstPort: 443, Domain: "other.example"}, Categories: []string{"gambling"}},
	}}
	if resp, b := e.do(dev, "POST", "/v1/flows", recs, nil); resp.StatusCode != 202 {
		t.Fatalf("flows %d %s", resp.StatusCode, b)
	}
	got := map[string][]string{}
	for _, r := range e.flows() {
		got[r.Flow.Domain] = r.Categories
	}
	if !slices.Equal(got["www.casino.example"], []string{"gambling"}) {
		t.Errorf("casino: %v", got["www.casino.example"])
	}
	if len(got["school.example"]) != 0 { // allow lists are not categories of a visit
		t.Errorf("school: %v", got["school.example"])
	}
	if len(got["other.example"]) != 0 {
		t.Errorf("spoofed categories kept: %v", got["other.example"])
	}
}
