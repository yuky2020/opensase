package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
)

// TestCustomLists covers issue #63: a tenant list is downloaded, served to Edges as a
// category and added to the tenant's snapshots; invalid lists are refused.
func TestCustomLists(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("0.0.0.0 bad.example\nworse.example\n"))
	}))
	defer src.Close()
	e := newEnvCfg(t, func(c *Config) { c.ListClient = src.Client() })
	e.setupTenant(1)
	p := examplePolicy()
	p.CustomLists = []api.CustomList{{ID: "mine", Title: "Mine", URL: "https://list.example/hosts"}}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)
	// The policy names https://list.example; fetch from the local test server instead.
	cat, _, err := e.s.downloadList(context.Background(), listSource{name: listCategory("acme", "mine"), url: src.URL}, "")
	if err != nil {
		t.Fatal(err)
	}
	e.s.lists.entries[cat.Name] = &listEntry{cat: cat, fetched: e.s.now()}
	e.s.publishCategories()
	db := e.s.edgeCats.Load().db
	if _, ok := db.Lookup("www.bad.example", []string{"t-acme-mine"}); !ok {
		t.Fatal("list not served")
	}
	tp, _ := e.s.tenantPolicy(context.Background(), "acme")
	if got := listCategories("acme", tp); !slices.Equal(got, []string{"t-acme-mine"}) {
		t.Fatalf("list categories %v", got)
	}
	for name, bad := range map[string]api.CustomList{
		"http":       {ID: "a", URL: "http://list.example/x"},
		"credential": {ID: "a", URL: "https://u:p@list.example/x"},
		"bad id":     {ID: "A B", URL: "https://list.example/x"},
	} {
		q := examplePolicy()
		q.CustomLists = []api.CustomList{bad}
		if body := string(e.adminDo("PUT", "/v1/admin/tenants/acme/policy", q, 400)); !strings.Contains(body, "customLists") {
			t.Errorf("%s: %s", name, body)
		}
	}
	q := examplePolicy()
	q.BuiltinLists = []string{"nope"}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", q, 400)
	if !categories.ValidName(listCategory("a-very-long-tenant-name-that-goes-on-and-on", "and-a-long-list-id-too-x")) {
		t.Fatal("long names must still give a valid category")
	}
}

// TestPublicListClient: the default client refuses non-public addresses (SSRF).
func TestPublicListClient(t *testing.T) {
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("a.example\n")) }))
	defer src.Close()
	if _, err := publicListClient().Get(src.URL); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("loopback fetch: %v", err)
	}
}
