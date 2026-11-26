package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/dlp"
)

// TestDLPDatasets covers ADR-0029 on the Control Plane: datasets are hashed and the content
// discarded, listed without hashes, served to Edges of the tenant only, and deleted.
func TestDLPDatasets(t *testing.T) {
	e := newEnvCfg(t, func(c *Config) {
		c.Edges = append(c.Edges, api.EdgeInfo{ID: "priv-beta", SessionURL: "https://pb:8443"})
	})
	e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "priv-beta", TenantID: "beta"}, 201)

	var d api.DLPDataset
	_ = json.Unmarshal(e.adminDo("PUT", "/v1/admin/tenants/acme/dlp-datasets/customers", api.DLPDatasetRequest{Kind: "values", Values: []string{"Mario Rossi", "ACCT-1234", "Mario Rossi", "too many words in this value"}}, 200), &d)
	if d.Entries != 2 || d.Kind != "values" {
		t.Fatalf("dataset %+v", d)
	}
	_ = json.Unmarshal(e.adminDo("PUT", "/v1/admin/tenants/acme/dlp-datasets/accounts", api.DLPDatasetRequest{Kind: "records", Records: [][]string{{"Mario Rossi", "ACCT-1234"}, {"Luigi Verdi", "ACCT-5678"}, {"alone"}}}, 200), &d)
	if d.Entries != 6 || d.Kind != "records" { // 4 field hashes + 2 pair hashes; one-field rows add nothing
		t.Fatalf("records dataset %+v", d)
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/dlp-datasets/mixed", api.DLPDatasetRequest{Kind: "records", Values: []string{"x"}, Records: [][]string{{"a", "b"}}}, 400)
	doc := []byte("Project Falcon will acquire Example Industries for 42 euro per share before the end of March.")
	_ = json.Unmarshal(e.adminDo("PUT", "/v1/admin/tenants/acme/dlp-datasets/falcon", api.DLPDatasetRequest{Kind: "document", Documents: [][]byte{doc}}, 200), &d)
	if d.Entries < 5 || d.Kind != "document" {
		t.Fatalf("document dataset %+v", d)
	}
	for _, bad := range []api.DLPDatasetRequest{{Kind: "x"}, {Kind: "values"}, {Kind: "values", Documents: [][]byte{doc}}} {
		e.adminDo("PUT", "/v1/admin/tenants/acme/dlp-datasets/bad", bad, 400)
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/dlp-datasets/Bad Name", api.DLPDatasetRequest{Kind: "values", Values: []string{"x"}}, 400)

	var list []api.DLPDataset
	raw := e.adminDo("GET", "/v1/admin/tenants/acme/dlp-datasets", nil, 200)
	_ = json.Unmarshal(raw, &list)
	if len(list) != 3 || bytes.Contains(raw, []byte("Mario")) {
		t.Fatalf("list %s", raw)
	}

	ec := e.edgeCert()
	edge := e.client(&ec)
	resp, b := e.do(edge, "GET", "/v1/edge/dlp-datasets?tenant=acme&names=customers,nope", nil, nil)
	var eds api.EdgeDatasets
	_ = json.Unmarshal(b, &eds)
	if resp.StatusCode != 200 || len(eds.Datasets) != 1 || len(eds.Datasets[0].Key) != 32 || len(eds.Datasets[0].Hashes) != 16 {
		t.Fatalf("edge datasets %d %+v", resp.StatusCode, eds)
	}
	if bytes.Contains(b, []byte("Mario")) || bytes.Contains(b, []byte("ACCT")) {
		t.Fatal("dataset values sent to the edge")
	}
	// The hashes match the values under the dataset key.
	hs := dlp.ValueHashes(eds.Datasets[0].Key, []string{"mario rossi"})
	ds := &dlp.Dataset{Kind: "values", Key: eds.Datasets[0].Key}
	for i := 0; i < len(eds.Datasets[0].Hashes); i += 8 {
		ds.Hashes = append(ds.Hashes, uint64(eds.Datasets[0].Hashes[i])<<56|uint64(eds.Datasets[0].Hashes[i+1])<<48|uint64(eds.Datasets[0].Hashes[i+2])<<40|uint64(eds.Datasets[0].Hashes[i+3])<<32|uint64(eds.Datasets[0].Hashes[i+4])<<24|uint64(eds.Datasets[0].Hashes[i+5])<<16|uint64(eds.Datasets[0].Hashes[i+6])<<8|uint64(eds.Datasets[0].Hashes[i+7]))
	}
	if ds.Count([]byte("customer MARIO ROSSI")) != 1 || len(hs) != 1 {
		t.Fatal("hashes do not match the value")
	}
	pb := e.edgeClientID("priv-beta")
	if resp, _ := e.do(pb, "GET", "/v1/edge/dlp-datasets?tenant=acme&names=customers", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("private edge of beta: %d", resp.StatusCode)
	}
	e.adminDo("DELETE", "/v1/admin/tenants/acme/dlp-datasets/customers", nil, 204)
	e.adminDo("DELETE", "/v1/admin/tenants/acme/dlp-datasets/customers", nil, 404)
}
