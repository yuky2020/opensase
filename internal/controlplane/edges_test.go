package controlplane

import (
	"encoding/json"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
)

// TestDeviceEdges covers issue #71: a device gets the Edge list ordered by priority, so
// Edges added after enrolment reach it.
func TestDeviceEdges(t *testing.T) {
	e := newEnvCfg(t, func(c *Config) {
		c.Edges = []api.EdgeInfo{
			{ID: "edge-1", SessionURL: "https://edge-1:8443", WGEndpoint: "edge-1:51820", Priority: 2},
			{ID: "edge-2", SessionURL: "https://edge-2:8443", WGEndpoint: "edge-2:51820"},
			{ID: "edge-3", SessionURL: "https://edge-3:8443", WGEndpoint: "edge-3:51820", Priority: 2},
		}
	})
	key := e.setupTenant(1)
	_, cert := e.enroll(key)
	resp, body := e.do(e.client(&cert), "GET", "/v1/edges", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("edges: %d %s", resp.StatusCode, body)
	}
	var de api.DeviceEdges
	if err := json.Unmarshal(body, &de); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, ed := range de.Edges {
		ids = append(ids, ed.ID)
	}
	if len(ids) != 3 || ids[0] != "edge-2" || ids[1] != "edge-1" || ids[2] != "edge-3" {
		t.Fatalf("order %v", ids)
	}
	if resp, _ := e.do(e.client(nil), "GET", "/v1/edges", nil, nil); resp.StatusCode == 200 {
		t.Fatal("edges without a device certificate")
	}
}
