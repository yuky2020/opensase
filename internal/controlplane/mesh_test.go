package controlplane

import (
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

func TestMeshInboundGrants(t *testing.T) {
	m := api.MeshPolicy{Rules: []api.MeshRule{
		{ID: "ssh", From: api.MeshSelector{Users: []string{"admin"}}, To: api.MeshSelector{All: true}, Protocol: "tcp", Ports: []policy.PortRange{{From: 22}}},
		{ID: "nas", From: api.MeshSelector{All: true}, To: api.MeshSelector{Devices: []string{"nas-1"}}},
	}}
	if g := meshInbound(m, store.Device{ID: "laptop", UserID: "alice"}); len(g) != 1 || g[0].RuleID != "ssh" {
		t.Fatalf("laptop grants %+v", g)
	}
	if g := meshInbound(m, store.Device{ID: "nas-1", UserID: "it"}); len(g) != 2 {
		t.Fatalf("nas grants %+v", g)
	}
	e := newEnv(t)
	e.setupTenant(1)
	for name, bad := range map[string]api.MeshPolicy{
		"no id":    {Rules: []api.MeshRule{{From: api.MeshSelector{All: true}, To: api.MeshSelector{All: true}}}},
		"empty to": {Rules: []api.MeshRule{{ID: "a", From: api.MeshSelector{All: true}}}},
		"protocol": {Rules: []api.MeshRule{{ID: "a", From: api.MeshSelector{All: true}, To: api.MeshSelector{All: true}, Protocol: "sctp"}}},
	} {
		p := examplePolicy()
		p.Mesh = bad
		if body := e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 400); len(body) == 0 {
			t.Errorf("%s: no error body", name)
		}
	}
	p := examplePolicy()
	p.Mesh = m
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)
}
