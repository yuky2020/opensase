package controlplane

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
)

func TestDeviceRoutesHandler(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1) // tenant acme
	erAcme, _ := e.enroll(key)
	d1 := erAcme.DeviceID

	// Create a second tenant and device
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/beta/users", api.AdminUser{ID: "u-beta", Email: "u@beta"}, 201)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/beta/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u-beta", MaxUses: 1}, 201), &pk)
	erBeta, _ := e.enroll(pk.Key)
	d2 := erBeta.DeviceID

	// Mint tenant admin tokens for role testing
	mint := func(tenant, role string) string {
		var c api.AdminTokenCreated
		_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/"+tenant+"/admin-tokens", api.AdminTokenRequest{Name: role, Role: role}, 201), &c)
		return c.Token
	}
	viewer := mint("acme", api.TenantRoleViewer)
	editor := mint("acme", api.TenantRolePolicyEditor)
	admin := mint("acme", api.TenantRoleAdmin)
	betaAdmin := mint("beta", api.TenantRoleAdmin)

	as := func(tok, method, path string, body any) (int, []byte) {
		resp, b := e.do(e.admin, method, path, body, map[string]string{"Authorization": "Bearer " + tok})
		return resp.StatusCode, b
	}

	routes1 := api.DeviceRoutes{CIDRs: []string{"10.30.0.0/24"}}

	// 1. Role enforcement:
	// Viewer gets 403 on PUT
	if code, _ := as(viewer, "PUT", "/v1/admin/tenants/acme/devices/"+d1+"/routes", routes1); code != http.StatusForbidden {
		t.Fatalf("viewer PUT: got %d, want 403", code)
	}
	// Policy editor gets 403 on PUT
	if code, _ := as(editor, "PUT", "/v1/admin/tenants/acme/devices/"+d1+"/routes", routes1); code != http.StatusForbidden {
		t.Fatalf("policy-editor PUT: got %d, want 403", code)
	}
	// Admin gets 200 on PUT
	if code, b := as(admin, "PUT", "/v1/admin/tenants/acme/devices/"+d1+"/routes", routes1); code != http.StatusOK {
		t.Fatalf("admin PUT: got %d want 200: %s", code, b)
	}
	// Viewer gets 200 on GET
	if code, b := as(viewer, "GET", "/v1/admin/tenants/acme/devices/"+d1+"/routes", nil); code != http.StatusOK {
		t.Fatalf("viewer GET: got %d want 200: %s", code, b)
	} else {
		var got api.DeviceRoutes
		_ = json.Unmarshal(b, &got)
		if !reflect.DeepEqual(got.CIDRs, routes1.CIDRs) {
			t.Fatalf("viewer GET routes: got %v, want %v", got.CIDRs, routes1.CIDRs)
		}
	}

	// 2. 404 for other tenant and nonexistent device:
	// Beta admin cannot access acme's device routes (404)
	if code, _ := as(betaAdmin, "GET", "/v1/admin/tenants/acme/devices/"+d1+"/routes", nil); code != http.StatusNotFound {
		t.Fatalf("beta admin GET acme device: got %d, want 404", code)
	}
	if code, _ := as(betaAdmin, "PUT", "/v1/admin/tenants/acme/devices/"+d1+"/routes", routes1); code != http.StatusNotFound {
		t.Fatalf("beta admin PUT acme device: got %d, want 404", code)
	}
	// Acme admin cannot access beta's device through acme URL (404)
	if code, _ := as(admin, "GET", "/v1/admin/tenants/acme/devices/"+d2+"/routes", nil); code != http.StatusNotFound {
		t.Fatalf("acme admin GET beta device under acme: got %d, want 404", code)
	}
	// Nonexistent device (404)
	if code, _ := as(admin, "GET", "/v1/admin/tenants/acme/devices/ghost/routes", nil); code != http.StatusNotFound {
		t.Fatalf("GET ghost device: got %d, want 404", code)
	}
	if code, _ := as(admin, "PUT", "/v1/admin/tenants/acme/devices/ghost/routes", routes1); code != http.StatusNotFound {
		t.Fatalf("PUT ghost device: got %d, want 404", code)
	}

	// 3. 409 on overlap:
	// Beta admin attempts to authorize overlapping CIDR 10.30.0.0/24 or sub-prefix on d2
	overlapReq := api.DeviceRoutes{CIDRs: []string{"10.30.0.128/25"}}
	if code, b := as(betaAdmin, "PUT", "/v1/admin/tenants/beta/devices/"+d2+"/routes", overlapReq); code != http.StatusConflict {
		t.Fatalf("PUT overlapping CIDR: got %d want 409: %s", code, b)
	}

	// Non-overlapping route succeeds on d2
	validBetaRoutes := api.DeviceRoutes{CIDRs: []string{"10.40.0.0/24"}}
	if code, b := as(betaAdmin, "PUT", "/v1/admin/tenants/beta/devices/"+d2+"/routes", validBetaRoutes); code != http.StatusOK {
		t.Fatalf("PUT valid beta routes: got %d want 200: %s", code, b)
	}

	// 4. Peer feed contains routes:
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	edgeCli := e.edgeClientID("edge-1")
	resp, body := e.do(edgeCli, "GET", "/v1/edge/peers", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edge/peers: status %d %s", resp.StatusCode, body)
	}
	var peers api.EdgePeers
	if err := json.Unmarshal(body, &peers); err != nil {
		t.Fatalf("unmarshal edge/peers: %v", err)
	}

	foundD1, foundD2 := false, false
	for _, dev := range peers.Devices {
		if dev.DeviceID == d1 {
			foundD1 = true
			if !reflect.DeepEqual(dev.Routes, routes1.CIDRs) {
				t.Errorf("d1 routes in feed = %v, want %v", dev.Routes, routes1.CIDRs)
			}
		}
		if dev.DeviceID == d2 {
			foundD2 = true
			if !reflect.DeepEqual(dev.Routes, validBetaRoutes.CIDRs) {
				t.Errorf("d2 routes in feed = %v, want %v", dev.Routes, validBetaRoutes.CIDRs)
			}
		}
	}
	if !foundD1 || !foundD2 {
		t.Fatalf("devices not in peer feed: d1=%v, d2=%v", foundD1, foundD2)
	}

	// 5. Auditing: check that PUT routes writes were audited
	var auditEntries []api.AuditEntry
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/audit?limit=50", nil, 200), &auditEntries)
	foundAudit := false
	for _, a := range auditEntries {
		if a.Method == "PUT" && a.Path == "/v1/admin/tenants/acme/devices/"+d1+"/routes" && a.Status == 200 {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Error("PUT device routes write not recorded in tenant audit log")
	}
}
