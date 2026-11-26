package controlplane

import (
	"encoding/json"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestPolicyTest(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	er, _ := e.enroll(key)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "other", Name: "Other"}, 201)
	before := len(e.flows())

	cases := []struct {
		name   string
		flow   policy.Flow
		action policy.Action
		ruleID string
	}{
		{"tenant block", policy.Flow{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: 25}, policy.ActionBlock, "no-smtp"},
		{"default allow", policy.Flow{Protocol: "udp", DstIP: "8.8.8.8", DstPort: 53}, policy.ActionAllow, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var res api.PolicyTestResult
			body := e.adminDo("POST", "/v1/admin/tenants/acme/policy-test", api.PolicyTestRequest{DeviceID: er.DeviceID, Flow: c.flow}, 200)
			if err := json.Unmarshal(body, &res); err != nil {
				t.Fatal(err)
			}
			if res.Decision.Action != c.action || res.Decision.RuleID != c.ruleID || res.SnapshotVersion == 0 {
				t.Fatalf("got %+v", res)
			}
		})
	}

	// A device of another tenant, or an unknown one, is not found.
	e.adminDo("POST", "/v1/admin/tenants/other/policy-test", api.PolicyTestRequest{DeviceID: er.DeviceID}, 404)
	e.adminDo("POST", "/v1/admin/tenants/acme/policy-test", api.PolicyTestRequest{DeviceID: "nope"}, 404)

	if got := len(e.flows()); got != before {
		t.Fatalf("policy test recorded flows: %d -> %d", before, got)
	}
}

func TestRoleAllowsPolicyTest(t *testing.T) {
	for _, role := range []string{api.TenantRoleAdmin, api.TenantRolePolicyEditor, api.TenantRoleViewer} {
		if !roleAllows(role, "POST", "/v1/admin/tenants/acme/policy-test", "acme") {
			t.Errorf("%s cannot run a policy test", role)
		}
	}
	if roleAllows(api.TenantRoleViewer, "POST", "/v1/admin/tenants/acme/users", "acme") {
		t.Error("viewer may create users")
	}
}
