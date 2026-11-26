package controlplane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

// TestSCIM covers issue #68: user and group provisioning, deprovisioning revokes devices,
// group membership scopes tenant rules, and the token is per tenant.
func TestSCIM(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(2)
	var tok struct{ Token, BaseURL string }
	if err := json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/scim-token", nil, 201), &tok); err != nil || tok.Token == "" {
		t.Fatalf("token %v %v", tok, err)
	}
	cli := e.client(nil)
	scim := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, e.srv.URL+"/scim/v2/acme"+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok.Token)
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
		}
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return out
	}

	u := scim("POST", "/Users", map[string]any{"schemas": []string{scimUserSchema}, "userName": "erin@acme.example", "name": map[string]string{"givenName": "Erin", "familyName": "Lee"}, "externalId": "ext-1"}, 201)
	uid := u["id"].(string)
	scim("POST", "/Users", map[string]any{"userName": "erin@acme.example"}, 409)
	if l := scim("GET", `/Users?filter=userName%20eq%20%22erin@acme.example%22`, nil, 200); l["totalResults"].(float64) != 1 {
		t.Fatalf("filter %v", l)
	}
	g := scim("POST", "/Groups", map[string]any{"displayName": "sales", "members": []map[string]string{{"value": uid}}}, 201)
	gid := g["id"].(string)

	// A rule for the sales group reaches only its members' snapshots.
	p := examplePolicy()
	p.Rules = append(p.Rules, policy.Rule{ID: "sales-only", Priority: 50, Action: policy.ActionBlock, Groups: []string{"sales"},
		Match: policy.Match{CIDRs: []string{"192.0.2.0/24"}}})
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)
	devs := map[string]store.Device{}
	for _, uidx := range []string{uid, "u1"} {
		pk := key
		if uidx == uid {
			var k api.ProvisioningKey
			_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: uid, MaxUses: 1}, 201), &k)
			pk = k.Key
		}
		er, _ := e.enroll(pk)
		d, _ := e.s.cfg.Store.GetDevice(t.Context(), er.DeviceID)
		devs[uidx] = d
	}
	has := func(d store.Device) bool {
		t.Helper()
		rec, err := e.s.cfg.Store.LatestSnapshot(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		var env policy.Envelope
		if err := json.Unmarshal(rec.Envelope, &env); err != nil {
			t.Fatal(err)
		}
		snap, err := policy.Verify(&env, e.keys)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range snap.Firewall.Rules {
			if r.ID == "sales-only" {
				if r.Groups != nil {
					t.Fatal("groups left in the snapshot")
				}
				return true
			}
		}
		return false
	}
	if !has(devs[uid]) || has(devs["u1"]) {
		t.Fatal("group rule not scoped to its members")
	}
	// Removing the member recompiles the snapshot without the rule.
	scim("PATCH", "/Groups/"+gid, map[string]any{"schemas": []string{scimPatchSchema}, "Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + uid + `"]`}}}, 200)
	if has(devs[uid]) {
		t.Fatal("rule kept after the user left the group")
	}

	// Deactivation revokes the user's devices and blocks enrolment.
	scim("PATCH", "/Users/"+uid, map[string]any{"schemas": []string{scimPatchSchema}, "Operations": []map[string]any{{"op": "replace", "value": map[string]any{"active": false}}}}, 200)
	if d, _ := e.s.cfg.Store.GetDevice(t.Context(), devs[uid].ID); !d.Revoked {
		t.Fatal("device of a deactivated user not revoked")
	}
	var k api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: uid, MaxUses: 1}, 201), &k)
	resp, _ := e.do(e.client(nil), "POST", "/v1/enroll", api.EnrollRequest{ProvisioningKey: k.Key, DeviceName: "x", Platform: "linux", CSRPEM: newCSR(t, mustKey(t))}, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("deactivated user enrolled")
	}
	scim("DELETE", "/Users/"+uid, nil, 204)
	scim("GET", "/Users/"+uid, nil, 404)

	// Wrong token.
	req, _ := http.NewRequest("GET", e.srv.URL+"/scim/v2/acme/Users", nil)
	req.Header.Set("Authorization", "Bearer osscim_wrong")
	if r, err := cli.Do(req); err != nil || r.StatusCode != 401 {
		t.Fatalf("wrong token: %v %v", r, err)
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
