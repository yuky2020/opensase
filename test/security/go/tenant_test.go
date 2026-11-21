package securitytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

func (f *fixture) flows(tenant string) (string, error) {
	r := f.admin("GET", "/tenants/"+tenant+"/flows?limit=2000", nil)
	if r.code != 200 {
		return "", fmt.Errorf("list flows: %s", r)
	}
	return string(r.body), nil
}

// waitFlows polls tenant's flows until has(body) or the timeout.
func (f *fixture) waitFlows(tenant string, d time.Duration, has func(string) bool) (string, error) {
	deadline := time.Now().Add(d)
	for {
		b, err := f.flows(tenant)
		if err != nil || has(b) || time.Now().After(deadline) {
			return b, err
		}
		time.Sleep(time.Second)
	}
}

func decideBody(domain string) string {
	return fmt.Sprintf(`{"flow":{"protocol":"tcp","dstIp":"198.51.100.7","dstPort":443,"domain":%q}}`, domain)
}

func TestTenantIsolation(t *testing.T) {
	f := stack(t)
	bMarks := []string{f.tB, f.appB, "-b-" + f.run}

	// The signed snapshot a device downloads carries its own tenant only.
	check(t, "SEC-TEN-001", "device snapshot holds only its own tenant's policy and apps", "", func(t *testing.T) error {
		r := do(f.cp(f.devA1.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil)
		env, err := decode[policy.Envelope](r)
		if err != nil {
			return err
		}
		var s policy.Snapshot
		if err := json.Unmarshal(env.Payload, &s); err != nil {
			return err
		}
		if s.TenantID != f.tA || s.DeviceID != f.devA1.id {
			return fmt.Errorf("snapshot for tenant %q device %q", s.TenantID, s.DeviceID)
		}
		if !strings.Contains(string(env.Payload), f.appA) {
			return errors.New("control: own private app missing from snapshot")
		}
		for _, m := range bMarks {
			if strings.Contains(string(env.Payload), m) {
				return fmt.Errorf("snapshot of tenant A contains tenant B data %q", m)
			}
		}
		return nil
	})

	// Cloud decisions use the caller's tenant data only.
	check(t, "SEC-TEN-002", "POST /v1/decide uses only the caller tenant's cloud data", "", func(t *testing.T) error {
		dA, err := decode[api.DecideResponse](do(f.cp(f.devA1.cert), "POST", f.cpURL+"/v1/decide", decideBody(marker(f.run, "a", "decideblock")), nil))
		if err != nil {
			return err
		}
		if dA.Decision.Action != policy.ActionBlock {
			return fmt.Errorf("control: own decide blocklist not applied: %+v", dA.Decision)
		}
		dB, err := decode[api.DecideResponse](do(f.cp(f.devA1.cert), "POST", f.cpURL+"/v1/decide", decideBody(marker(f.run, "b", "decideblock")), nil))
		if err != nil {
			return err
		}
		if dB.Decision.Action != policy.ActionAllow {
			return fmt.Errorf("tenant B's cloud blocklist applied to a tenant A device: %+v", dB.Decision)
		}
		return nil
	})

	// A device reporting flows "for" a device of another tenant: they land in its own
	// tenant with its own device ID, never in tenant B.
	check(t, "SEC-TEN-003", "device flow records cannot be written into another tenant/device", "", func(t *testing.T) error {
		m := "flowspoof-" + f.run + ".sectest.test"
		now := time.Now().UTC()
		b := api.FlowBatch{Records: []api.FlowRecord{{Start: now, Flow: policy.Flow{Protocol: "tcp", DstIP: "192.0.2.9", DstPort: 443, Domain: m}, Where: "edge", DeviceID: f.devB1.id, Decision: policy.Decision{Action: policy.ActionAllow}}}}
		if err := want(do(f.cp(f.devA1.cert), "POST", f.cpURL+"/v1/flows", b, nil), "post flows", http.StatusAccepted); err != nil {
			return err
		}
		fa, err := f.waitFlows(f.tA, 5*time.Second, func(s string) bool { return strings.Contains(s, m) })
		if err != nil {
			return err
		}
		fb, err := f.flows(f.tB)
		if err != nil {
			return err
		}
		if strings.Contains(fb, m) {
			return errors.New("tenant A device wrote a flow record into tenant B")
		}
		batch, _ := decode[api.FlowBatch](resp{code: 200, body: []byte(fa)})
		for _, rec := range batch.Records {
			if rec.Flow.Domain == m && (rec.DeviceID != f.devA1.id || rec.Where != "device") {
				return fmt.Errorf("record stored with deviceId %q where %q", rec.DeviceID, rec.Where)
			}
		}
		if !strings.Contains(fa, m) {
			return errors.New("control: record not stored for the reporting device")
		}
		return nil
	})

	// User rules are per (tenant, user) from the certificate.
	check(t, "SEC-TEN-004", "user rules of tenant A invisible to tenant B devices", "", func(t *testing.T) error {
		m := "userrule-" + f.run
		ur := api.UserRules{Rules: []policy.Rule{{ID: m, Priority: 100, Action: policy.ActionBlock, Match: policy.Match{CIDRs: []string{"192.0.2.0/24"}}}}}
		if err := want(do(f.cp(f.devA1.cert), "PUT", f.cpURL+"/v1/self/rules", ur, nil), "put user rules", 200); err != nil {
			return err
		}
		ra := do(f.cp(f.devA2.cert), "GET", f.cpURL+"/v1/self/rules", nil, nil)
		if !strings.Contains(string(ra.body), m) {
			return fmt.Errorf("control: same user's other device does not see the rule: %s", ra)
		}
		rb := do(f.cp(f.devB1.cert), "GET", f.cpURL+"/v1/self/rules", nil, nil)
		if rb.code != 200 || strings.Contains(string(rb.body), m) {
			return fmt.Errorf("tenant B device: %s", rb)
		}
		return nil
	})

	// A connector's config lists its own tenant's apps only.
	check(t, "SEC-TEN-005", "connector config holds only its tenant's private apps", "", func(t *testing.T) error {
		ca, err := decode[api.ConnectorConfig](do(f.cp(f.connA.cert), "GET", f.cpURL+"/v1/connector/config", nil, nil))
		if err != nil {
			return err
		}
		j, _ := json.Marshal(ca)
		if !strings.Contains(string(j), f.appA) {
			return errors.New("control: own app missing")
		}
		for _, m := range bMarks {
			if strings.Contains(string(j), m) {
				return fmt.Errorf("connector A config contains %q", m)
			}
		}
		return nil
	})

	// The admin API refuses a provisioning key that would put tenant A's user into B.
	check(t, "SEC-TEN-006", "provisioning key for a user of another tenant -> 404", "", func(t *testing.T) error {
		return want(f.admin("POST", "/tenants/"+f.tB+"/provisioning-keys", api.ProvisioningKeyRequest{UserID: f.uA}), "cross-tenant key", http.StatusNotFound)
	})

	// Private Edge (ADR-0014): its peer feed holds its tenant only.
	check(t, "SEC-TEN-010", "Private Edge peer feed holds only its tenant's devices and connectors", "", func(t *testing.T) error {
		p, err := decode[api.EdgePeers](do(f.cp(f.privEdgeCert), "GET", f.cpURL+"/v1/edge/peers", nil, nil))
		if err != nil {
			return err
		}
		seenA1, seenConnA := false, false
		for _, d := range p.Devices {
			if d.TenantID != f.tA {
				return fmt.Errorf("private edge of %s received device %s of tenant %s", f.tA, d.DeviceID, d.TenantID)
			}
			seenA1 = seenA1 || d.DeviceID == f.devA1.id
		}
		for _, c := range p.Connectors {
			if c.TenantID != f.tA {
				return fmt.Errorf("private edge received connector %s of tenant %s", c.ConnectorID, c.TenantID)
			}
			seenConnA = seenConnA || c.ConnectorID == f.connA.id
		}
		if !seenA1 || !seenConnA {
			return fmt.Errorf("control: own device (%v) / connector (%v) missing", seenA1, seenConnA)
		}
		return nil
	})

	// A Private Edge claiming a live session for another tenant's device gets no
	// decisions and cannot write that tenant's flows.
	check(t, "SEC-TEN-011", "Private Edge cannot decide for or write flows of other tenants' devices", "", func(t *testing.T) error {
		c := f.cp(f.privEdgeCert)
		if err := want(do(c, "POST", f.cpURL+"/v1/edge/sessions", api.EdgeSessions{DeviceIDs: []string{f.devA1.id, f.devB1.id}}, nil), "report sessions", http.StatusNoContent); err != nil {
			return err
		}
		if err := want(do(c, "POST", f.cpURL+"/v1/decide?device="+f.devA1.id, decideBody("x.test"), nil), "control: decide for own tenant", 200); err != nil {
			return err
		}
		if err := want(do(c, "POST", f.cpURL+"/v1/decide?device="+f.devB1.id, decideBody("x.test"), nil), "decide for tenant B device", http.StatusForbidden); err != nil {
			return err
		}
		m := "privedge-" + f.run + ".sectest.test"
		b := api.FlowBatch{Records: []api.FlowRecord{
			{Start: time.Now().UTC(), Flow: policy.Flow{Protocol: "tcp", DstIP: "192.0.2.9", DstPort: 80, Domain: m}, DeviceID: f.devB1.id},
			{Start: time.Now().UTC(), Flow: policy.Flow{Protocol: "tcp", DstIP: "192.0.2.9", DstPort: 80, Domain: m}, DeviceID: f.devA1.id},
		}}
		if err := want(do(c, "POST", f.cpURL+"/v1/flows", b, nil), "post flows", http.StatusAccepted); err != nil {
			return err
		}
		if fa, _ := f.waitFlows(f.tA, 5*time.Second, func(s string) bool { return strings.Contains(s, m) }); !strings.Contains(fa, m) {
			return errors.New("control: own-tenant edge flow not stored")
		}
		if fb, _ := f.flows(f.tB); strings.Contains(fb, m) {
			return errors.New("private edge of tenant A wrote a flow into tenant B")
		}
		return nil
	})

	// Any edge (even a public one) acts only for devices it reported as live.
	check(t, "SEC-TEN-012", "edge decide/flows for a device without a reported live session -> refused", "", func(t *testing.T) error {
		id := "sectest-" + f.run + "-pub2"
		ec, err := f.newEdge(id, "")
		if err != nil {
			return skipf("%v", err)
		}
		defer f.admin("POST", "/edges/"+id+"/revoke", nil)
		c := f.cp(ec)
		if err := want(do(c, "POST", f.cpURL+"/v1/decide?device="+f.devB1.id, decideBody("x.test"), nil), "decide without session", http.StatusForbidden); err != nil {
			return err
		}
		return want(do(c, "POST", f.cpURL+"/v1/decide?device=../"+f.devB1.id, decideBody("x.test"), nil), "decide with traversal id", http.StatusForbidden)
	})

	// ST-03: a tenant admin token (osa_...) administers only its tenant. The super-admin
	// mints one for tenant A; with it, tenant B must look nonexistent (404, the same answer as
	// for a tenant that does not exist), super-admin routes must be refused (403), and the
	// token must die at once when revoked. Positive control: the token works on tenant A.
	tokA, err := decode[api.AdminTokenCreated](f.admin("POST", "/tenants/"+f.tA+"/admin-tokens", api.AdminTokenRequest{Name: "sectest " + f.run, ValidFor: 3600}))
	asA := func(method, path string, body any) resp {
		return do(f.anon(), method, f.cpURL+"/v1/admin"+path, body, map[string]string{"Authorization": "Bearer " + tokA.Token})
	}
	revoked := false
	defer func() {
		if err == nil && !revoked {
			f.admin("POST", "/tenants/"+f.tA+"/admin-tokens/"+tokA.ID+"/revoke", nil)
		}
	}()
	ready := func() error {
		if err != nil {
			return fmt.Errorf("create tenant admin token: %w", err)
		}
		if r := asA("GET", "/tenants/"+f.tA+"/devices", nil); r.code != http.StatusOK {
			return fmt.Errorf("positive control: tenant A's token on tenant A: %s", r)
		}
		return nil
	}
	check(t, "SEC-TEN-020", "admin credential is scoped to one tenant", "", func(t *testing.T) error {
		if e := ready(); e != nil {
			return e
		}
		for _, p := range []string{"/devices", "/flows", "/policy", "/users", "/connectors", "/admin-tokens"} {
			if r := asA("GET", "/tenants/"+f.tB+p, nil); r.code != http.StatusNotFound {
				return fmt.Errorf("tenant A's admin reads tenant B %s: %s", p, r)
			}
		}
		if r := asA("PUT", "/tenants/"+f.tB+"/policy", api.TenantPolicy{DefaultAction: policy.ActionAllow}); r.code != http.StatusNotFound {
			return fmt.Errorf("tenant A's admin writes tenant B's policy: %s", r)
		}
		return nil
	})
	check(t, "SEC-TEN-021", "tenant admin cannot escalate (mint for B, create tenants, manage Edges)", "", func(t *testing.T) error {
		if e := ready(); e != nil {
			return e
		}
		if r := asA("POST", "/tenants/"+f.tB+"/admin-tokens", api.AdminTokenRequest{Name: "escalate"}); r.code != http.StatusNotFound {
			return fmt.Errorf("token for tenant B minted by tenant A: %s", r)
		}
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{"POST", "/tenants", api.AdminTenant{ID: "sectest-" + f.run + "-esc", Name: "x"}},
			{"GET", "/edges", nil},
			{"POST", "/edges", api.AdminEdge{ID: "sectest-" + f.run + "-esc", TenantID: f.tA}},
			{"POST", "/edges/" + f.pubEdge + "/revoke", nil},
		} {
			if r := asA(c.method, c.path, c.body); r.code != http.StatusForbidden {
				return fmt.Errorf("%s %s as tenant admin: %s", c.method, c.path, r)
			}
		}
		ts, e := decode[[]api.AdminTenant](asA("GET", "/tenants", nil))
		if e != nil || len(ts) != 1 || ts[0].ID != f.tA {
			return fmt.Errorf("tenant list for tenant admin: %v: %w", ts, e)
		}
		return nil
	})
	check(t, "SEC-TEN-022", "admin token list carries no secrets", "", func(t *testing.T) error {
		if e := ready(); e != nil {
			return e
		}
		r := f.admin("GET", "/tenants/"+f.tA+"/admin-tokens", nil)
		if r.code != http.StatusOK {
			return fmt.Errorf("list: %s", r)
		}
		if bytes.Contains(r.body, []byte(tokA.Token)) || bytes.Contains(r.body, []byte(`"token"`)) {
			return errors.New("the admin token list returns token secrets")
		}
		return nil
	})
	check(t, "SEC-TEN-023", "revoked tenant admin token is refused at once", "", func(t *testing.T) error {
		if e := ready(); e != nil {
			return e
		}
		if r := f.admin("POST", "/tenants/"+f.tA+"/admin-tokens/"+tokA.ID+"/revoke", nil); r.code != http.StatusNoContent {
			return fmt.Errorf("revoke: %s", r)
		}
		revoked = true
		if r := asA("GET", "/tenants/"+f.tA+"/devices", nil); r.code != http.StatusUnauthorized {
			return fmt.Errorf("revoked token still works: %s", r)
		}
		return nil
	})
	check(t, "SEC-TEN-024", "empty or malformed bearer is not an admin", "", func(t *testing.T) error {
		// Variants are reported by index so that the token never reaches the log.
		for i, h := range []string{"Bearer ", "Bearer", "Bearer osa_", "Bearer  " + f.token, "bearer " + f.token} {
			r := do(f.anon(), "GET", f.cpURL+"/v1/admin/tenants", nil, map[string]string{"Authorization": h})
			if r.code != http.StatusUnauthorized {
				return fmt.Errorf("authorization header variant #%d accepted: %d", i, r.code)
			}
		}
		return nil
	})
}
