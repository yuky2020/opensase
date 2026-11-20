package securitytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// no5xx is nil unless r is a server error or a transport failure.
func no5xx(r resp, what string) error {
	if r.err != nil {
		return fmt.Errorf("%s: %w", what, r.err)
	}
	if r.code >= 500 {
		return fmt.Errorf("%s: %s", what, r)
	}
	return nil
}

func dirNames(p string) map[string]bool {
	out := map[string]bool{}
	es, _ := os.ReadDir(p)
	for _, e := range es {
		out[e.Name()] = true
	}
	return out
}

func TestInputHandling(t *testing.T) {
	f := stack(t)
	big := bytes.Repeat([]byte("A"), 2<<20)
	bigJSON := []byte(`{"provisioningKey":"osk_` + string(big) + `"}`)

	// Bodies above the 1 MiB limit (4 KiB on the Edge session channel) are refused with a
	// 4xx, without the server buffering them.
	check(t, "SEC-IN-001", "oversized bodies -> 4xx on CP (1 MiB) and Edge (4 KiB)", "", func(t *testing.T) error {
		var errs []error
		for _, c := range []struct {
			cl     *http.Client
			method string
			url    string
			hdr    map[string]string
		}{
			{f.anon(), "POST", f.cpURL + "/v1/enroll", nil},
			{f.anon(), "POST", f.cpURL + "/v1/connector/enroll", nil},
			{f.anon(), "PUT", f.cpURL + "/v1/admin/tenants/" + f.tA + "/policy", map[string]string{"Authorization": "Bearer " + f.token}},
			{f.cp(f.devA1.cert), "POST", f.cpURL + "/v1/flows", nil},
			{f.cp(f.devA1.cert), "PUT", f.cpURL + "/v1/self/rules", nil},
		} {
			r := do(c.cl, c.method, c.url, bigJSON, c.hdr)
			// 429 (enroll rate limit) means the body was never examined: inconclusive.
			if r.err == nil && (r.code < 400 || r.code >= 500 || r.code == http.StatusTooManyRequests) {
				errs = append(errs, fmt.Errorf("%s %s: %s", c.method, c.url, r))
			}
		}
		r := do(f.edge(f.devA1.cert), "POST", f.edgeURL+"/v1/session", []byte(`{"wgPublicKey":"`+strings.Repeat("A", 8000)+`"}`), nil)
		if r.err == nil && r.code != http.StatusBadRequest {
			errs = append(errs, fmt.Errorf("edge session 8 KB body: %s", r))
		}
		return errors.Join(errs...)
	})

	// Malformed JSON never causes a 5xx and never succeeds.
	check(t, "SEC-IN-002", "malformed JSON -> 400, never 5xx or 2xx", "", func(t *testing.T) error {
		bodies := []string{"", "{", "[]", `"x"`, `{"provisioningKey":1}`, `{"unknown":true}`,
			strings.Repeat("[", 100000), "{\"provisioningKey\":\"osk_\xff\xfe\"}", `{"a":1e999999}`, `{"provisioningKey":"osk_x"}{"x":1}`}
		targets := []struct {
			cl  *http.Client
			m   string
			u   string
			hdr map[string]string
		}{
			{f.anon(), "POST", f.cpURL + "/v1/enroll", nil},
			{f.anon(), "POST", f.cpURL + "/v1/connector/enroll", nil},
			{f.anon(), "POST", f.cpURL + "/v1/admin/tenants", map[string]string{"Authorization": "Bearer " + f.token}},
			{f.anon(), "PUT", f.cpURL + "/v1/admin/tenants/" + f.tA + "/policy", map[string]string{"Authorization": "Bearer " + f.token}},
			{f.cp(f.devA1.cert), "POST", f.cpURL + "/v1/decide", nil},
			{f.cp(f.devA1.cert), "POST", f.cpURL + "/v1/flows", nil},
			{f.cp(f.devA1.cert), "POST", f.cpURL + "/v1/renew", nil},
			{f.cp(f.pubEdgeCert), "POST", f.cpURL + "/v1/edge/sessions", nil},
			{f.edge(f.devA1.cert), "POST", f.edgeURL + "/v1/session", nil},
		}
		var errs []error
		for _, tg := range targets {
			for i, b := range bodies {
				// Failed enrollments count against the per-IP limit (30/min): the connector
				// route gets the first four bodies only, so the suite stays within budget.
				if strings.HasSuffix(tg.u, "/v1/connector/enroll") && i >= 4 {
					break
				}
				r := do(tg.cl, tg.m, tg.u, b, tg.hdr)
				if r.err != nil || r.code >= 500 || r.code < 400 || r.code == http.StatusTooManyRequests {
					errs = append(errs, fmt.Errorf("%s %s body %.20q: %s", tg.m, tg.u, b, r))
				}
			}
		}
		f.admin("PUT", "/tenants/"+f.tA+"/policy", tenantPolicy(f.run, "a", f.appA))
		return errors.Join(errs...)
	})

	// IDs that would escape a path segment or a directory: rejected at creation, 404 in
	// URLs, and no file appears outside pki/tenants/<valid id>.
	check(t, "SEC-IN-003", "path traversal in tenant/edge/user IDs refused, no file written", "", func(t *testing.T) error {
		pkiDir := filepath.Join(f.devDir, "pki")
		before, beforeT := dirNames(pkiDir), dirNames(filepath.Join(pkiDir, "tenants"))
		bad := []string{"..", ".", "../x", "..%2fx", "a/b", `a\b`, "/etc", "x\x00y", ".hidden", "-x", strings.Repeat("a", 129), "a b", "ü"}
		var errs []error
		for _, id := range bad {
			if r := f.admin("POST", "/tenants", map[string]string{"id": id, "name": "sectest traversal"}); r.code != http.StatusBadRequest {
				errs = append(errs, fmt.Errorf("tenant id %q: %s", id, r))
			}
			if r := f.admin("POST", "/edges", map[string]string{"id": id}); r.code != http.StatusBadRequest {
				errs = append(errs, fmt.Errorf("edge id %q: %s", id, r))
			}
			if r := f.admin("POST", "/tenants/"+f.tA+"/users", map[string]string{"id": id, "email": "x@sectest.test"}); r.code != http.StatusBadRequest {
				errs = append(errs, fmt.Errorf("user id %q: %s", id, r))
			}
		}
		for _, p := range []string{"/tenants/..%2f..%2f/policy", "/tenants/%2e%2e/flows", "/tenants/..%2Facme/devices", "/tenants/" + f.tA + "/devices/..%2f..%2fx/revoke", "/tenants/%00/policy"} {
			r := f.admin("GET", p, nil)
			if strings.HasSuffix(p, "/revoke") {
				r = f.admin("POST", p, nil)
			}
			if r.err != nil || (r.code != 404 && r.code != 400) {
				errs = append(errs, fmt.Errorf("GET %s: %s", p, r))
			}
		}
		after, afterT := dirNames(pkiDir), dirNames(filepath.Join(pkiDir, "tenants"))
		for n := range after {
			if !before[n] {
				errs = append(errs, fmt.Errorf("new file in pki/: %q", n))
			}
		}
		for n := range afterT {
			if !beforeT[n] {
				errs = append(errs, fmt.Errorf("new tenant dir: %q", n))
			}
		}
		return errors.Join(errs...)
	})

	// Injection payloads in names and IDs: IDs are refused; free-text names are stored
	// verbatim (parameterized SQL), and the store keeps working.
	check(t, "SEC-IN-004", "SQL/shell injection in IDs refused, in names stored verbatim", "", func(t *testing.T) error {
		var errs []error
		for _, id := range []string{"x' OR '1'='1", "x;DROP TABLE tenants", "x\"--", "$(id)", "`id`"} {
			if r := f.admin("POST", "/tenants", map[string]string{"id": id, "name": "x"}); r.code != http.StatusBadRequest {
				errs = append(errs, fmt.Errorf("tenant id %q: %s", id, r))
			}
			if r := f.admin("GET", "/tenants/"+strings.ReplaceAll(id, " ", "%20")+"/devices", nil); r.code != 404 && r.code != 400 {
				errs = append(errs, fmt.Errorf("GET devices of %q: %s", id, r))
			}
		}
		name := `sectest '); DROP TABLE tenants;-- <script>alert(1)</script> $(id)`
		id := "sectest-" + f.run + "-inj"
		if err := want(f.admin("POST", "/tenants", api.AdminTenant{ID: id, Name: name}), "create injection-named tenant", 201); err != nil {
			return err
		}
		ts, err := decode[[]api.AdminTenant](f.admin("GET", "/tenants", nil))
		if err != nil {
			return err
		}
		found := false
		for _, x := range ts {
			found = found || (x.ID == id && x.Name == name)
		}
		if !found {
			errs = append(errs, errors.New("name not stored verbatim"))
		}
		// Device name injection at enrollment, read back through the admin API.
		pk, err := decode[api.ProvisioningKey](f.admin("POST", "/tenants/"+f.tA+"/provisioning-keys", api.ProvisioningKeyRequest{UserID: f.uA}))
		if err != nil {
			return err
		}
		k := newKey()
		dn := `dev'); DELETE FROM devices;--`
		er, err := decode[api.EnrollResponse](do(f.anon(), "POST", f.cpURL+"/v1/enroll", api.EnrollRequest{ProvisioningKey: pk.Key, DeviceName: dn, Platform: "linux", CSRPEM: csrPEM(k)}, nil))
		if err != nil {
			return err
		}
		defer f.admin("POST", "/tenants/"+f.tA+"/devices/"+er.DeviceID+"/revoke", nil)
		devs := f.admin("GET", "/tenants/"+f.tA+"/devices", nil)
		if !strings.Contains(string(devs.body), `DELETE FROM devices`) || !strings.Contains(string(devs.body), f.devA1.id) {
			errs = append(errs, fmt.Errorf("device list after injection: %s", devs))
		}
		return errors.Join(errs...)
	})

	// Policy validation: malformed domains, CIDRs, ports and actions are refused with a
	// 400 (never stored, never a 5xx).
	check(t, "SEC-IN-005", "malformed domains/CIDRs/actions in tenant policy -> 400", "", func(t *testing.T) error {
		base := func() api.TenantPolicy { return tenantPolicy(f.run, "a", f.appA) }
		cases := map[string]func(*api.TenantPolicy){
			"domain with space":    func(p *api.TenantPolicy) { p.DNS.BlockDomains = []string{"ev il.com"} },
			"domain with NUL":      func(p *api.TenantPolicy) { p.DNS.BlockDomains = []string{"evil.com\x00.x"} },
			"domain with newline":  func(p *api.TenantPolicy) { p.DNS.BlockDomains = []string{"evil.com\nallow"} },
			"domain 300 chars":     func(p *api.TenantPolicy) { p.DNS.BlockDomains = []string{strings.Repeat("a", 300) + ".com"} },
			"double wildcard":      func(p *api.TenantPolicy) { p.Rules[0].Match.Domains = []string{"*.*.com"} },
			"bad CIDR":             func(p *api.TenantPolicy) { p.Rules[0].Match.CIDRs = []string{"10.0.0.0/99"} },
			"bad action":           func(p *api.TenantPolicy) { p.Rules[0].Action = "permit" },
			"bad decide CIDR":      func(p *api.TenantPolicy) { p.DecideBlockCIDRs = []string{"nope"} },
			"app domain traversal": func(p *api.TenantPolicy) { p.PrivateApps[0].Domains = []string{"../../etc"} },
			"app port 0":           func(p *api.TenantPolicy) { p.PrivateApps[0].Ports = []policy.PortRange{{From: 0}} },
			"app range inverted":   func(p *api.TenantPolicy) { p.PrivateApps[0].Ports = []policy.PortRange{{From: 90, To: 80}} },
			"rule source user":     func(p *api.TenantPolicy) { p.Rules[0].Source = policy.SourceUser },
		}
		var errs []error
		for name, mod := range cases {
			p := base()
			mod(&p)
			r := f.admin("PUT", "/tenants/"+f.tA+"/policy", p)
			if r.code != http.StatusBadRequest {
				errs = append(errs, fmt.Errorf("%s: %s", name, r))
			}
		}
		// Restore the fixture policy whatever happened.
		f.admin("PUT", "/tenants/"+f.tA+"/policy", base())
		return errors.Join(errs...)
	})

	// Snapshot long-poll: at most 2 per device (3rd -> 429); bad wait values -> 400.
	check(t, "SEC-IN-006", "snapshot long-poll capped at 2 per device; bad wait -> 400", "", func(t *testing.T) error {
		d, err := f.enrollDevice(f.tA, f.uA, "sectest-poll")
		if err != nil {
			return skipf("enroll: %v", err)
		}
		defer f.admin("POST", "/tenants/"+d.tenant+"/devices/"+d.id+"/revoke", nil)
		snap := do(f.cp(d.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil)
		etag := snap.hdr.Get("ETag")
		hdr := map[string]string{"If-None-Match": etag}
		short := f.cp(d.cert)
		short.Timeout = 5 * time.Second
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { do(short, "GET", f.cpURL+"/v1/snapshot?wait=30", nil, hdr) })
		}
		time.Sleep(1500 * time.Millisecond)
		third := do(f.cp(d.cert), "GET", f.cpURL+"/v1/snapshot?wait=30", nil, hdr)
		wg.Wait()
		var errs []error
		if third.code != http.StatusTooManyRequests {
			errs = append(errs, fmt.Errorf("3rd concurrent long-poll: %s", third))
		}
		for _, w := range []string{"-1", "abc", "99999999999999999999999", "1e3"} {
			if r := do(f.cp(d.cert), "GET", f.cpURL+"/v1/snapshot?wait="+w, nil, hdr); r.code != http.StatusBadRequest {
				errs = append(errs, fmt.Errorf("wait=%s: %s", w, r))
			}
		}
		return errors.Join(errs...)
	})

	// Flow rate limit: 1000 records/device/minute; a batch above 2000 is refused.
	check(t, "SEC-IN-007", "flow records rate-limited to 1000/device/min, batches >2000 -> 413", "", func(t *testing.T) error {
		d, err := f.enrollDevice(f.tA, f.uA, "sectest-flood")
		if err != nil {
			return skipf("enroll: %v", err)
		}
		defer f.admin("POST", "/tenants/"+d.tenant+"/devices/"+d.id+"/revoke", nil)
		m := "flood-" + f.run + ".sectest.test"
		mk := func(n int) api.FlowBatch {
			b := api.FlowBatch{}
			for range n {
				b.Records = append(b.Records, api.FlowRecord{Start: time.Now().UTC(), Flow: policy.Flow{Protocol: "tcp", DstIP: "192.0.2.1", DstPort: 1, Domain: m}})
			}
			return b
		}
		if err := want(do(f.cp(d.cert), "POST", f.cpURL+"/v1/flows", mk(2001), nil), "2001-record batch", http.StatusRequestEntityTooLarge); err != nil {
			return err
		}
		for range 2 {
			if err := want(do(f.cp(d.cert), "POST", f.cpURL+"/v1/flows", mk(900), nil), "900-record batch", http.StatusAccepted); err != nil {
				return err
			}
		}
		r := f.admin("GET", "/tenants/"+f.tA+"/flows?limit=10000", nil)
		if r.code != 200 {
			return fmt.Errorf("list flows: %s", r)
		}
		body := string(r.body)
		n := strings.Count(body, m)
		if n == 0 {
			return errors.New("control: no flood records stored")
		}
		if n > 1000 {
			return fmt.Errorf("%d records stored for one device within a minute (limit 1000)", n)
		}
		return nil
	})

	// Provisioning keys: single use, expiry honoured, lifetime capped at 30 days.
	check(t, "SEC-IN-009", "provisioning key single-use, expiry and 30-day cap enforced", "", func(t *testing.T) error {
		pk, err := decode[api.ProvisioningKey](f.admin("POST", "/tenants/"+f.tA+"/provisioning-keys", api.ProvisioningKeyRequest{UserID: f.uA, MaxUses: -5}))
		if err != nil {
			return err
		}
		enroll := func(key string) resp {
			return do(f.anon(), "POST", f.cpURL+"/v1/enroll", api.EnrollRequest{ProvisioningKey: key, DeviceName: "sectest-key", Platform: "linux", CSRPEM: csrPEM(newKey())}, nil)
		}
		r1 := enroll(pk.Key)
		if r1.code != 200 {
			return fmt.Errorf("control: first use: %s", r1)
		}
		if er, err := decode[api.EnrollResponse](r1); err == nil {
			defer f.admin("POST", "/tenants/"+f.tA+"/devices/"+er.DeviceID+"/revoke", nil)
		}
		if err := want(enroll(pk.Key), "second use of maxUses<1 key", http.StatusForbidden); err != nil {
			return err
		}
		pk2, err := decode[api.ProvisioningKey](f.admin("POST", "/tenants/"+f.tA+"/provisioning-keys", api.ProvisioningKeyRequest{UserID: f.uA, ValidFor: 1}))
		if err != nil {
			return err
		}
		time.Sleep(2500 * time.Millisecond)
		if err := want(enroll(pk2.Key), "expired key", http.StatusForbidden); err != nil {
			return err
		}
		pk3, err := decode[api.ProvisioningKey](f.admin("POST", "/tenants/"+f.tA+"/provisioning-keys", api.ProvisioningKeyRequest{UserID: f.uA, ValidFor: 1 << 30}))
		if err != nil {
			return err
		}
		if pk3.ExpiresAt.After(time.Now().Add(30*24*time.Hour + time.Minute)) {
			return fmt.Errorf("key valid until %v (cap 30 days)", pk3.ExpiresAt)
		}
		// Prefix confusion: a device key on the connector route and vice versa.
		return want(do(f.anon(), "POST", f.cpURL+"/v1/connector/enroll", api.ConnectorEnrollRequest{ProvisioningKey: pk3.Key, CSRPEM: csrPEM(newKey())}, nil), "device key on connector enroll", http.StatusBadRequest)
	})

	// Device-controlled flow records are clamped (review #10 regression).
	check(t, "SEC-IN-010", "flow record fields clamped (time, bytes, string lengths)", "", func(t *testing.T) error {
		m := "clamp-" + f.run
		long := m + strings.Repeat("x", 5000)
		rec := api.FlowRecord{Start: time.Date(1971, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC), BytesIn: 1 << 62, BytesOut: 1 << 62,
			Flow:     policy.Flow{Protocol: strings.Repeat("p", 500), DstIP: strings.Repeat("1", 500), Domain: long, App: strings.Repeat("a", 5000)},
			Decision: policy.Decision{RuleID: strings.Repeat("r", 5000), Layer: strings.Repeat("l", 500)}}
		if err := want(do(f.cp(f.devA1.cert), "POST", f.cpURL+"/v1/flows", api.FlowBatch{Records: []api.FlowRecord{rec}}, nil), "post", http.StatusAccepted); err != nil {
			return err
		}
		body, err := f.waitFlows(f.tA, 5*time.Second, func(s string) bool { return strings.Contains(s, m) })
		if err != nil {
			return err
		}
		var b api.FlowBatch
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			return err
		}
		for _, r := range b.Records {
			if !strings.HasPrefix(r.Flow.Domain, m) {
				continue
			}
			now := time.Now()
			switch {
			case len(r.Flow.Domain) > 253 || len(r.Flow.App) > 256 || len(r.Decision.RuleID) > 128 || len(r.Flow.DstIP) > 45 || len(r.Flow.Protocol) > 8:
				return fmt.Errorf("strings not clamped: domain %d app %d rule %d", len(r.Flow.Domain), len(r.Flow.App), len(r.Decision.RuleID))
			case r.BytesIn > 1<<40 || r.BytesOut > 1<<40:
				return fmt.Errorf("bytes not clamped: %d", r.BytesIn)
			case r.Start.Before(now.Add(-25*time.Hour)) || r.End.After(now.Add(6*time.Minute)):
				return fmt.Errorf("times not clamped: %v .. %v", r.Start, r.End)
			}
			return nil
		}
		return errors.New("control: record not found")
	})

	// Edge session channel input: zero key, unknown session, skipped epoch.
	check(t, "SEC-IN-011", "Edge /v1/session rejects zero WG key, unknown session and epoch skips", "", func(t *testing.T) error {
		c := f.edge(f.devA2.cert)
		if err := want(do(c, "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","epoch":0}`, nil), "zero key", 400); err != nil {
			return err
		}
		if err := want(do(c, "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":3,"sessionId":"deadbeef"}`, nil), "unknown session", 409); err != nil {
			return err
		}
		s, err := decode[api.SessionResponse](do(c, "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":0}`, nil))
		if err != nil {
			return err
		}
		return want(do(c, "POST", f.edgeURL+"/v1/session", fmt.Sprintf(`{"wgPublicKey":%q,"epoch":%d,"sessionId":%q}`, randWGKey(), s.Epoch+5, s.SessionID), nil), "epoch skip", 409)
	})

	// Request headers above the server limit (Go default 1 MiB) are refused, never a 5xx.
	check(t, "SEC-IN-013", "1.5 MB request header refused (431 or closed), CP stays up", "", func(t *testing.T) error {
		r := do(f.anon(), "GET", f.cpURL+"/v1/pki/ca", nil, map[string]string{"X-Sectest": strings.Repeat("a", 1536<<10)})
		if r.err == nil && r.code != http.StatusRequestHeaderFieldsTooLarge && r.code != http.StatusBadRequest {
			return fmt.Errorf("1.5 MB header: %s", r)
		}
		return want(do(f.anon(), "GET", f.cpURL+"/v1/pki/ca", nil, nil), "CP after oversized header", 200)
	})

	// Random structural fuzz of JSON bodies on the authenticated routes: never a 5xx, and
	// the CP is still healthy afterwards.
	check(t, "SEC-IN-012", "JSON body fuzz (600 cases) -> no 5xx, CP stays healthy", "", func(t *testing.T) error {
		rng := rand.New(rand.NewPCG(1, 2))
		atoms := []string{`null`, `true`, `-1`, `0`, `1e308`, `18446744073709551616`, `""`, `"` + strings.Repeat("x", 3000) + `"`, `"\u0000"`, `"../../"`, `[]`, `{}`, `"osk_x"`, `"198.51.100.7"`, `"*"`}
		keys := []string{"flow", "records", "protocol", "dstIp", "dstPort", "domain", "rules", "apps", "deviceIds", "connectorIds", "csrPem", "provisioningKey", "wgPublicKey", "epoch", "sessionId", "match", "action", "priority", "start", "end"}
		var gen func(depth int) string
		gen = func(depth int) string {
			switch {
			case depth > 3 || rng.IntN(3) == 0:
				return atoms[rng.IntN(len(atoms))]
			case rng.IntN(2) == 0:
				n := rng.IntN(4)
				parts := make([]string, n)
				for i := range parts {
					parts[i] = gen(depth + 1)
				}
				return "[" + strings.Join(parts, ",") + "]"
			default:
				n := rng.IntN(4)
				parts := make([]string, n)
				for i := range parts {
					parts[i] = fmt.Sprintf("%q:%s", keys[rng.IntN(len(keys))], gen(depth+1))
				}
				return "{" + strings.Join(parts, ",") + "}"
			}
		}
		dev, edge, conn := f.cp(f.devA2.cert), f.cp(f.pubEdgeCert), f.cp(f.connA.cert)
		targets := []struct {
			cl     *http.Client
			m, u   string
			hdr    map[string]string
			unsafe bool
		}{
			{dev, "POST", f.cpURL + "/v1/decide", nil, false},
			{dev, "POST", f.cpURL + "/v1/flows", nil, false},
			{dev, "PUT", f.cpURL + "/v1/self/rules", nil, false},
			{edge, "POST", f.cpURL + "/v1/edge/sessions", nil, false},
			{edge, "POST", f.cpURL + "/v1/flows", nil, false},
			{conn, "POST", f.cpURL + "/v1/connector/renew", nil, false},
			{f.anon(), "POST", f.cpURL + "/v1/enroll", nil, false},
			{f.anon(), "PUT", f.cpURL + "/v1/admin/tenants/" + f.tA + "/policy", map[string]string{"Authorization": "Bearer " + f.token}, false},
		}
		var errs []error
		enrollSent := 0
		for i := range 600 {
			tg := targets[i%len(targets)]
			if strings.HasSuffix(tg.u, "/v1/enroll") {
				if enrollSent++; enrollSent > 8 { // enroll failures are rate-limited (30/min/IP)
					continue
				}
			}
			body := gen(0)
			if err := no5xx(do(tg.cl, tg.m, tg.u, body, tg.hdr), fmt.Sprintf("%s %s %.60s", tg.m, tg.u, body)); err != nil {
				errs = append(errs, err)
			}
		}
		f.admin("PUT", "/tenants/"+f.tA+"/policy", tenantPolicy(f.run, "a", f.appA))
		do(dev, "PUT", f.cpURL+"/v1/self/rules", api.UserRules{}, nil)
		if r := do(f.anon(), "GET", f.cpURL+"/v1/pki/ca", nil, nil); r.code != 200 {
			errs = append(errs, fmt.Errorf("CP unhealthy after fuzz: %s", r))
		}
		if len(errs) > 5 {
			errs = append(errs[:5], fmt.Errorf("... and %d more", len(errs)-5))
		}
		return errors.Join(errs...)
	})
}
