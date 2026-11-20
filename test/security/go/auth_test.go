package securitytest

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// adminRoutes are every admin endpoint of pkg/api (method, path).
func adminRoutes(t string) [][2]string {
	return [][2]string{
		{"GET", "/tenants"}, {"POST", "/tenants"},
		{"GET", "/tenants/" + t + "/users"}, {"POST", "/tenants/" + t + "/users"},
		{"POST", "/tenants/" + t + "/provisioning-keys"},
		{"GET", "/tenants/" + t + "/policy"}, {"PUT", "/tenants/" + t + "/policy"},
		{"GET", "/tenants/" + t + "/flows"}, {"GET", "/tenants/" + t + "/devices"},
		{"POST", "/tenants/" + t + "/devices/x/revoke"},
		{"GET", "/tenants/" + t + "/connectors"}, {"POST", "/tenants/" + t + "/connectors"},
		{"POST", "/tenants/" + t + "/connectors/x/revoke"},
		{"GET", "/edges"}, {"POST", "/edges"}, {"POST", "/edges/x/revoke"},
	}
}

func randWGKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestAuth(t *testing.T) {
	f := stack(t)

	// Admin API with no Authorization header: every route must answer 401 before touching
	// any data (a 404/400 would leak that the auth check runs after routing).
	check(t, "SEC-AUTH-001", "admin API without a token -> 401 on every route", "", func(t *testing.T) error {
		for _, rt := range adminRoutes(f.tA) {
			r := do(f.anon(), rt[0], f.cpURL+"/v1/admin"+rt[1], "{}", nil)
			if err := want(r, rt[0]+" "+rt[1], http.StatusUnauthorized); err != nil {
				return err
			}
		}
		return nil
	})

	// Wrong tokens and near misses: truncated, extended, other scheme, lowercase scheme,
	// token in the query string, empty bearer.
	check(t, "SEC-AUTH-002", "admin API with wrong or malformed tokens -> 401", "", func(t *testing.T) error {
		tok := f.token
		variants := map[string]map[string]string{
			"wrong":      {"Authorization": "Bearer not-the-admin-token-000000"},
			"truncated":  {"Authorization": "Bearer " + tok[:len(tok)-1]},
			"extended":   {"Authorization": "Bearer " + tok + "x"},
			"basic":      {"Authorization": "Basic " + tok},
			"no-scheme":  {"Authorization": tok},
			"empty":      {"Authorization": "Bearer "},
			"x-header":   {"X-Admin-Token": tok},
			"cookie":     {"Cookie": "token=" + tok},
			"double-tok": {"Authorization": "Bearer wrong, Bearer " + tok},
		}
		for name, h := range variants {
			r := do(f.anon(), "GET", f.cpURL+"/v1/admin/tenants", nil, h)
			if err := want(r, name, http.StatusUnauthorized); err != nil {
				return err
			}
		}
		r := do(f.anon(), "GET", f.cpURL+"/v1/admin/tenants?token="+tok, nil, nil)
		return want(r, "token in query", http.StatusUnauthorized)
	})

	// Timing of the token check: a token that matches all but the last byte must not take
	// measurably longer than one that differs in the first byte (byte-wise early exit).
	// Interleaved samples, median comparison; threshold well above loopback jitter.
	check(t, "SEC-AUTH-003", "admin token check has no prefix-length timing signal", "", func(t *testing.T) error {
		tok := f.token
		last := "0"
		if tok[len(tok)-1] == '0' {
			last = "1"
		}
		near := tok[:len(tok)-1] + last
		far := strings.Repeat("z", len(tok))
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: f.clientTLS(nil, pki.ServerControlPlane, ""), ForceAttemptHTTP2: true}}
		non401 := 0
		measure := func(tk string) time.Duration {
			req, _ := http.NewRequest("GET", f.cpURL+"/v1/admin/tenants", nil) //nolint:noctx // client has keep-alive, short op
			req.Header.Set("Authorization", "Bearer "+tk)
			s := time.Now()
			r, err := c.Do(req)
			d := time.Since(s)
			if err != nil || r.StatusCode != http.StatusUnauthorized {
				non401++
			}
			if err == nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
			return d
		}
		for range 20 { // warm up the connection
			measure(far)
		}
		const n = 300
		var a, b []time.Duration
		for range n {
			a = append(a, measure(near))
			b = append(b, measure(far))
		}
		med := func(x []time.Duration) time.Duration {
			sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
			return x[len(x)/2]
		}
		if non401 > 0 {
			return fmt.Errorf("%d timing samples were not a 401 (measurement invalid)", non401)
		}
		ma, mb := med(a), med(b)
		diff := ma - mb
		t.Logf("median near-miss %v, far-miss %v", ma, mb)
		if diff > 200*time.Microsecond {
			return fmt.Errorf("near-miss token median %v vs far-miss %v (+%v)", ma, mb, diff)
		}
		return nil
	})

	// A client certificate (device) is not an admin credential.
	check(t, "SEC-AUTH-004", "device certificate without token on admin API -> 401", "", func(t *testing.T) error {
		return want(do(f.cp(f.devA1.cert), "GET", f.cpURL+"/v1/admin/tenants", nil, nil), "device cert on admin", http.StatusUnauthorized)
	})

	// Role isolation: each certificate kind on every route of the other kinds. Allowed
	// pairs must NOT get 401/403 (positive control: the identity itself works).
	check(t, "SEC-AUTH-010", "device/connector/edge certificates refused on each other's routes", "", func(t *testing.T) error {
		type route struct {
			method, path, body string
			allowed            map[string]bool
		}
		routes := []route{
			{"GET", "/v1/snapshot", "", map[string]bool{"device": true}},
			{"GET", "/v1/self/rules", "", map[string]bool{"device": true}},
			{"POST", "/v1/renew", "{}", map[string]bool{"device": true}},
			{"POST", "/v1/flows", `{"records":[]}`, map[string]bool{"device": true, "edge": true}},
			{"POST", "/v1/decide", `{"flow":{"protocol":"tcp","dstIp":"192.0.2.1","dstPort":80}}`, map[string]bool{"device": true, "edge": true}},
			{"GET", "/v1/connector/config", "", map[string]bool{"connector": true}},
			{"POST", "/v1/connector/renew", "{}", map[string]bool{"connector": true}},
			{"GET", "/v1/edge/peers", "", map[string]bool{"edge": true}},
			{"POST", "/v1/edge/sessions", `{"deviceIds":[]}`, map[string]bool{"edge": true}},
		}
		ids := map[string]tls.Certificate{"device": f.devA1.cert, "connector": f.connA.cert, "edge": f.pubEdgeCert}
		var errs []error
		for kind, cert := range ids {
			c := f.cp(cert)
			for _, rt := range routes {
				var body any
				if rt.body != "" {
					body = rt.body
				}
				r := do(c, rt.method, f.cpURL+rt.path, body, nil)
				denied := r.code == http.StatusUnauthorized || r.code == http.StatusForbidden
				switch {
				case r.err != nil:
					errs = append(errs, fmt.Errorf("%s %s %s: %w", kind, rt.method, rt.path, r.err))
				case rt.allowed[kind] && denied && (kind != "edge" || rt.path != "/v1/decide"):
					errs = append(errs, fmt.Errorf("control: %s on %s %s denied: %s", kind, rt.method, rt.path, r))
				case !rt.allowed[kind] && !denied:
					errs = append(errs, fmt.Errorf("%s cert accepted on %s %s: %s", kind, rt.method, rt.path, r))
				}
			}
		}
		// Edge session channel: devices only.
		for kind, cert := range ids {
			r := f.session(cert)
			if kind == "device" && r.code != http.StatusOK {
				errs = append(errs, fmt.Errorf("control: device on edge /v1/session: %s", r))
			}
			if kind != "device" {
				if err := edgeDenied(r, kind+" cert on edge /v1/session"); err != nil {
					errs = append(errs, err)
				}
			}
		}
		// Connector broker: connectors only (the Edge speaks first, HTTP/2 client preface).
		for kind, cert := range ids {
			got := brokerProbe(f.env, cert, api.BrokerALPN)
			if kind == "connector" && got != nil {
				errs = append(errs, fmt.Errorf("control: connector on broker: %w", got))
			}
			if kind != "connector" && got == nil {
				errs = append(errs, fmt.Errorf("%s cert accepted on the connector broker", kind))
			}
		}
		return errors.Join(errs...)
	})

	// Revoked device: every device route and the Edge session channel must refuse it. The
	// Edge learns revocations on its 10s peer sync: allow 30s.
	check(t, "SEC-AUTH-020", "revoked device refused on CP routes and on the Edge", "", func(t *testing.T) error {
		d, err := f.enrollDevice(f.tA, f.uA, "sectest-revoke")
		if err != nil {
			return skipf("enroll: %v", err)
		}
		if err := want(do(f.edge(d.cert), "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":0}`, nil), "control: session before revoke", 200); err != nil {
			return err
		}
		if r := f.admin("POST", "/tenants/"+d.tenant+"/devices/"+d.id+"/revoke", nil); r.code != http.StatusNoContent {
			return skipf("revoke: %s", r)
		}
		c := f.cp(d.cert)
		var errs []error
		for _, rt := range [][3]string{{"GET", "/v1/snapshot", ""}, {"GET", "/v1/self/rules", ""}, {"POST", "/v1/renew", `{"csrPem":"` + jsonEsc(csrPEM(newKey())) + `"}`}, {"POST", "/v1/flows", `{"records":[]}`}, {"POST", "/v1/decide", `{"flow":{"protocol":"tcp","dstIp":"192.0.2.1","dstPort":80}}`}} {
			var body any
			if rt[2] != "" {
				body = rt[2]
			}
			if err := want(do(c, rt[0], f.cpURL+rt[1], body, nil), "revoked "+rt[1], http.StatusForbidden); err != nil {
				errs = append(errs, err)
			}
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			r := f.session(d.cert)
			if r.code != http.StatusOK {
				if err := edgeDenied(r, "revoked device"); err != nil {
					errs = append(errs, err)
				}
				break
			}
			if time.Now().After(deadline) {
				errs = append(errs, errors.New("edge still accepts the revoked device after 30s"))
				break
			}
			time.Sleep(2 * time.Second)
		}
		return errors.Join(errs...)
	})

	// Revoking through another tenant's path must not work (tenant-scoped revocation).
	check(t, "SEC-AUTH-021", "device revoke through another tenant's path -> 404, device unaffected", "", func(t *testing.T) error {
		if err := want(f.admin("POST", "/tenants/"+f.tB+"/devices/"+f.devA1.id+"/revoke", nil), "cross-tenant revoke", http.StatusNotFound); err != nil {
			return err
		}
		if err := want(f.admin("POST", "/tenants/"+f.tB+"/connectors/"+f.connA.id+"/revoke", nil), "cross-tenant connector revoke", http.StatusNotFound); err != nil {
			return err
		}
		return want(do(f.cp(f.devA1.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil), "device A1 after cross-tenant revoke", 200)
	})

	// Revoked connector: config and renew refused at once; the Edge broker within 30s.
	check(t, "SEC-AUTH-022", "revoked connector refused on CP routes and the Edge broker", "", func(t *testing.T) error {
		cn := f.connA2
		if err := want(do(f.cp(cn.cert), "GET", f.cpURL+"/v1/connector/config", nil, nil), "control: config before revoke", 200); err != nil {
			return err
		}
		if err := brokerProbe(f.env, cn.cert, api.BrokerALPN); err != nil {
			return fmt.Errorf("control: broker before revoke: %w", err)
		}
		if r := f.admin("POST", "/tenants/"+cn.tenant+"/connectors/"+cn.id+"/revoke", nil); r.code != http.StatusNoContent {
			return skipf("revoke: %s", r)
		}
		var errs []error
		if err := want(do(f.cp(cn.cert), "GET", f.cpURL+"/v1/connector/config", nil, nil), "revoked config", http.StatusForbidden); err != nil {
			errs = append(errs, err)
		}
		if err := want(do(f.cp(cn.cert), "POST", f.cpURL+"/v1/connector/renew", `{"csrPem":"`+jsonEsc(csrPEM(newKey()))+`"}`, nil), "revoked renew", http.StatusForbidden); err != nil {
			errs = append(errs, err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for brokerProbe(f.env, cn.cert, api.BrokerALPN) == nil {
			if time.Now().After(deadline) {
				errs = append(errs, errors.New("edge broker still accepts the revoked connector after 30s"))
				break
			}
			time.Sleep(2 * time.Second)
		}
		return errors.Join(errs...)
	})

	// Unregistered and revoked Edge certificates (both validly signed by root) -> 403.
	check(t, "SEC-AUTH-023", "unregistered and revoked Edge certificates -> 403", "", func(t *testing.T) error {
		ca, err := f.rootCA()
		if err != nil {
			return skipf("root CA: %v", err)
		}
		certPEM, keyPEM, err := ca.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindEdge, ID: "sectest-" + f.run + "-unreg", DNSNames: []string{"localhost"}})
		if err != nil {
			return err
		}
		unreg, _ := tls.X509KeyPair(certPEM, keyPEM)
		if err := want(do(f.cp(unreg), "GET", f.cpURL+"/v1/edge/peers", nil, nil), "unregistered edge", http.StatusForbidden); err != nil {
			return err
		}
		id := "sectest-" + f.run + "-rev"
		ec, err := f.newEdge(id, "")
		if err != nil {
			return skipf("%v", err)
		}
		if err := want(do(f.cp(ec), "GET", f.cpURL+"/v1/edge/peers", nil, nil), "control: edge before revoke", 200); err != nil {
			return err
		}
		f.admin("POST", "/edges/"+id+"/revoke", nil)
		for _, p := range []string{"/v1/edge/peers"} {
			if err := want(do(f.cp(ec), "GET", f.cpURL+p, nil, nil), "revoked edge "+p, http.StatusForbidden); err != nil {
				return err
			}
		}
		if err := want(do(f.cp(ec), "POST", f.cpURL+"/v1/edge/sessions", `{"deviceIds":[]}`, nil), "revoked edge sessions", http.StatusForbidden); err != nil {
			return err
		}
		// A revoked edge ID cannot be registered again (no silent un-revoke).
		return want(f.admin("POST", "/edges", api.AdminEdge{ID: id}), "re-register revoked edge", http.StatusConflict)
	})

	// Superseded certificate: after a renewal, the old certificate works only on /v1/renew.
	sup := func(t *testing.T) (old, cur *ident, err error) {
		d, err := f.enrollDevice(f.tA, f.uA, "sectest-renew")
		if err != nil {
			return nil, nil, skipf("enroll: %v", err)
		}
		n, err := f.renew(d)
		if err != nil {
			return nil, nil, skipf("renew: %v", err)
		}
		return d, n, nil
	}
	check(t, "SEC-AUTH-030", "superseded device certificate refused on CP routes other than /v1/renew", "", func(t *testing.T) error {
		old, cur, err := sup(t)
		if err != nil {
			return err
		}
		if err := want(do(f.cp(cur.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil), "control: new cert", 200); err != nil {
			return err
		}
		var errs []error
		c := f.cp(old.cert)
		for _, rt := range [][3]string{{"GET", "/v1/snapshot", ""}, {"GET", "/v1/self/rules", ""}, {"POST", "/v1/flows", `{"records":[]}`}, {"POST", "/v1/decide", `{"flow":{"protocol":"tcp","dstIp":"192.0.2.1","dstPort":80}}`}} {
			var body any
			if rt[2] != "" {
				body = rt[2]
			}
			if err := want(do(c, rt[0], f.cpURL+rt[1], body, nil), "superseded cert "+rt[1], http.StatusForbidden); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})

	// The Edge session channel is a route too: a superseded (possibly stolen) certificate
	// must not set up tunnels once the device has renewed.
	check(t, "SEC-AUTH-031", "superseded device certificate refused on the Edge session channel", "ST-01", func(t *testing.T) error {
		old, cur, err := sup(t)
		if err != nil {
			return err
		}
		if err := want(do(f.edge(cur.cert), "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":0}`, nil), "control: new cert on edge", 200); err != nil {
			return err
		}
		r := do(f.edge(old.cert), "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":0}`, nil)
		t.Logf("superseded cert on edge: %s", r)
		switch r.code {
		case http.StatusForbidden:
			return nil
		case http.StatusOK:
			return errors.New("edge set up a WireGuard session for the superseded certificate (HTTP 200)")
		}
		return fmt.Errorf("inconclusive (want 403): %s", r)
	})

	// The lost-response retry window: once the new certificate has been used (so its
	// response was clearly delivered), the superseded certificate must not renew again.
	// Otherwise a thief of the old key takes over the device and locks the owner out.
	check(t, "SEC-AUTH-032", "superseded certificate cannot renew after the new one was used", "ST-02", func(t *testing.T) error {
		old, cur, err := sup(t)
		if err != nil {
			return err
		}
		if err := want(do(f.cp(cur.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil), "control: new cert used", 200); err != nil {
			return err
		}
		stolen, err := f.renew(old)
		if err != nil {
			return nil // refused
		}
		// Demonstrate the impact: the attacker's cert works, the owner's is locked out.
		ra := do(f.cp(stolen.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil)
		ro := do(f.cp(cur.cert), "GET", f.cpURL+"/v1/snapshot", nil, nil)
		return fmt.Errorf("superseded cert renewed again: attacker cert %d, owner's current cert %d", ra.code, ro.code)
	})

	// Two renewals ago: no longer accepted even on /v1/renew.
	check(t, "SEC-AUTH-033", "certificate superseded twice refused on /v1/renew", "", func(t *testing.T) error {
		old, cur, err := sup(t)
		if err != nil {
			return err
		}
		if _, err := f.renew(cur); err != nil {
			return skipf("second renew: %v", err)
		}
		if _, err := f.renew(old); err == nil {
			return errors.New("certificate superseded twice still renews")
		}
		return nil
	})

	// Renewal must use a fresh key (CSR with the same key as the presented certificate).
	check(t, "SEC-PKI-005", "renewal CSR reusing the current key -> 400 (device and connector)", "", func(t *testing.T) error {
		d, err := f.enrollDevice(f.tA, f.uA, "sectest-reuse")
		if err != nil {
			return skipf("enroll: %v", err)
		}
		r := do(f.cp(d.cert), "POST", f.cpURL+"/v1/renew", api.RenewRequest{CSRPEM: csrPEM(d.key)}, nil)
		if err := want(r, "device renew with same key", http.StatusBadRequest); err != nil {
			return err
		}
		r = do(f.cp(f.connA.cert), "POST", f.cpURL+"/v1/connector/renew", api.RenewRequest{CSRPEM: csrPEM(f.connA.key)}, nil)
		return want(r, "connector renew with same key", http.StatusBadRequest)
	})
}

// renew renews d with a new key and returns the new identity (d keeps its old cert).
func (f *fixture) renew(d *ident) (*ident, error) {
	k := newKey()
	rr, err := decode[api.RenewResponse](do(f.cp(d.cert), "POST", f.cpURL+"/v1/renew", api.RenewRequest{CSRPEM: csrPEM(k)}, nil))
	if err != nil {
		return nil, err
	}
	c, err := tlsCert([]byte(rr.CertificatePEM), k)
	if err != nil {
		return nil, err
	}
	return &ident{id: d.id, tenant: d.tenant, key: k, cert: c}, nil
}

func jsonEsc(s string) string { return strings.ReplaceAll(s, "\n", `\n`) }

// brokerProbe connects to the Edge connector listener with cert and ALPN. It returns nil
// when the Edge accepted the connector (it starts HTTP/2 as the client, so its preface
// arrives), or an error describing the refusal.
func brokerProbe(e *env, cert tls.Certificate, alpn string) error {
	c := e.clientTLS([]tls.Certificate{cert}, pki.ServerEdge, e.edgeID)
	if alpn != "" {
		c.NextProtos = []string{alpn}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", e.broker, c)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	defer conn.Close()
	if err := pqsession.CheckPostQuantum(conn.ConnectionState()); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	buf := make([]byte, 24)
	n, err := io.ReadFull(conn, buf)
	if n == 24 && string(buf) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return nil
	}
	return fmt.Errorf("closed by the edge after %d bytes: %w", n, err)
}
