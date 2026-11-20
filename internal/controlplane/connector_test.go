package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
)

// brokerEdgesCfg configures three edges: edge-1 (broker, registered by the tests),
// edge-2 (broker, never registered) and edge-3 (registered, no broker).
func brokerEdgesCfg(c *Config) {
	c.Edges = []api.EdgeInfo{
		{ID: "edge-1", SessionURL: "https://edge:8443", WGEndpoint: "edge:51820", BrokerAddr: "edge:8444"},
		{ID: "edge-2", SessionURL: "https://edge2:8443", WGEndpoint: "edge2:51820", BrokerAddr: "edge2:8444"},
		{ID: "edge-3", SessionURL: "https://edge3:8443", WGEndpoint: "edge3:51820"},
	}
}

func privateApp(id, group string, domains []string, ports []policy.PortRange, users ...string) api.TenantPrivateApp {
	return api.TenantPrivateApp{
		PrivateApp: policy.PrivateApp{ID: id, Name: strings.ToUpper(id), Domains: domains, Ports: ports, ConnectorGroup: group},
		Users:      users,
	}
}

func ztnaPolicy() api.TenantPolicy {
	p := examplePolicy()
	p.PrivateApps = []api.TenantPrivateApp{
		privateApp("intranet", "", []string{"*.acme.internal"}, []policy.PortRange{{From: 443}}),
		privateApp("db", "dc2", []string{"db.acme.internal"}, []policy.PortRange{{From: 5432}}, "u1"),
	}
	return p
}

func (e *env) createConnector(tenant, name, group string) api.AdminConnectorCreated {
	e.t.Helper()
	var c api.AdminConnectorCreated
	if err := json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/"+tenant+"/connectors", api.AdminConnectorRequest{Name: name, Group: group}, 201), &c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// enrollConnector enrolls with a fresh P-256 key and returns the response and client cert.
func (e *env) enrollConnector(key string) (api.ConnectorEnrollResponse, tls.Certificate) {
	e.t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resp, b := e.do(e.admin, "POST", "/v1/connector/enroll", api.ConnectorEnrollRequest{ProvisioningKey: key, CSRPEM: newCSR(e.t, k)}, nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("connector enroll: %d %s", resp.StatusCode, b)
	}
	var er api.ConnectorEnrollResponse
	if err := json.Unmarshal(b, &er); err != nil {
		e.t.Fatal(err)
	}
	return er, keyPair(e.t, er.CertificatePEM, k)
}

func (e *env) connectorConfig(c *http.Client, hdr map[string]string, query string) (int, string, api.ConnectorConfig) {
	e.t.Helper()
	resp, b := e.do(c, "GET", "/v1/connector/config"+query, nil, hdr)
	var cfg api.ConnectorConfig
	if resp.StatusCode == 200 {
		if err := json.Unmarshal(b, &cfg); err != nil {
			e.t.Fatal(err)
		}
	}
	return resp.StatusCode, resp.Header.Get("ETag"), cfg
}

func (e *env) peers(edge *http.Client) api.EdgePeers {
	e.t.Helper()
	resp, b := e.do(edge, "GET", "/v1/edge/peers", nil, nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("peers: %d %s", resp.StatusCode, b)
	}
	var p api.EdgePeers
	if err := json.Unmarshal(b, &p); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func TestConnectorEnroll(t *testing.T) {
	e := newEnvCfg(t, brokerEdgesCfg)
	e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/tenants/nope/connectors", api.AdminConnectorRequest{Name: "x"}, 404)
	e.adminDo("POST", "/v1/admin/tenants/acme/connectors", api.AdminConnectorRequest{}, 400)
	e.adminDo("POST", "/v1/admin/tenants/acme/connectors", api.AdminConnectorRequest{Name: "x", Group: "bad group"}, 400)
	if resp, _ := e.do(e.admin, "POST", "/v1/admin/tenants/acme/connectors", api.AdminConnectorRequest{Name: "x"}, nil); resp.StatusCode != 401 {
		t.Fatalf("no admin token: %d", resp.StatusCode)
	}
	created := e.createConnector("acme", "dc1-a", "")
	c := created.Connector
	if c.Group != "default" || c.TenantID != "acme" || c.Revoked || c.ID == "" || !strings.HasPrefix(created.ProvisioningKey, connectorKeyPrefix) || !c.LastSeen.IsZero() {
		t.Fatalf("created %+v", created)
	}
	var devKey api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1"}, 201), &devKey)

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tests := []struct {
		name string
		req  api.ConnectorEnrollRequest
		want int
	}{
		{"missing key", api.ConnectorEnrollRequest{CSRPEM: newCSR(t, p256)}, 400},
		{"device key is not a connector key", api.ConnectorEnrollRequest{ProvisioningKey: devKey.Key, CSRPEM: newCSR(t, p256)}, 400},
		{"bad CSR", api.ConnectorEnrollRequest{ProvisioningKey: created.ProvisioningKey, CSRPEM: "nope"}, 400},
		{"unknown key", api.ConnectorEnrollRequest{ProvisioningKey: connectorKeyPrefix + "AAAA", CSRPEM: newCSR(t, p256)}, 403},
		// A rejected key type does not consume the key (the next enrollment succeeds).
		{"P-384 key", api.ConnectorEnrollRequest{ProvisioningKey: created.ProvisioningKey, CSRPEM: newCSR(t, p384)}, 400},
	}
	for _, tc := range tests {
		if resp, b := e.do(e.admin, "POST", "/v1/connector/enroll", tc.req, nil); resp.StatusCode != tc.want {
			t.Errorf("%s: %d want %d: %s", tc.name, resp.StatusCode, tc.want, b)
		}
	}
	er, cert := e.enrollConnector(created.ProvisioningKey)
	if er.TenantID != "acme" || er.ConnectorID != c.ID || er.Group != "default" {
		t.Fatalf("enroll response %+v", er)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(er.CAPEM))
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("connector cert vs CAPEM: %v", err)
	}
	if len(cert.Leaf.URIs) != 1 || cert.Leaf.URIs[0].String() != pki.ConnectorURI("acme", c.ID).String() {
		t.Fatalf("URI %v", cert.Leaf.URIs)
	}
	if d := time.Until(cert.Leaf.NotAfter); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("validity %v", d)
	}
	// Single use.
	if resp, _ := e.do(e.admin, "POST", "/v1/connector/enroll", api.ConnectorEnrollRequest{ProvisioningKey: created.ProvisioningKey, CSRPEM: newCSR(t, p256)}, nil); resp.StatusCode != 403 {
		t.Fatalf("reused key: %d", resp.StatusCode)
	}
	// A revoked, never-enrolled connector cannot enroll.
	other := e.createConnector("acme", "dc1-b", "dc1")
	e.adminDo("POST", "/v1/admin/tenants/acme/connectors/"+other.Connector.ID+"/revoke", nil, 204)
	if resp, _ := e.do(e.admin, "POST", "/v1/connector/enroll", api.ConnectorEnrollRequest{ProvisioningKey: other.ProvisioningKey, CSRPEM: newCSR(t, p256)}, nil); resp.StatusCode != 403 {
		t.Fatalf("revoked connector enrolled: %d", resp.StatusCode)
	}
	e.adminDo("POST", "/v1/admin/tenants/acme/connectors/ghost/revoke", nil, 404)

	var list []api.AdminConnector
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/connectors", nil, 200), &list)
	if len(list) != 2 || list[0].ID != c.ID || list[0].Revoked || !list[1].Revoked || list[1].Group != "dc1" {
		t.Fatalf("list %+v", list)
	}
}

func TestConnectorConfig(t *testing.T) {
	e := newEnvCfg(t, brokerEdgesCfg)
	e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-3"}, 201)
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", ztnaPolicy(), 204)
	created := e.createConnector("acme", "dc", "")
	_, cert := e.enrollConnector(created.ProvisioningKey)
	conn := e.client(&cert)

	code, tag, cfg := e.connectorConfig(conn, nil, "")
	if code != 200 || tag != etag(cfg.Version) || cfg.Version == 0 {
		t.Fatalf("config %d %s %+v", code, tag, cfg)
	}
	// Only registered Edges with a BrokerAddr; only the apps of group "default", no Users.
	if len(cfg.Edges) != 1 || cfg.Edges[0].ID != "edge-1" || cfg.Edges[0].BrokerAddr != "edge:8444" {
		t.Fatalf("edges %+v", cfg.Edges)
	}
	if len(cfg.Apps) != 1 || cfg.Apps[0].ID != "intranet" || cfg.Apps[0].ConnectorGroup != "default" {
		t.Fatalf("apps %+v", cfg.Apps)
	}
	if code, _, _ := e.connectorConfig(conn, map[string]string{"If-None-Match": tag}, ""); code != 304 {
		t.Fatalf("If-None-Match: %d", code)
	}
	if code, _, _ := e.connectorConfig(conn, map[string]string{"If-None-Match": tag}, "?wait=1"); code != 304 {
		t.Fatalf("long-poll timeout: %d", code)
	}
	if code, _, _ := e.connectorConfig(conn, nil, "?wait=x"); code != 400 {
		t.Fatalf("bad wait: %d", code)
	}
	// Stable while nothing changes.
	if _, tag2, _ := e.connectorConfig(conn, nil, ""); tag2 != tag {
		t.Fatalf("version moved without a change: %s -> %s", tag, tag2)
	}

	// Long-poll wakes on a tenant policy change; the version increases even when this
	// group's apps are unchanged.
	type result struct {
		code int
		cfg  api.ConnectorConfig
	}
	longPoll := func(tag string) <-chan result {
		ch := make(chan result, 1)
		go func() {
			req, _ := http.NewRequest("GET", e.srv.URL+"/v1/connector/config?wait=30", nil)
			req.Header.Set("If-None-Match", tag)
			r, err := conn.Do(req)
			if err != nil {
				ch <- result{}
				return
			}
			defer r.Body.Close()
			var c api.ConnectorConfig
			_ = json.NewDecoder(r.Body).Decode(&c)
			ch <- result{r.StatusCode, c}
		}()
		return ch
	}
	waitPolls := func(n int) {
		waitUntil(t, func() bool {
			e.s.polls.mu.Lock()
			defer e.s.polls.mu.Unlock()
			return e.s.polls.n[connectorPollKey(created.Connector.ID)] == n
		})
	}
	ch := longPoll(tag)
	waitPolls(1)
	p := ztnaPolicy()
	p.Rules = p.Rules[:1]
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)
	var r result
	select {
	case r = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll did not wake on policy change")
	}
	if r.code != 200 || r.cfg.Version <= cfg.Version || len(r.cfg.Apps) != 1 {
		t.Fatalf("after policy change %+v (was %d)", r, cfg.Version)
	}
	cfg = r.cfg

	// Registering a broker Edge wakes the long-poll and adds it.
	ch = longPoll(etag(cfg.Version))
	waitPolls(1)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-2"}, 201)
	select {
	case r = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll did not wake on edge registration")
	}
	if r.code != 200 || r.cfg.Version <= cfg.Version || len(r.cfg.Edges) != 2 {
		t.Fatalf("after edge change %+v", r)
	}
	cfg = r.cfg

	// Per-connector long-poll cap, as for device snapshots.
	var wg sync.WaitGroup
	codes := make(chan int, maxLongPollsPerDev)
	for range maxLongPollsPerDev {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", e.srv.URL+"/v1/connector/config?wait=2", nil)
			req.Header.Set("If-None-Match", etag(cfg.Version))
			if r, err := conn.Do(req); err == nil {
				r.Body.Close()
				codes <- r.StatusCode
			}
		}()
	}
	waitPolls(maxLongPollsPerDev)
	if code, _, _ := e.connectorConfig(conn, map[string]string{"If-None-Match": etag(cfg.Version)}, "?wait=2"); code != http.StatusTooManyRequests {
		t.Fatalf("third long-poll: %d", code)
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 304 {
			t.Fatalf("capped long-poll: %d", c)
		}
	}
}

func TestConnectorRenewAndRevoke(t *testing.T) {
	e := newEnvCfg(t, brokerEdgesCfg)
	e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	ec := e.edgeCert()
	edge := e.client(&ec)
	created := e.createConnector("acme", "dc", "dc1")
	id := created.Connector.ID
	pending := e.createConnector("acme", "never-enrolled", "dc1")
	if p := e.peers(edge); p.Connectors == nil || len(p.Connectors) != 0 {
		t.Fatalf("unenrolled connector listed: %+v", p.Connectors)
	}
	_, oldCert := e.enrollConnector(created.ProvisioningKey)
	old := e.client(&oldCert)
	if p := e.peers(edge); len(p.Connectors) != 1 || p.Connectors[0] != (api.EdgeConnector{ConnectorID: id, TenantID: "acme", Group: "dc1"}) {
		t.Fatalf("peers connectors %+v", p.Connectors)
	}

	oldKey := oldCert.PrivateKey.(*ecdsa.PrivateKey)
	if resp, _ := e.do(old, "POST", "/v1/connector/renew", api.RenewRequest{CSRPEM: newCSR(t, oldKey)}, nil); resp.StatusCode != 400 {
		t.Fatalf("same key: %d", resp.StatusCode)
	}
	if resp, _ := e.do(old, "POST", "/v1/connector/renew", api.RenewRequest{CSRPEM: "x"}, nil); resp.StatusCode != 400 {
		t.Fatalf("bad CSR: %d", resp.StatusCode)
	}
	if resp, _ := e.do(e.admin, "POST", "/v1/connector/renew", api.RenewRequest{}, nil); resp.StatusCode != 401 {
		t.Fatalf("no cert: %d", resp.StatusCode)
	}
	renew := func(c *http.Client, want int) tls.Certificate {
		t.Helper()
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		resp, body := e.do(c, "POST", "/v1/connector/renew", api.RenewRequest{CSRPEM: newCSR(t, k)}, nil)
		if resp.StatusCode != want {
			t.Fatalf("renew: %d want %d: %s", resp.StatusCode, want, body)
		}
		if want != 200 {
			return tls.Certificate{}
		}
		var rr api.RenewResponse
		_ = json.Unmarshal(body, &rr)
		cert := keyPair(t, rr.CertificatePEM, k)
		if got := cert.Leaf.URIs[0].String(); got != pki.ConnectorURI("acme", id).String() {
			t.Fatalf("renewed URI %s", got)
		}
		return cert
	}
	cfgCode := func(c *http.Client) int {
		t.Helper()
		code, _, _ := e.connectorConfig(c, nil, "")
		return code
	}
	lost := renew(old, 200) // response lost: the connector keeps the old cert
	if code := cfgCode(old); code != 403 {
		t.Fatalf("superseded cert on config: %d", code)
	}
	newCert := renew(old, 200) // retry with the superseded cert
	if code := cfgCode(e.client(&lost)); code != 403 {
		t.Fatalf("undelivered cert accepted: %d", code)
	}
	cur := e.client(&newCert)
	if code := cfgCode(cur); code != 200 {
		t.Fatalf("renewed cert: %d", code)
	}
	newest := renew(cur, 200)
	renew(old, 403) // superseded twice

	// last_seen from the Edge session report; unknown IDs are ignored.
	if resp, _ := e.do(edge, "POST", "/v1/edge/sessions", EdgeSessions{DeviceIDs: []string{}, ConnectorIDs: []string{id, "ghost"}}, nil); resp.StatusCode != 204 {
		t.Fatalf("sessions: %d", resp.StatusCode)
	}
	var list []api.AdminConnector
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/connectors", nil, 200), &list)
	if len(list) != 2 || list[0].ID != id || list[0].LastSeen.IsZero() || !list[1].LastSeen.IsZero() || list[1].ID != pending.Connector.ID {
		t.Fatalf("last seen %+v", list)
	}

	// Revocation: refused everywhere, and Edges drop it at the next peer sync.
	nc := e.client(&newest)
	e.adminDo("POST", "/v1/admin/tenants/acme/connectors/"+id+"/revoke", nil, 204)
	if code := cfgCode(nc); code != 403 {
		t.Fatalf("revoked connector config: %d", code)
	}
	renew(nc, 403)
	if p := e.peers(edge); len(p.Connectors) != 0 {
		t.Fatalf("revoked connector still a peer: %+v", p.Connectors)
	}
}

// A revoked connector's in-flight long-poll ends with 403.
func TestConnectorRevokeEndsLongPoll(t *testing.T) {
	e := newEnvCfg(t, brokerEdgesCfg)
	e.setupTenant(1)
	created := e.createConnector("acme", "dc", "")
	_, cert := e.enrollConnector(created.ProvisioningKey)
	conn := e.client(&cert)
	_, tag, _ := e.connectorConfig(conn, nil, "")
	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", e.srv.URL+"/v1/connector/config?wait=30", nil)
		req.Header.Set("If-None-Match", tag)
		r, err := conn.Do(req)
		if err != nil {
			done <- 0
			return
		}
		r.Body.Close()
		done <- r.StatusCode
	}()
	waitUntil(t, func() bool {
		e.s.polls.mu.Lock()
		defer e.s.polls.mu.Unlock()
		return e.s.polls.n[connectorPollKey(created.Connector.ID)] == 1
	})
	e.adminDo("POST", "/v1/admin/tenants/acme/connectors/"+created.Connector.ID+"/revoke", nil, 204)
	select {
	case code := <-done:
		if code != 403 {
			t.Fatalf("long-poll after revoke: %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll not ended by revocation")
	}
}

func TestCertRoleIsolation(t *testing.T) {
	e := newEnvCfg(t, brokerEdgesCfg)
	key := e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)
	er, devCert := e.enroll(key)
	_, connCert := e.enrollConnector(e.createConnector("acme", "dc", "").ProvisioningKey)
	dev, conn := e.client(&devCert), e.client(&connCert)
	ec := e.edgeCert()
	edge := e.client(&ec)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	renewBody := api.RenewRequest{CSRPEM: newCSR(t, k)}

	type call struct {
		method, path string
		body         any
	}
	deviceAndEdgeRoutes := []call{
		{"GET", "/v1/snapshot", nil},
		{"GET", "/v1/snapshot?wait=1", nil},
		{"GET", "/v1/self/rules", nil},
		{"PUT", "/v1/self/rules", api.UserRules{}},
		{"POST", "/v1/renew", renewBody},
		{"POST", "/v1/decide", api.DecideRequest{Flow: policy.Flow{Protocol: "tcp", DstIP: "1.1.1.1", DstPort: 443}}},
		{"POST", "/v1/decide?device=" + er.DeviceID, api.DecideRequest{}},
		{"POST", "/v1/flows", api.FlowBatch{}},
		{"GET", "/v1/edge/peers", nil},
		{"POST", "/v1/edge/sessions", EdgeSessions{}},
	}
	for _, c := range deviceAndEdgeRoutes {
		if resp, b := e.do(conn, c.method, c.path, c.body, nil); resp.StatusCode != 403 {
			t.Errorf("connector cert on %s %s: %d %s", c.method, c.path, resp.StatusCode, b)
		}
	}
	connectorRoutes := []call{
		{"GET", "/v1/connector/config", nil},
		{"GET", "/v1/connector/config?wait=1", nil},
		{"POST", "/v1/connector/renew", renewBody},
	}
	for _, c := range connectorRoutes {
		for name, cl := range map[string]*http.Client{"device": dev, "edge": edge} {
			if resp, b := e.do(cl, c.method, c.path, c.body, nil); resp.StatusCode != 403 {
				t.Errorf("%s cert on %s %s: %d %s", name, c.method, c.path, resp.StatusCode, b)
			}
		}
		if resp, _ := e.do(e.admin, c.method, c.path, c.body, nil); resp.StatusCode != 401 {
			t.Errorf("no cert on %s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
	// Admin routes ignore client certs: a connector cert is no admin credential.
	if resp, _ := e.do(conn, "GET", "/v1/admin/tenants", nil, nil); resp.StatusCode != 401 {
		t.Errorf("connector cert on admin: %d", resp.StatusCode)
	}
}

func TestPrivateAppEntitlement(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(2)
	e.adminDo("POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u2", Email: "U2@Acme.example"}, 201)
	var k2 api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u2"}, 201), &k2)

	_, c1 := e.enroll(key)
	_, c2 := e.enroll(k2.Key)
	p := examplePolicy()
	p.PrivateApps = []api.TenantPrivateApp{
		privateApp("everyone", "", []string{"*.acme.internal"}, []policy.PortRange{{From: 443}}),
		privateApp("by-id", "dc1", []string{"hr.example"}, []policy.PortRange{{From: 443}}, "u1"),
		privateApp("by-email", "dc1", []string{"git.example"}, []policy.PortRange{{From: 22}}, "u2@acme.example"),
		privateApp("nobody", "dc1", []string{"secret.example"}, []policy.PortRange{{From: 443}}, "u9", "x@y"),
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)

	// Group defaulted on PUT; Users kept in the tenant policy.
	var got api.TenantPolicy
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/policy", nil, 200), &got)
	if got.PrivateApps[0].ConnectorGroup != "default" || got.PrivateApps[1].Users[0] != "u1" {
		t.Fatalf("stored apps %+v", got.PrivateApps)
	}

	snapApps := func(cert tls.Certificate) ([]string, *policy.Snapshot, []byte) {
		t.Helper()
		resp, body := e.do(e.client(&cert), "GET", "/v1/snapshot", nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("snapshot %d", resp.StatusCode)
		}
		var env policy.Envelope
		_ = json.Unmarshal(body, &env)
		s, err := policy.Verify(&env, e.keys)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, a := range s.PrivateApps {
			ids = append(ids, a.ID)
		}
		return ids, s, env.Payload
	}
	tests := []struct {
		name string
		cert tls.Certificate
		want string
	}{
		{"u1 by ID", c1, "everyone,by-id"},
		{"u2 by email, case-insensitive", c2, "everyone,by-email"},
	}
	for _, tc := range tests {
		ids, s, payload := snapApps(tc.cert)
		if strings.Join(ids, ",") != tc.want {
			t.Errorf("%s: apps %v want %s", tc.name, ids, tc.want)
		}
		if strings.Contains(string(payload), `"users"`) {
			t.Errorf("%s: entitlement list leaked into the snapshot", tc.name)
		}
		c, err := policy.Compile(s)
		if err != nil {
			t.Fatal(err)
		}
		if d := c.Evaluate(policy.Flow{Protocol: "tcp", DstIP: "100.96.0.1", DstPort: 443, Domain: "wiki.acme.internal"}, true); d.Layer != policy.LayerZTNA || d.RuleID != "ztna:everyone" {
			t.Errorf("%s: decision %+v", tc.name, d)
		}
	}
}

func TestPrivateAppValidation(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)
	fieldOf := func(b []byte) string {
		var eb errorBody
		_ = json.Unmarshal(b, &eb)
		return eb.Field
	}
	ok := func() api.TenantPrivateApp {
		return privateApp("app", "", []string{"*.acme.internal"}, []policy.PortRange{{From: 443}})
	}
	tests := []struct {
		name  string
		mod   func(*api.TenantPrivateApp)
		field string
	}{
		{"bad id", func(a *api.TenantPrivateApp) { a.ID = "../x" }, "privateApps[1].id"},
		{"empty id", func(a *api.TenantPrivateApp) { a.ID = "" }, "privateApps[1].id"},
		{"duplicate id", func(a *api.TenantPrivateApp) { a.ID = "first" }, "privateApps[1].id"},
		{"no domains", func(a *api.TenantPrivateApp) { a.Domains = nil }, "privateApps[1].domains"},
		{"bad domain", func(a *api.TenantPrivateApp) { a.Domains = []string{"ok.example", "bad domain"} }, "privateApps[1].domains[1]"},
		{"no ports", func(a *api.TenantPrivateApp) { a.Ports = nil }, "privateApps[1].ports"},
		{"port zero", func(a *api.TenantPrivateApp) { a.Ports = []policy.PortRange{{From: 0, To: 10}} }, "privateApps[1].ports[0]"},
		{"bad port range", func(a *api.TenantPrivateApp) { a.Ports = []policy.PortRange{{From: 10, To: 1}} }, "privateApps[1].ports[0]"},
		{"bad group", func(a *api.TenantPrivateApp) { a.ConnectorGroup = "a/b" }, "privateApps[1].connectorGroup"},
		{"empty user", func(a *api.TenantPrivateApp) { a.Users = []string{" "} }, "privateApps[1].users[0]"},
	}
	for _, tc := range tests {
		p := examplePolicy()
		first := ok()
		first.ID = "first"
		app := ok()
		tc.mod(&app)
		p.PrivateApps = []api.TenantPrivateApp{first, app}
		if got := fieldOf(e.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 400)); got != tc.field {
			t.Errorf("%s: field %q want %q", tc.name, got, tc.field)
		}
	}
}

func TestAdminListTenantsAndUsers(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	var ts []api.AdminTenant
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants", nil, 200), &ts)
	if len(ts) != 2 || ts[0] != (api.AdminTenant{ID: "acme", Name: "Acme"}) || ts[1].ID != "beta" {
		t.Fatalf("tenants %+v", ts)
	}
	var us []api.AdminUser
	_ = json.Unmarshal(e.adminDo("GET", "/v1/admin/tenants/acme/users", nil, 200), &us)
	if len(us) != 1 || us[0].ID != "u1" || us[0].Email != "u1@acme" {
		t.Fatalf("users %+v", us)
	}
	if b := e.adminDo("GET", "/v1/admin/tenants/beta/users", nil, 200); strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("empty users: %s", b)
	}
	e.adminDo("GET", "/v1/admin/tenants/nope/users", nil, 404)
	if b := e.adminDo("GET", "/v1/admin/tenants/beta/connectors", nil, 200); strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("empty connectors: %s", b)
	}
}

func TestAdminPortal(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "<!doctype html><title>portal</title>")
	write("main.dart.js", "console.log(1)")
	write("canvaskit/canvaskit.wasm", "\x00asm")
	write("assets/AssetManifest.json", "{}")
	e := newEnvCfg(t, func(c *Config) { c.PortalDir = dir })

	// e.admin presents no client certificate, like a browser.
	tests := []struct {
		method, path string
		code         int
		body         string // substring
		ctype        string // prefix
	}{
		{"GET", "/admin/", 200, "<title>portal", "text/html"},
		{"GET", "/admin/tenants/acme/connectors", 200, "<title>portal", "text/html"}, // client-side route
		{"GET", "/admin/assets", 200, "<title>portal", "text/html"},                  // directory: never listed
		{"GET", "/admin/main.dart.js", 200, "console.log", "text/javascript"},
		{"GET", "/admin/canvaskit/canvaskit.wasm", 200, "asm", "application/wasm"},
		{"GET", "/admin/assets/AssetManifest.json", 200, "{}", "application/json"},
		{"GET", "/admin/missing.js", 404, "", ""},
		{"GET", "/admin/../cp.db", 404, "", ""},
		{"GET", "/admin/%2e%2e/cp.db", 404, "", ""},
		{"HEAD", "/admin/", 200, "", "text/html"},
		{"POST", "/admin/", 405, "", ""},
	}
	noRedirect := e.client(nil)
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, tc := range tests {
		resp, body := e.do(noRedirect, tc.method, tc.path, nil, nil)
		if resp.StatusCode != tc.code || !strings.Contains(string(body), tc.body) || !strings.HasPrefix(resp.Header.Get("Content-Type"), tc.ctype) {
			t.Errorf("%s %s: %d %q %q", tc.method, tc.path, resp.StatusCode, resp.Header.Get("Content-Type"), body)
			continue
		}
		h := resp.Header
		if h.Get("Content-Security-Policy") != portalCSP || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s: security headers %v", tc.method, tc.path, h)
		}
	}
	if !strings.Contains(portalCSP, "script-src 'self' 'wasm-unsafe-eval'") || !strings.Contains(portalCSP, "frame-ancestors 'none'") {
		t.Fatal("CSP")
	}
	if resp, _ := e.do(noRedirect, "GET", "/admin", nil, nil); resp.StatusCode != 301 || resp.Header.Get("Location") != "/admin/" {
		t.Fatalf("/admin redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A browser without a client certificate can call the admin API with the Bearer token.
	if resp, _ := e.do(noRedirect, "GET", "/v1/admin/tenants", nil, map[string]string{"Authorization": "Bearer " + testToken}); resp.StatusCode != 200 || resp.TLS.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("admin API without client cert: %d", resp.StatusCode)
	}

	// Without -portal-dir there is no /admin/.
	plain := newEnv(t)
	if resp, _ := plain.do(plain.admin, "GET", "/admin/", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("portal without dir: %d", resp.StatusCode)
	}
}
