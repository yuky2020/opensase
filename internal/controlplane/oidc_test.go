package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

type fakeIDP struct {
	server       *httptest.Server
	privKey      *ecdsa.PrivateKey
	mu           sync.Mutex
	codes        map[string]fakeAuthSession
	tamperNonce  bool
	customGroups []string
	customEmail  string
}

type fakeAuthSession struct {
	challenge string
	nonce     string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeIDP{
		privKey: key,
		codes:   make(map[string]fakeAuthSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/auth", f.handleAuth)
	mux.HandleFunc("/token", f.handleToken)

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIDP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]string{
		"issuer":                 f.server.URL,
		"authorization_endpoint": f.server.URL + "/auth",
		"token_endpoint":         f.server.URL + "/token",
		"jwks_uri":               f.server.URL + "/jwks",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIDP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	var xBuf, yBuf [32]byte
	f.privKey.X.FillBytes(xBuf[:])
	f.privKey.Y.FillBytes(yBuf[:])

	jwks := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "fake-key-1",
				"alg": "ES256",
				"use": "sig",
				"x":   base64.RawURLEncoding.EncodeToString(xBuf[:]),
				"y":   base64.RawURLEncoding.EncodeToString(yBuf[:]),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (f *fakeIDP) handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	nonce := q.Get("nonce")
	redirectURI := q.Get("redirect_uri")

	code := "code-" + state
	f.mu.Lock()
	f.codes[code] = fakeAuthSession{challenge: challenge, nonce: nonce}
	f.mu.Unlock()

	target := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	http.Redirect(w, r, target, http.StatusFound)
}

func (f *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	verifier := r.Form.Get("code_verifier")

	f.mu.Lock()
	sess, ok := f.codes[code]
	tamperNonce := f.tamperNonce
	groups := f.customGroups
	email := f.customEmail
	f.mu.Unlock()

	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	h := sha256.Sum256([]byte(verifier))
	gotChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	if gotChallenge != sess.challenge {
		http.Error(w, "pkce challenge mismatch", http.StatusBadRequest)
		return
	}

	nonce := sess.nonce
	if tamperNonce {
		nonce = "wrong-nonce"
	}
	if groups == nil {
		groups = []string{"super-admins"}
	}
	if email == "" {
		email = "alice@example.com"
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":    f.server.URL,
		"sub":    "sub-alice-1234",
		"aud":    r.Form.Get("client_id"),
		"exp":    now + 3600,
		"iat":    now,
		"nonce":  nonce,
		"email":  email,
		"groups": groups,
	}

	headerJSON := []byte(`{"alg":"ES256","typ":"JWT","kid":"fake-key-1"}`)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	sigHash := sha256.Sum256([]byte(signingInput))
	rInt, sInt, err := ecdsa.Sign(rand.Reader, f.privKey, sigHash[:])
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	var sigBytes [64]byte
	rInt.FillBytes(sigBytes[:32])
	sInt.FillBytes(sigBytes[32:])

	idToken := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes[:])
	resp := map[string]string{
		"id_token":   idToken,
		"token_type": "Bearer",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func noRedirectClient(e *env) *http.Client {
	c := e.client(nil)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

func TestOIDCAdminConfigCRUD(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)

	// Create a viewer token and a policy-editor token for role enforcement check.
	var viewerCred api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "v", Role: "viewer"}, 201), &viewerCred)

	var editorCred api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/admin-tokens", api.AdminTokenRequest{Name: "pe", Role: "policy-editor"}, 201), &editorCred)

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "viewer cannot PUT oidc",
			run: func(t *testing.T) {
				req := api.TenantOIDC{
					Issuer:       "https://idp.example.com",
					ClientID:     "client-1",
					ClientSecret: "secret-1",
					GroupRoles:   map[string]string{"admins": "admin"},
				}
				resp, _ := e.do(e.admin, "PUT", "/v1/admin/tenants/acme/oidc", req, map[string]string{"Authorization": "Bearer " + viewerCred.Token})
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("expected 403 Forbidden for viewer PUT, got %d", resp.StatusCode)
				}
			},
		},
		{
			name: "policy editor cannot PUT oidc",
			run: func(t *testing.T) {
				req := api.TenantOIDC{
					Issuer:       "https://idp.example.com",
					ClientID:     "client-1",
					ClientSecret: "secret-1",
					GroupRoles:   map[string]string{"admins": "admin"},
				}
				resp, _ := e.do(e.admin, "PUT", "/v1/admin/tenants/acme/oidc", req, map[string]string{"Authorization": "Bearer " + editorCred.Token})
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("expected 403 Forbidden for policy-editor PUT, got %d", resp.StatusCode)
				}
			},
		},
		{
			name: "validation on PUT",
			run: func(t *testing.T) {
				badConfigs := []struct {
					desc string
					cfg  api.TenantOIDC
				}{
					{"empty issuer", api.TenantOIDC{ClientID: "c", GroupRoles: map[string]string{"g": "admin"}}},
					{"insecure http issuer", api.TenantOIDC{Issuer: "http://insecure.example.com", ClientID: "c", GroupRoles: map[string]string{"g": "admin"}}},
					{"empty client ID", api.TenantOIDC{Issuer: "https://idp.example.com", GroupRoles: map[string]string{"g": "admin"}}},
					{"empty group roles", api.TenantOIDC{Issuer: "https://idp.example.com", ClientID: "c", GroupRoles: map[string]string{}}},
					{"invalid group role", api.TenantOIDC{Issuer: "https://idp.example.com", ClientID: "c", GroupRoles: map[string]string{"g": "super-user"}}},
				}
				for _, bc := range badConfigs {
					resp, _ := e.do(e.admin, "PUT", "/v1/admin/tenants/acme/oidc", bc.cfg, map[string]string{"Authorization": "Bearer " + testToken})
					if resp.StatusCode != http.StatusBadRequest {
						t.Errorf("%s: expected 400, got %d", bc.desc, resp.StatusCode)
					}
				}
			},
		},
		{
			name: "admin PUT and GET - secret never returned",
			run: func(t *testing.T) {
				cfg := api.TenantOIDC{
					Issuer:       "https://idp.example.com",
					ClientID:     "client-123",
					ClientSecret: "super-secret-xyz",
					GroupRoles: map[string]string{
						"admins": "admin",
					},
				}
				raw := e.adminDo("PUT", "/v1/admin/tenants/acme/oidc", cfg, 200)
				if bytes.Contains(raw, []byte("super-secret-xyz")) {
					t.Fatal("PUT response contains client secret")
				}
				var putResp api.TenantOIDC
				_ = json.Unmarshal(raw, &putResp)
				if !putResp.HasSecret || putResp.ClientSecret != "" {
					t.Fatalf("unexpected put response: %+v", putResp)
				}
				if !strings.HasSuffix(putResp.RedirectURL, "/v1/auth/oidc/callback") {
					t.Fatalf("unexpected redirect URL: %s", putResp.RedirectURL)
				}

				// GET config
				getRaw := e.adminDo("GET", "/v1/admin/tenants/acme/oidc", nil, 200)
				if bytes.Contains(getRaw, []byte("super-secret-xyz")) {
					t.Fatal("GET response contains client secret")
				}
				var getResp api.TenantOIDC
				_ = json.Unmarshal(getRaw, &getResp)
				if !getResp.HasSecret || getResp.ClientSecret != "" || getResp.ClientID != "client-123" {
					t.Fatalf("unexpected get response: %+v", getResp)
				}

				// PUT without secret keeps the stored secret
				updateCfg := api.TenantOIDC{
					Issuer:   "https://idp.example.com",
					ClientID: "client-123",
					GroupRoles: map[string]string{
						"admins": "admin",
						"devs":   "viewer",
					},
				}
				rawUpdate := e.adminDo("PUT", "/v1/admin/tenants/acme/oidc", updateCfg, 200)
				var updateResp api.TenantOIDC
				_ = json.Unmarshal(rawUpdate, &updateResp)
				if !updateResp.HasSecret {
					t.Fatal("expected stored secret to be retained when PUT has empty secret")
				}

				// DELETE
				e.adminDo("DELETE", "/v1/admin/tenants/acme/oidc", nil, 204)
				e.adminDo("GET", "/v1/admin/tenants/acme/oidc", nil, 404)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestOIDCLoginAndCallback(t *testing.T) {
	idp := newFakeIDP(t)
	e := newEnv(t)
	e.setupTenant(1)

	// Configure OIDC for tenant acme pointing to fakeIDP.
	oidcCfg := api.TenantOIDC{
		Issuer:       idp.server.URL,
		ClientID:     "portal-app",
		ClientSecret: "client-secret-123",
		GroupRoles: map[string]string{
			"super-admins": "admin",
			"policy-devs":  "policy-editor",
			"observers":    "viewer",
		},
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/oidc", oidcCfg, 200)

	cli := noRedirectClient(e)

	// 1. GET /v1/auth/oidc/acme/login -> 302 to IdP authorize URL
	resp, _ := e.do(cli, "GET", "/v1/auth/oidc/acme/login", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("login: expected Cache-Control: no-store, got %q", cc)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("login: missing Location header")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	state := u.Query().Get("state")
	challenge := u.Query().Get("code_challenge")
	nonce := u.Query().Get("nonce")
	if state == "" || challenge == "" || nonce == "" {
		t.Fatalf("login redirect missing required parameters: %s", loc)
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method must be S256, got %s", u.Query().Get("code_challenge_method"))
	}

	// 2. Simulate IdP authorization: fetch IdP auth endpoint which records code and redirects back
	idpAuthResp, _ := cli.Get(loc)
	if idpAuthResp.StatusCode != http.StatusFound {
		t.Fatalf("idp auth: expected 302, got %d", idpAuthResp.StatusCode)
	}
	callbackLoc := idpAuthResp.Header.Get("Location")
	cbURL, err := url.Parse(callbackLoc)
	if err != nil {
		t.Fatalf("parse callback loc: %v", err)
	}
	code := cbURL.Query().Get("code")

	// 3. Callback -> 303 with token in fragment
	cbResp, _ := e.do(cli, "GET", "/v1/auth/oidc/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), nil, nil)
	if cbResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: expected 303 See Other, got %d", cbResp.StatusCode)
	}
	if cc := cbResp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("callback: expected Cache-Control: no-store, got %q", cc)
	}
	if rp := cbResp.Header.Get("Referrer-Policy"); rp != "no-referrer" {
		t.Fatalf("callback: expected Referrer-Policy: no-referrer, got %q", rp)
	}
	dest := cbResp.Header.Get("Location")
	if !strings.HasPrefix(dest, "/admin/#/oidc-signin?token=") {
		t.Fatalf("callback: unexpected destination %s", dest)
	}
	tokenEscaped := strings.TrimPrefix(dest, "/admin/#/oidc-signin?token=")
	token, err := url.QueryUnescape(tokenEscaped)
	if err != nil {
		t.Fatalf("unescape token: %v", err)
	}
	if !strings.HasPrefix(token, "osa_") {
		t.Fatalf("minted token should have osa_ prefix, got %s", token)
	}

	// 4. Token works on /v1/admin/whoami and role is admin
	whoamiRaw := e.doAuth(token, "GET", "/v1/admin/whoami", nil, 200)
	var whoami api.AdminIdentity
	_ = json.Unmarshal(whoamiRaw, &whoami)
	if whoami.Role != "tenant" || whoami.TenantID != "acme" || whoami.TenantRole != "admin" {
		t.Fatalf("unexpected whoami: %+v", whoami)
	}

	// Check token expiry is about 1 hour
	tokens, err := e.s.cfg.Store.ListAdminTokens(context.Background(), "acme")
	if err != nil || len(tokens) == 0 {
		t.Fatalf("list admin tokens: %v", err)
	}
	found := false
	for _, tok := range tokens {
		if tok.Name == "oidc:alice@example.com" {
			found = true
			rem := time.Until(tok.ExpiresAt)
			if rem < 55*time.Minute || rem > 61*time.Minute {
				t.Fatalf("token validity not ~1 hour: %v", rem)
			}
		}
	}
	if !found {
		t.Fatal("minted oidc token not found in store")
	}

	// 5. Replayed state -> 400
	replayedResp, _ := e.do(cli, "GET", "/v1/auth/oidc/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), nil, nil)
	if replayedResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed state: expected 400, got %d", replayedResp.StatusCode)
	}

	// 6. Unknown state -> 400
	unknownResp, _ := e.do(cli, "GET", "/v1/auth/oidc/callback?state=unknown-random-state&code=some-code", nil, nil)
	if unknownResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown state: expected 400, got %d", unknownResp.StatusCode)
	}

	// 7. User without mapped group -> 403 and audited
	idp.mu.Lock()
	idp.customGroups = []string{"unmapped-group"}
	idp.customEmail = "unmapped@example.com"
	idp.mu.Unlock()

	resp2, _ := e.do(cli, "GET", "/v1/auth/oidc/acme/login", nil, nil)
	u2, _ := url.Parse(resp2.Header.Get("Location"))
	state2 := u2.Query().Get("state")
	idpResp2, _ := cli.Get(resp2.Header.Get("Location"))
	uCB2, _ := url.Parse(idpResp2.Header.Get("Location"))
	code2 := uCB2.Query().Get("code")

	deniedResp, _ := e.do(cli, "GET", "/v1/auth/oidc/callback?state="+url.QueryEscape(state2)+"&code="+url.QueryEscape(code2), nil, nil)
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("unmapped group: expected 403, got %d", deniedResp.StatusCode)
	}

	// 8. Wrong nonce from IdP -> error and no token
	idp.mu.Lock()
	idp.tamperNonce = true
	idp.customGroups = []string{"super-admins"}
	idp.customEmail = "tamper@example.com"
	idp.mu.Unlock()

	resp3, _ := e.do(cli, "GET", "/v1/auth/oidc/acme/login", nil, nil)
	u3, _ := url.Parse(resp3.Header.Get("Location"))
	state3 := u3.Query().Get("state")
	idpResp3, _ := cli.Get(resp3.Header.Get("Location"))
	uCB3, _ := url.Parse(idpResp3.Header.Get("Location"))
	code3 := uCB3.Query().Get("code")

	nonceResp, _ := e.do(cli, "GET", "/v1/auth/oidc/callback?state="+url.QueryEscape(state3)+"&code="+url.QueryEscape(code3), nil, nil)
	if nonceResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered nonce: expected 400, got %d", nonceResp.StatusCode)
	}

	// 9. Audit contains "oidc.login" with email and no token text
	auditRaw := e.adminDo("GET", "/v1/admin/tenants/acme/audit", nil, 200)
	if !bytes.Contains(auditRaw, []byte("oidc.login")) {
		t.Fatalf("audit missing oidc.login: %s", auditRaw)
	}
	if !bytes.Contains(auditRaw, []byte("alice@example.com")) {
		t.Fatalf("audit missing user email: %s", auditRaw)
	}
	if bytes.Contains(auditRaw, []byte(token)) {
		t.Fatal("audit contains raw token text")
	}
	if !bytes.Contains(auditRaw, []byte("oidc.login.denied")) {
		t.Fatalf("audit missing oidc.login.denied: %s", auditRaw)
	}
}

func (e *env) doAuth(tok, method, path string, body any, want int) []byte {
	e.t.Helper()
	resp, b := e.do(e.admin, method, path, body, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: status %d want %d: %s", method, path, resp.StatusCode, want, b)
	}
	return b
}
