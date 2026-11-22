package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeServerState struct {
	mu           sync.Mutex
	codes        map[string]fakeCodeEntry
	jwksHitCount int
}

type fakeCodeEntry struct {
	challenge string
	idToken   string
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
	}
	hJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	p1 := base64.RawURLEncoding.EncodeToString(hJSON)
	p2 := base64.RawURLEncoding.EncodeToString(cJSON)
	signingInput := p1 + "." + p2
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	p3 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + p3
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
	}
	hJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	p1 := base64.RawURLEncoding.EncodeToString(hJSON)
	p2 := base64.RawURLEncoding.EncodeToString(cJSON)
	signingInput := p1 + "." + p2
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	sigBytes := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sigBytes[32-len(rb):32], rb)
	copy(sigBytes[64-len(sb):64], sb)
	p3 := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + p3
}

func signNone(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "none",
		"typ": "JWT",
	}
	hJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	p1 := base64.RawURLEncoding.EncodeToString(hJSON)
	p2 := base64.RawURLEncoding.EncodeToString(cJSON)
	return p1 + "." + p2 + "."
}

func signHS256(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	hJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	p1 := base64.RawURLEncoding.EncodeToString(hJSON)
	p2 := base64.RawURLEncoding.EncodeToString(cJSON)
	signingInput := p1 + "." + p2
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	p3 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + p3
}

func tamperPart(part string) string {
	if len(part) == 0 {
		return "x"
	}
	// Change the first character: the last one may carry only padding bits.
	b := []byte(part)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func setupFakeIDP(t *testing.T) (*httptest.Server, *fakeServerState, *rsa.PrivateKey, string, *ecdsa.PrivateKey, string) {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaKid := "rsa-test-key-1"

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	ecKid := "ec-test-key-1"

	state := &fakeServerState{
		codes: make(map[string]fakeCodeEntry),
	}

	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		state.jwksHitCount++
		state.mu.Unlock()

		xb := make([]byte, 32)
		yb := make([]byte, 32)
		ecX := ecKey.X.Bytes()
		ecY := ecKey.Y.Bytes()
		copy(xb[32-len(ecX):], ecX)
		copy(yb[32-len(ecY):], ecY)

		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": rsaKid,
					"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
				},
				{
					"kty": "EC",
					"use": "sig",
					"alg": "ES256",
					"crv": "P-256",
					"kid": ecKid,
					"x":   base64.RawURLEncoding.EncodeToString(xb),
					"y":   base64.RawURLEncoding.EncodeToString(yb),
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		verifier := r.Form.Get("code_verifier")

		state.mu.Lock()
		entry, ok := state.codes[code]
		state.mu.Unlock()

		if !ok {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}

		h := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])
		if challenge != entry.challenge {
			http.Error(w, "invalid verifier", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token": entry.idToken,
		})
	})

	ts := httptest.NewServer(mux)
	serverURL = ts.URL
	return ts, state, rsaKey, rsaKid, ecKey, ecKid
}

func TestOIDC(t *testing.T) {
	ts, state, rsaKey, rsaKid, ecKey, ecKid := setupFakeIDP(t)
	defer ts.Close()

	ctx := context.Background()
	cfg := Config{
		Issuer:       ts.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  ts.URL + "/callback",
		Scopes:       []string{"email", "profile", "openid", "email"},
	}

	provider, err := Discover(ctx, ts.Client(), cfg)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	t.Run("happy path ES256 (claims, email, groups)", func(t *testing.T) {
		authReq, err := provider.AuthCodeURL()
		if err != nil {
			t.Fatalf("AuthCodeURL failed: %v", err)
		}

		now := time.Now()
		claims := map[string]any{
			"iss":    ts.URL,
			"sub":    "user-es256-1",
			"aud":    cfg.ClientID,
			"email":  "alice@example.com",
			"name":   "Alice User",
			"groups": []any{"engineering", "security", 123},
			"exp":    now.Add(15 * time.Minute).Unix(),
			"iat":    now.Unix(),
			"nonce":  authReq.Nonce,
		}

		token := signES256(t, ecKey, ecKid, claims)

		h := sha256.Sum256([]byte(authReq.Verifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

		code := "code-es256-happy"
		state.mu.Lock()
		state.codes[code] = fakeCodeEntry{
			challenge: codeChallenge,
			idToken:   token,
		}
		state.mu.Unlock()

		verifiedClaims, err := provider.Exchange(ctx, code, authReq.Verifier, authReq.Nonce)
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}

		if verifiedClaims.Subject != "user-es256-1" {
			t.Errorf("subject mismatch: got %s, want user-es256-1", verifiedClaims.Subject)
		}
		if verifiedClaims.Email != "alice@example.com" {
			t.Errorf("email mismatch: got %s, want alice@example.com", verifiedClaims.Email)
		}
		if verifiedClaims.Name != "Alice User" {
			t.Errorf("name mismatch: got %s, want Alice User", verifiedClaims.Name)
		}
		wantGroups := []string{"engineering", "security"}
		if !reflect.DeepEqual(verifiedClaims.Groups, wantGroups) {
			t.Errorf("groups mismatch: got %v, want %v", verifiedClaims.Groups, wantGroups)
		}
	})

	t.Run("happy path RS256 (claims, email, groups)", func(t *testing.T) {
		authReq, err := provider.AuthCodeURL()
		if err != nil {
			t.Fatalf("AuthCodeURL failed: %v", err)
		}

		now := time.Now()
		claims := map[string]any{
			"iss":    ts.URL,
			"sub":    "user-rs256-2",
			"aud":    cfg.ClientID,
			"email":  "bob@example.com",
			"name":   "Bob User",
			"groups": []any{"operators"},
			"exp":    now.Add(15 * time.Minute).Unix(),
			"iat":    now.Unix(),
			"nonce":  authReq.Nonce,
		}

		token := signRS256(t, rsaKey, rsaKid, claims)

		h := sha256.Sum256([]byte(authReq.Verifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

		code := "code-rs256-happy"
		state.mu.Lock()
		state.codes[code] = fakeCodeEntry{
			challenge: codeChallenge,
			idToken:   token,
		}
		state.mu.Unlock()

		verifiedClaims, err := provider.Exchange(ctx, code, authReq.Verifier, authReq.Nonce)
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}

		if verifiedClaims.Subject != "user-rs256-2" {
			t.Errorf("subject mismatch: got %s, want user-rs256-2", verifiedClaims.Subject)
		}
		if verifiedClaims.Email != "bob@example.com" {
			t.Errorf("email mismatch: got %s, want bob@example.com", verifiedClaims.Email)
		}
		if verifiedClaims.Name != "Bob User" {
			t.Errorf("name mismatch: got %s, want Bob User", verifiedClaims.Name)
		}
		wantGroups := []string{"operators"}
		if !reflect.DeepEqual(verifiedClaims.Groups, wantGroups) {
			t.Errorf("groups mismatch: got %v, want %v", verifiedClaims.Groups, wantGroups)
		}
	})

	t.Run("AuthCodeURL contains S256 challenge, state, nonce, redirect_uri; state/nonce/verifier differ between calls", func(t *testing.T) {
		req1, err := provider.AuthCodeURL()
		if err != nil {
			t.Fatalf("first AuthCodeURL failed: %v", err)
		}
		req2, err := provider.AuthCodeURL()
		if err != nil {
			t.Fatalf("second AuthCodeURL failed: %v", err)
		}

		if req1.State == req2.State {
			t.Errorf("state must differ between calls")
		}
		if req1.Nonce == req2.Nonce {
			t.Errorf("nonce must differ between calls")
		}
		if req1.Verifier == req2.Verifier {
			t.Errorf("verifier must differ between calls")
		}

		u, err := url.Parse(req1.URL)
		if err != nil {
			t.Fatalf("parse generated auth url: %v", err)
		}
		q := u.Query()

		if q.Get("response_type") != "code" {
			t.Errorf("response_type: got %s, want code", q.Get("response_type"))
		}
		if q.Get("client_id") != cfg.ClientID {
			t.Errorf("client_id: got %s, want %s", q.Get("client_id"), cfg.ClientID)
		}
		if q.Get("redirect_uri") != cfg.RedirectURL {
			t.Errorf("redirect_uri: got %s, want %s", q.Get("redirect_uri"), cfg.RedirectURL)
		}
		if q.Get("code_challenge_method") != "S256" {
			t.Errorf("code_challenge_method: got %s, want S256", q.Get("code_challenge_method"))
		}
		if q.Get("state") != req1.State {
			t.Errorf("state in query: got %s, want %s", q.Get("state"), req1.State)
		}
		if q.Get("nonce") != req1.Nonce {
			t.Errorf("nonce in query: got %s, want %s", q.Get("nonce"), req1.Nonce)
		}

		h := sha256.Sum256([]byte(req1.Verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
		if q.Get("code_challenge") != expectedChallenge {
			t.Errorf("code_challenge mismatch: got %s, want %s", q.Get("code_challenge"), expectedChallenge)
		}

		scopeVal := q.Get("scope")
		if scopeVal != "openid email profile" {
			t.Errorf("scope deduplication mismatch: got %q, want 'openid email profile'", scopeVal)
		}
	})

	baseValidClaims := func(now time.Time, nonce string) map[string]any {
		return map[string]any{
			"iss":   ts.URL,
			"sub":   "sub-valid",
			"aud":   cfg.ClientID,
			"exp":   now.Add(10 * time.Minute).Unix(),
			"iat":   now.Unix(),
			"nonce": nonce,
		}
	}

	rejectedCases := []struct {
		name        string
		buildToken  func(t *testing.T, now time.Time, nonce string) string
		targetNonce func(nonce string) string
	}{
		{
			name: "wrong issuer",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				c["iss"] = "https://wrong.example.com"
				return signRS256(t, rsaKey, rsaKid, c)
			},
		},
		{
			name: "wrong audience",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				c["aud"] = "other-client.example.com"
				return signRS256(t, rsaKey, rsaKid, c)
			},
		},
		{
			name: "multiple audiences without azp",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				c["aud"] = []any{cfg.ClientID, "extra-audience.example.com"}
				delete(c, "azp")
				return signRS256(t, rsaKey, rsaKid, c)
			},
		},
		{
			name: "expired",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				c["exp"] = now.Add(-5 * time.Minute).Unix()
				return signRS256(t, rsaKey, rsaKid, c)
			},
		},
		{
			name: "iat far in the future",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				c["iat"] = now.Add(15 * time.Minute).Unix()
				return signRS256(t, rsaKey, rsaKid, c)
			},
		},
		{
			name: "wrong nonce",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, "good-nonce")
				return signRS256(t, rsaKey, rsaKid, c)
			},
			targetNonce: func(nonce string) string {
				return "expected-different-nonce"
			},
		},
		{
			name: "alg none",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				return signNone(t, c)
			},
		},
		{
			name: "alg HS256",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				return signHS256(t, []byte("super-secret-key-32-bytes-long!"), c)
			},
		},
		{
			name: "unknown kid after refetch",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("generate other rsa key: %v", err)
				}
				return signRS256(t, otherKey, "unknown-kid-999", c)
			},
		},
		{
			name: "tampered payload",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				tok := signRS256(t, rsaKey, rsaKid, c)
				parts := strings.Split(tok, ".")
				return parts[0] + "." + tamperPart(parts[1]) + "." + parts[2]
			},
		},
		{
			name: "tampered signature",
			buildToken: func(t *testing.T, now time.Time, nonce string) string {
				c := baseValidClaims(now, nonce)
				tok := signES256(t, ecKey, ecKid, c)
				parts := strings.Split(tok, ".")
				return parts[0] + "." + parts[1] + "." + tamperPart(parts[2])
			},
		},
	}

	for _, tc := range rejectedCases {
		t.Run("rejected: "+tc.name, func(t *testing.T) {
			now := time.Now()
			nonce := "test-nonce-123"
			tok := tc.buildToken(t, now, nonce)

			targetNonce := nonce
			if tc.targetNonce != nil {
				targetNonce = tc.targetNonce(nonce)
			}

			initialHits := 0
			if tc.name == "unknown kid after refetch" {
				state.mu.Lock()
				initialHits = state.jwksHitCount
				state.mu.Unlock()
			}

			_, err := provider.VerifyIDToken(ctx, tok, targetNonce)
			if err == nil {
				t.Fatalf("expected error for case %q, got nil", tc.name)
			}

			if tc.name == "unknown kid after refetch" {
				state.mu.Lock()
				hitsAfter := state.jwksHitCount
				state.mu.Unlock()
				if hitsAfter <= initialHits {
					t.Errorf("expected JWKS endpoint to be refetched for unknown kid: initial %d, after %d", initialHits, hitsAfter)
				}
			}
		})
	}

	t.Run("rejected: wrong PKCE verifier at the token endpoint", func(t *testing.T) {
		authReq, err := provider.AuthCodeURL()
		if err != nil {
			t.Fatalf("AuthCodeURL: %v", err)
		}

		now := time.Now()
		c := baseValidClaims(now, authReq.Nonce)
		token := signRS256(t, rsaKey, rsaKid, c)

		h := sha256.Sum256([]byte(authReq.Verifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

		code := "code-pkce-mismatch"
		state.mu.Lock()
		state.codes[code] = fakeCodeEntry{
			challenge: codeChallenge,
			idToken:   token,
		}
		state.mu.Unlock()

		_, err = provider.Exchange(ctx, code, "invalid-verifier-string", authReq.Nonce)
		if err == nil {
			t.Fatalf("expected Exchange to fail with wrong verifier, got nil")
		}
	})

	t.Run("rejected: discovery issuer mismatch", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "https://mismatch.example.com",
				"authorization_endpoint": "https://mismatch.example.com/auth",
				"token_endpoint":         "https://mismatch.example.com/token",
				"jwks_uri":               "https://mismatch.example.com/jwks",
			})
		})
		badServer := httptest.NewServer(mux)
		defer badServer.Close()

		badCfg := Config{
			Issuer:   badServer.URL,
			ClientID: "test-client",
		}
		_, err := Discover(ctx, badServer.Client(), badCfg)
		if err == nil {
			t.Fatalf("expected error on issuer mismatch, got nil")
		}
	})

	t.Run("rejected: discovery with http endpoints on a non-local host", func(t *testing.T) {
		mux := http.NewServeMux()
		var sURL string
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 sURL,
				"authorization_endpoint": "https://auth.example.com/auth",
				"token_endpoint":         "http://insecure.example.com/token",
				"jwks_uri":               "https://auth.example.com/jwks",
			})
		})
		insecureServer := httptest.NewServer(mux)
		defer insecureServer.Close()
		sURL = insecureServer.URL

		insecureCfg := Config{
			Issuer:   insecureServer.URL,
			ClientID: "test-client",
		}
		_, err := Discover(ctx, insecureServer.Client(), insecureCfg)
		if err == nil {
			t.Fatalf("expected error on http endpoints on non-local host, got nil")
		}
	})

	t.Run("multiple audiences with valid azp", func(t *testing.T) {
		now := time.Now()
		c := baseValidClaims(now, "nonce-azp")
		c["aud"] = []any{cfg.ClientID, "second-client.example.com"}
		c["azp"] = cfg.ClientID

		token := signRS256(t, rsaKey, rsaKid, c)
		claims, err := provider.VerifyIDToken(ctx, token, "nonce-azp")
		if err != nil {
			t.Fatalf("expected valid token with matching azp, got: %v", err)
		}
		if claims.Subject != "sub-valid" {
			t.Errorf("subject mismatch: %s", claims.Subject)
		}
	})
}
