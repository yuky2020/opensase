// Package oidc is a minimal OpenID Connect relying party (authorization code flow with
// PKCE S256, ID token verification against the provider's JWKS), standard library only
// (issue #17).
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config holds the OpenID Connect client configuration.
// ClientSecret is optional for public clients with PKCE.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type endpoints struct {
	authURL  string
	tokenURL string
	jwksURL  string
}

// Provider represents an OpenID Connect relying party provider.
type Provider struct {
	config     Config
	endpoints  endpoints
	httpClient *http.Client
	now        func() time.Time

	jwksMu        sync.Mutex
	jwksKeys      []jwkKey
	jwksFetched   time.Time
	jwksRefetched time.Time
}

func (p *Provider) getNow() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *Provider) getHTTPClient() *http.Client {
	if p.httpClient != nil {
		return p.httpClient
	}
	return http.DefaultClient
}

type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

func isAllowedEndpoint(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "127.0.0.1" || host == "::1" || host == "localhost"
	}
	return false
}

// Discover discovers OpenID Connect endpoints from the provider's issuer.
func Discover(ctx context.Context, hc *http.Client, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	issuerClean := strings.TrimRight(cfg.Issuer, "/")
	discoveryURL := issuerClean + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}

	client := hc
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read discovery response: %w", err)
	}

	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	if doc.Issuer != cfg.Issuer {
		return nil, errors.New("discovery issuer mismatch")
	}

	if !isAllowedEndpoint(doc.AuthorizationEndpoint) {
		return nil, fmt.Errorf("unsupported or disallowed authorization_endpoint: %s", doc.AuthorizationEndpoint)
	}
	if !isAllowedEndpoint(doc.TokenEndpoint) {
		return nil, fmt.Errorf("unsupported or disallowed token_endpoint: %s", doc.TokenEndpoint)
	}
	if !isAllowedEndpoint(doc.JwksURI) {
		return nil, fmt.Errorf("unsupported or disallowed jwks_uri: %s", doc.JwksURI)
	}

	return &Provider{
		config: cfg,
		endpoints: endpoints{
			authURL:  doc.AuthorizationEndpoint,
			tokenURL: doc.TokenEndpoint,
			jwksURL:  doc.JwksURI,
		},
		httpClient: client,
		now:        time.Now,
	}, nil
}

// AuthRequest contains the authorization URL and generated parameters.
type AuthRequest struct {
	URL      string
	State    string
	Nonce    string
	Verifier string
}

// AuthCodeURL constructs the authorization code flow URL with PKCE (S256).
func (p *Provider) AuthCodeURL() (AuthRequest, error) {
	genRandom := func() (string, error) {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}

	state, err := genRandom()
	if err != nil {
		return AuthRequest{}, fmt.Errorf("generate state: %w", err)
	}

	nonce, err := genRandom()
	if err != nil {
		return AuthRequest{}, fmt.Errorf("generate nonce: %w", err)
	}

	verifier, err := genRandom()
	if err != nil {
		return AuthRequest{}, fmt.Errorf("generate verifier: %w", err)
	}

	h := sha256.Sum256([]byte(verifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	scopes := []string{"openid"}
	seen := map[string]bool{"openid": true}
	for _, s := range p.config.Scopes {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	scopeParam := strings.Join(scopes, " ")

	u, err := url.Parse(p.endpoints.authURL)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("invalid authorization endpoint URL: %w", err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.config.ClientID)
	q.Set("redirect_uri", p.config.RedirectURL)
	q.Set("scope", scopeParam)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return AuthRequest{
		URL:      u.String(),
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
	}, nil
}

// Claims represents claims parsed and verified from an ID token.
type Claims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	Expiry  time.Time
	Raw     map[string]any
}

// Exchange exchanges an authorization code and PKCE verifier for an ID token and verifies it.
// Errors must never include the code, the tokens or the verifier.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (*Claims, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.config.RedirectURL)
	form.Set("client_id", p.config.ClientID)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoints.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("failed to create token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.config.ClientSecret != "" {
		req.SetBasicAuth(p.config.ClientID, p.config.ClientSecret)
	}

	resp, err := p.getHTTPClient().Do(req)
	if err != nil {
		return nil, errors.New("token request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.New("failed to read token response")
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, errors.New("failed to parse token response")
	}
	if tokenResp.IDToken == "" {
		return nil, errors.New("missing id_token in token response")
	}

	claims, err := p.VerifyIDToken(ctx, tokenResp.IDToken, nonce)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	return claims, nil
}
