package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const maxTokenBytes = 64 * 1024

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func getNumericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	case int:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return time.Unix(i, 0), true
		}
		f, err := n.Float64()
		if err == nil {
			return time.Unix(int64(f), 0), true
		}
	}
	return time.Time{}, false
}

func (p *Provider) findKeyLocked(kid, alg string) *jwkKey {
	for i := range p.jwksKeys {
		k := &p.jwksKeys[i]
		if kid != "" && k.Kid != "" && k.Kid != kid {
			continue
		}
		if kid != "" && k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if alg == "RS256" && k.Kty != "RSA" {
			continue
		}
		if alg == "ES256" && k.Kty != "EC" {
			continue
		}
		return k
	}
	return nil
}

func (p *Provider) fetchJWKSLocked(ctx context.Context) error {
	if p.endpoints.jwksURL == "" {
		return errors.New("jwks endpoint is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoints.jwksURL, nil)
	if err != nil {
		return errors.New("failed to create jwks request")
	}
	resp, err := p.getHTTPClient().Do(req)
	if err != nil {
		return errors.New("failed to fetch jwks")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return errors.New("failed to read jwks response")
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return errors.New("failed to parse jwks json")
	}

	p.jwksKeys = doc.Keys
	p.jwksFetched = p.getNow()
	return nil
}

func (p *Provider) getKey(ctx context.Context, kid, alg string) (*jwkKey, error) {
	p.jwksMu.Lock()
	defer p.jwksMu.Unlock()

	now := p.getNow()
	cacheExpired := p.jwksKeys == nil || now.Sub(p.jwksFetched) >= 10*time.Minute
	if cacheExpired {
		if err := p.fetchJWKSLocked(ctx); err != nil {
			return nil, err
		}
	}

	key := p.findKeyLocked(kid, alg)
	if key == nil {
		canRefetch := !cacheExpired && (p.jwksRefetched.IsZero() || now.Sub(p.jwksRefetched) >= 30*time.Second)
		if canRefetch {
			if err := p.fetchJWKSLocked(ctx); err != nil {
				return nil, err
			}
			p.jwksRefetched = now
			key = p.findKeyLocked(kid, alg)
		}
	}

	if key == nil {
		return nil, errors.New("unknown kid: matching key not found in JWKS")
	}
	return key, nil
}

// VerifyIDToken verifies a compact JWS ID token against the provider's JWKS and configuration.
// Errors must never include the code, the tokens or the verifier.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, nonce string) (*Claims, error) {
	if len(raw) > maxTokenBytes {
		return nil, errors.New("token exceeds maximum size of 64 KiB")
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid compact JWS format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid base64url in header")
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("failed to parse header JSON")
	}

	if header.Alg != "RS256" && header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported or disallowed algorithm: %s", header.Alg)
	}

	key, err := p.getKey(ctx, header.Kid, header.Alg)
	if err != nil {
		return nil, err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid base64url in signature")
	}

	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))

	switch header.Alg {
	case "RS256":
		if key.Kty != "RSA" {
			return nil, errors.New("key type must be RSA for RS256")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, errors.New("invalid RSA modulus encoding")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, errors.New("invalid RSA exponent encoding")
		}
		modulus := new(big.Int).SetBytes(nBytes)
		if modulus.BitLen() < 2048 {
			return nil, errors.New("RSA modulus must be at least 2048 bits")
		}
		exponent := new(big.Int).SetBytes(eBytes)
		if !exponent.IsInt64() || exponent.Int64() <= 0 {
			return nil, errors.New("invalid RSA public exponent")
		}
		rsaPub := &rsa.PublicKey{
			N: modulus,
			E: int(exponent.Int64()),
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigBytes); err != nil {
			return nil, errors.New("invalid signature")
		}

	case "ES256":
		if key.Kty != "EC" {
			return nil, errors.New("key type must be EC for ES256")
		}
		if key.Crv != "P-256" {
			return nil, errors.New("curve must be P-256 for ES256")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, errors.New("invalid EC x coordinate encoding")
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, errors.New("invalid EC y coordinate encoding")
		}
		if len(xBytes) != 32 || len(yBytes) != 32 {
			return nil, errors.New("invalid EC coordinate length")
		}

		uncompressed := make([]byte, 65)
		uncompressed[0] = 0x04
		copy(uncompressed[1:33], xBytes)
		copy(uncompressed[33:65], yBytes)

		// ParseUncompressedPublicKey refuses points that are not on the curve.
		ecPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
		if err != nil {
			return nil, fmt.Errorf("invalid EC public key: %w", err)
		}

		if len(sigBytes) != 64 {
			return nil, errors.New("ES256 signature must be exactly 64 bytes")
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(ecPub, hash[:], r, s) {
			return nil, errors.New("invalid signature")
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid base64url in payload")
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &rawClaims); err != nil {
		return nil, errors.New("failed to parse payload JSON")
	}

	iss, ok := rawClaims["iss"].(string)
	if !ok || iss != p.config.Issuer {
		return nil, errors.New("issuer mismatch")
	}

	var audList []string
	switch v := rawClaims["aud"].(type) {
	case string:
		audList = []string{v}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				audList = append(audList, s)
			}
		}
	default:
		return nil, errors.New("missing or invalid aud claim")
	}

	foundAud := false
	for _, a := range audList {
		if a == p.config.ClientID {
			foundAud = true
			break
		}
	}
	if !foundAud {
		return nil, errors.New("audience does not contain client ID")
	}

	if len(audList) > 1 {
		azp, ok := rawClaims["azp"].(string)
		if !ok || azp != p.config.ClientID {
			return nil, errors.New("multiple audiences require azp matching client ID")
		}
	}

	now := p.getNow()
	clockSkew := 1 * time.Minute

	expTime, ok := getNumericDate(rawClaims["exp"])
	if !ok {
		return nil, errors.New("missing or invalid exp claim")
	}
	if !now.Before(expTime.Add(clockSkew)) {
		return nil, errors.New("token is expired")
	}

	iatTime, ok := getNumericDate(rawClaims["iat"])
	if !ok {
		return nil, errors.New("missing or invalid iat claim")
	}
	if iatTime.After(now.Add(5*time.Minute + clockSkew)) {
		return nil, errors.New("iat is too far in the future")
	}

	// The nonce is mandatory: this relying party always sends one, so an empty expected
	// nonce is a caller bug and must not turn the replay check off.
	if nonce == "" {
		return nil, errors.New("expected nonce is empty")
	}
	tokNonce, _ := rawClaims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(tokNonce), []byte(nonce)) != 1 {
		return nil, errors.New("nonce mismatch")
	}

	var groups []string
	if gList, ok := rawClaims["groups"].([]any); ok {
		for _, item := range gList {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}
	}

	sub, _ := rawClaims["sub"].(string)
	email, _ := rawClaims["email"].(string)
	name, _ := rawClaims["name"].(string)

	return &Claims{
		Subject: sub,
		Email:   email,
		Name:    name,
		Groups:  groups,
		Expiry:  expTime,
		Raw:     rawClaims,
	}, nil
}
