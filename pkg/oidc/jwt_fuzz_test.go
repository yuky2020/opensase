package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func buildSignedRS256Token(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
	}
	hJSON, _ := json.Marshal(header)
	cJSON, _ := json.Marshal(claims)
	p1 := base64.RawURLEncoding.EncodeToString(hJSON)
	p2 := base64.RawURLEncoding.EncodeToString(cJSON)
	signingInput := p1 + "." + p2
	h := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	p3 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + p3
}

func buildSignedES256Token(key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
	}
	hJSON, _ := json.Marshal(header)
	cJSON, _ := json.Marshal(claims)
	p1 := base64.RawURLEncoding.EncodeToString(hJSON)
	p2 := base64.RawURLEncoding.EncodeToString(cJSON)
	signingInput := p1 + "." + p2
	h := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
	sigBytes := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sigBytes[32-len(rb):32], rb)
	copy(sigBytes[64-len(sb):64], sb)
	p3 := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + p3
}

func FuzzVerifyIDToken(f *testing.F) {
	fixedTime := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate rsa key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate ec key: %v", err)
	}

	rsaJWK := jwkKey{
		Kty: "RSA",
		Alg: "RS256",
		Kid: "rsa-1",
		Use: "sig",
		N:   b64.EncodeToString(rsaKey.N.Bytes()),
		E:   b64.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}

	ecX := make([]byte, 32)
	ecY := make([]byte, 32)
	xb := ecKey.X.Bytes()
	yb := ecKey.Y.Bytes()
	copy(ecX[32-len(xb):], xb)
	copy(ecY[32-len(yb):], yb)
	ecJWK := jwkKey{
		Kty: "EC",
		Alg: "ES256",
		Kid: "ec-1",
		Use: "sig",
		Crv: "P-256",
		X:   b64.EncodeToString(ecX),
		Y:   b64.EncodeToString(ecY),
	}

	p := &Provider{
		config: Config{
			Issuer:   "https://issuer.example.com",
			ClientID: "client-id-1",
		},
		now:         func() time.Time { return fixedTime },
		jwksFetched: fixedTime,
		jwksKeys:    []jwkKey{rsaJWK, ecJWK},
	}

	validClaims := map[string]any{
		"iss":   "https://issuer.example.com",
		"aud":   "client-id-1",
		"exp":   fixedTime.Add(1 * time.Hour).Unix(),
		"iat":   fixedTime.Unix(),
		"nonce": "test-nonce",
		"sub":   "user-1",
		"email": "user@example.com",
	}

	validRSAToken := buildSignedRS256Token(rsaKey, "rsa-1", validClaims)
	validECToken := buildSignedES256Token(ecKey, "ec-1", validClaims)

	parts := strings.Split(validRSAToken, ".")
	emptySigToken := parts[0] + "." + parts[1] + "."

	f.Add(validRSAToken)
	f.Add(validECToken)
	f.Add(emptySigToken)
	f.Add("header.payload")
	f.Add("header.payload.bad-sig")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		tokenParts := strings.Split(raw, ".")
		claims, err := p.VerifyIDToken(context.Background(), raw, "test-nonce")
		if err == nil {
			// Invariant: never returns success for a token whose signature part is empty
			if len(tokenParts) != 3 || tokenParts[2] == "" {
				t.Fatalf("VerifyIDToken returned success for token with empty or invalid signature part: %q", raw)
			}
			if claims == nil {
				t.Fatal("VerifyIDToken returned nil claims with nil error")
			}
		}
	})
}
