package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// controlPlane is the Edge's view of the Control Plane API. It is an interface so tests can
// substitute a fake.
type controlPlane interface {
	PKIBundle(ctx context.Context) (api.PKIBundle, error)
	Peers(ctx context.Context) (api.EdgePeers, error)
	Decide(ctx context.Context, deviceID string, f policy.Flow) (api.DecideResponse, error)
	PostFlows(ctx context.Context, recs []api.FlowRecord) error
	ReportSessions(ctx context.Context, s api.EdgeSessions) error
	InspectionCA(ctx context.Context, req api.InspectionCARequest) (api.InspectionCAResponse, error)
	// Categories fetches category data (ADR-0022). With etag set, notModified reports 304.
	Categories(ctx context.Context, names []string, etag string) (body []byte, newETag string, notModified bool, err error)
}

// cpClient talks to the Control Plane over PQ TLS with the edge certificate.
type cpClient struct {
	base string
	hc   *http.Client
}

func newCPClient(baseURL string, root *x509.CertPool, cert tls.Certificate) (*cpClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("edge: control plane URL must be https://host[:port], got %q", baseURL)
	}
	cfg := pqsession.Harden(&tls.Config{RootCAs: root, Certificates: []tls.Certificate{cert}})
	// Inside the handshake, before any request is sent: the server must be the Control Plane
	// (its SPIFFE URI, not just a DNS name that an edge cert may share) over PQ TLS
	// (security review #1, #12).
	cfg.VerifyConnection = pki.ExpectServer(pki.ServerControlPlane, "")
	return &cpClient{
		base: u.String(),
		hc: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4},
		},
	}, nil
}

func (c *cpClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(msg))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

func (c *cpClient) PKIBundle(ctx context.Context) (api.PKIBundle, error) {
	var b api.PKIBundle
	return b, c.do(ctx, http.MethodGet, "/v1/pki/ca", nil, &b)
}

func (c *cpClient) Peers(ctx context.Context) (api.EdgePeers, error) {
	var p api.EdgePeers
	return p, c.do(ctx, http.MethodGet, "/v1/edge/peers", nil, &p)
}

func (c *cpClient) Decide(ctx context.Context, deviceID string, f policy.Flow) (api.DecideResponse, error) {
	var r api.DecideResponse
	return r, c.do(ctx, http.MethodPost, "/v1/decide?device="+url.QueryEscape(deviceID), api.DecideRequest{Flow: f}, &r)
}

func (c *cpClient) PostFlows(ctx context.Context, recs []api.FlowRecord) error {
	return c.do(ctx, http.MethodPost, "/v1/flows", api.FlowBatch{Records: recs}, nil)
}

// ReportSessions posts the devices with a live session and the connectors with a live
// broker connection (api.EdgeSessions).
func (c *cpClient) ReportSessions(ctx context.Context, s api.EdgeSessions) error {
	return c.do(ctx, http.MethodPost, "/v1/edge/sessions", s, nil)
}

// InspectionCA asks for the Edge's inspection intermediate of one tenant (ADR-0018).
func (c *cpClient) InspectionCA(ctx context.Context, req api.InspectionCARequest) (api.InspectionCAResponse, error) {
	var out api.InspectionCAResponse
	err := c.do(ctx, http.MethodPost, "/v1/edge/inspection-ca", req, &out)
	return out, err
}

// Categories fetches the named web categories in the pkg/categories wire format.
func (c *cpClient) Categories(ctx context.Context, names []string, etag string) ([]byte, string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/edge/categories?names="+url.QueryEscape(strings.Join(names, ",")), nil)
	if err != nil {
		return nil, "", false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, true, nil
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		return b, resp.Header.Get("ETag"), false, err
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return nil, "", false, fmt.Errorf("GET /v1/edge/categories: %s: %s", resp.Status, bytes.TrimSpace(msg))
}

// trust is the material from the PKI bundle: the pool that verifies device certificates and
// the snapshot signing keys.
type trust struct {
	pool *x509.CertPool
	keys map[string]ed25519.PublicKey
}

// parseBundle keeps the tenant CAs that chain to root; tenant != "" (a single-tenant Private
// Edge, ADR-0014) keeps only that tenant's CA, so other tenants' certificates do not verify.
func parseBundle(b api.PKIBundle, root *x509.Certificate, tenant string) (*trust, error) {
	certs, err := pki.ParseCertsPEM([]byte(b.CAPEM))
	if err != nil {
		return nil, err
	}
	t := &trust{pool: x509.NewCertPool(), keys: map[string]ed25519.PublicKey{}}
	t.pool.AddCert(root)
	for _, c := range certs {
		// Only accept tenant CAs that chain to our configured root.
		if c.Equal(root) {
			continue
		}
		if tid, err := pki.TenantOfCA(c); err != nil || (tenant != "" && tid != tenant) || c.CheckSignatureFrom(root) != nil {
			continue
		}
		t.pool.AddCert(c)
	}
	for _, k := range b.SnapshotKeys {
		if k.Algorithm == policy.AlgEd25519 && len(k.PublicKey) == ed25519.PublicKeySize {
			t.keys[k.KeyID] = ed25519.PublicKey(k.PublicKey)
		}
	}
	if len(t.keys) == 0 {
		return nil, fmt.Errorf("edge: PKI bundle has no usable snapshot key")
	}
	return t, nil
}
