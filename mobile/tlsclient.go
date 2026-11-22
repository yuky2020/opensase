package mobile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

const maxResponseBytes = 8 << 20

// protectFunc excludes a socket from the VPN (VpnService.protect). It returns false if the
// socket could not be protected; the connection is then refused (it would loop into the TUN).
type protectFunc func(fd int) bool

// dialer returns a net.Dialer whose sockets are protected before connect.
func dialer(protect protectFunc) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if protect != nil {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var ok bool
			if err := c.Control(func(fd uintptr) { ok = protect(int(fd)) }); err != nil {
				return err
			}
			if !ok {
				return errors.New("mobile: VpnService.protect failed")
			}
			return nil
		}
	}
	return d
}

// pqTransport builds an HTTP transport whose every connection is TLS 1.3 with
// X25519MLKEM768 (pqsession.Harden) and is verified with pqsession.CheckPostQuantum after
// the handshake, before any request is sent.
func pqTransport(base *tls.Config, protect protectFunc, hosts *hostCache, keepAlive bool) *http.Transport {
	d := dialer(protect)
	dial := d.DialContext
	if hosts != nil {
		dial = hosts.dialContext(d)
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			raw, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			cfg := pqsession.Harden(base.Clone())
			if cfg.ServerName == "" {
				cfg.ServerName = host
			}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			if err := pqsession.CheckPostQuantum(tc.ConnectionState()); err != nil {
				tc.Close()
				return nil, err
			}
			return tc, nil
		},
		DisableKeepAlives:     !keepAlive,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // long-poll; per-request contexts bound the time
		ForceAttemptHTTP2:     false,
	}
}

// bootstrapTLS returns the TLS config used for POST /v1/enroll, before the device has the
// tenant trust anchor. Trust, in order: a PEM bundle in stateDir/bootstrap-ca.pem; a
// "#sha256=<hex>" fragment on the control URL pinning the SHA-256 of any certificate in the
// server's chain (the chain must verify up to that certificate); the system roots.
// Whatever the trust source, the server must also prove the Control Plane identity
// (spiffe://opensase/controlplane, review #1): an Edge certificate chains to the same root.
//
// CONTRACT-CHANGE-REQUEST: the enrollment trust bootstrap is not specified by mobile/api.go
// or pkg/api. Proposal: the provisioning key (or a QR code) carries the CA fingerprint, as
// implemented here with the URL fragment.
func bootstrapTLS(controlURL *url.URL, bootstrapPEM []byte) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: controlURL.Hostname(),
		// Runs after the chain (or pin) verification, also when InsecureSkipVerify is set.
		VerifyConnection: pki.ExpectServer(pki.ServerControlPlane, ""),
	}
	if len(bootstrapPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(bootstrapPEM) {
			return nil, errors.New("mobile: bootstrap CA file has no certificates")
		}
		cfg.RootCAs = pool
		return pqsession.Harden(cfg), nil
	}
	frag := controlURL.Fragment
	if pin, ok := strings.CutPrefix(frag, "sha256="); ok {
		want, err := hex.DecodeString(strings.ReplaceAll(pin, ":", ""))
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("mobile: invalid #sha256= pin in control URL")
		}
		name := cfg.ServerName
		// Standard verification is replaced by verification against the pinned certificate.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinned(rawCerts, want, name)
		}
	} else if frag != "" {
		return nil, errors.New("mobile: unsupported control URL fragment")
	}
	return pqsession.Harden(cfg), nil
}

func verifyPinned(rawCerts [][]byte, pin []byte, serverName string) error {
	if len(rawCerts) == 0 {
		return errors.New("mobile: no server certificate")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	pinned := false
	for i, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs[i] = c
		sum := sha256.Sum256(raw)
		if bytes.Equal(sum[:], pin) {
			roots.AddCert(c)
			pinned = true
		} else if i > 0 {
			inter.AddCert(c)
		}
	}
	if !pinned {
		return errors.New("mobile: server certificate chain does not contain the pinned certificate")
	}
	// A pinned leaf is its own root.
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: inter})
	return err
}

// mtlsConfig is the device mTLS config after enrollment, with the current device
// certificate, for a server that must prove the given identity: kind
// pki.ServerControlPlane with id "", or pki.ServerEdge with the EdgeInfo.ID (review #1).
func mtlsConfig(en *enrollment, kind, id string) *tls.Config {
	return pqsession.Harden(&tls.Config{
		Certificates:     []tls.Certificate{*en.cert.Load()},
		RootCAs:          en.ca,
		VerifyConnection: pki.ExpectServer(kind, id),
	})
}

// swapTransport is the Control Plane round tripper. Renewal installs a transport built
// with the new device certificate; idle connections of the old one are closed, and its
// in-flight requests (a long-poll) finish on their connection.
type swapTransport struct {
	cur atomic.Pointer[http.Transport]
}

func (s *swapTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return s.cur.Load().RoundTrip(r)
}

func (s *swapTransport) swap(t *http.Transport) {
	if old := s.cur.Swap(t); old != nil {
		old.CloseIdleConnections()
	}
}

// CloseIdleConnections is called by http.Client.CloseIdleConnections.
func (s *swapTransport) CloseIdleConnections() { s.cur.Load().CloseIdleConnections() }

// httpError is a non-2xx response.
type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("http %d: %s", e.Status, e.Body)
}

// doJSON sends in (if non-nil) as JSON and decodes a 2xx response into out (if non-nil).
// It returns the response for header access; the body is already closed.
func doJSON(ctx context.Context, c *http.Client, method, u string, hdr http.Header, in, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(lr, 512))
		return resp, &httpError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(lr).Decode(out); err != nil {
			return resp, fmt.Errorf("decode %s %s: %w", method, u, err)
		}
	}
	return resp, nil
}

// joinURL appends path (with optional query) to a base URL.
func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}
