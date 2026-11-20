package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

const (
	linkDialTimeout = 10 * time.Second
	linkBackoffMin  = time.Second
	linkBackoffMax  = time.Minute
	linkStable      = 30 * time.Second // a link that lived this long resets the backoff
	linkReadIdle    = 15 * time.Second // HTTP/2 PING after this much silence
	linkPingTimeout = 5 * time.Second
)

// EdgeTLSConfig is the client TLS config of a broker link to the Edge edgeID: TLS 1.3 with
// X25519MLKEM768 only, ALPN api.BrokerALPN, the connector certificate from getCert (called
// on every handshake, so a renewed certificate is used by the next connection), the provider
// root as the only trust anchor, and the Edge SPIFFE URI spiffe://opensase/edge/<edgeID>
// checked inside the handshake.
func EdgeTLSConfig(root *x509.CertPool, getCert func() *tls.Certificate, edgeID, serverName string) *tls.Config {
	return pqsession.Harden(&tls.Config{
		RootCAs:    root,
		ServerName: serverName,
		NextProtos: []string{api.BrokerALPN},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c := getCert(); c != nil {
				return c, nil
			}
			return nil, errors.New("connector: no certificate")
		},
		VerifyConnection: pki.ExpectServer(pki.ServerEdge, edgeID),
	})
}

// DialEdge opens one broker connection: TCP, then the PQ TLS handshake with cfg, then the
// ALPN check.
func DialEdge(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: linkDialTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, linkDialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	cs := tc.ConnectionState()
	if err := pqsession.CheckPostQuantum(cs); err != nil {
		_ = tc.Close()
		return nil, err
	}
	if cs.NegotiatedProtocol != api.BrokerALPN {
		_ = tc.Close()
		return nil, fmt.Errorf("connector: edge negotiated ALPN %q, want %q", cs.NegotiatedProtocol, api.BrokerALPN)
	}
	return tc, nil
}

// ServeBroker serves h over an established broker connection (the connector is the HTTP/2
// server) until the connection or ctx ends.
func ServeBroker(ctx context.Context, conn net.Conn, h http.Handler) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	srv := &http2.Server{
		ReadIdleTimeout: linkReadIdle,
		PingTimeout:     linkPingTimeout,
		// No IdleTimeout: an idle broker link without streams is the normal state.
	}
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: h})
	_ = conn.Close()
}

// Link keeps one broker connection to an Edge, reconnecting with exponential backoff and
// jitter, until ctx is done.
type Link struct {
	Edge    api.EdgeInfo
	TLS     *tls.Config
	Handler http.Handler
	Log     *slog.Logger
	// OnState is called with true when the link is up and false when it went down (optional).
	OnState func(up bool)
}

func (l *Link) Run(ctx context.Context) {
	lg := l.Log.With("edge", l.Edge.ID, "addr", l.Edge.BrokerAddr)
	backoff := linkBackoffMin
	for ctx.Err() == nil {
		start := time.Now()
		tc, err := DialEdge(ctx, l.Edge.BrokerAddr, l.TLS)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			lg.Warn("broker link failed", "err", err, "retryIn", backoff.String())
		} else {
			lg.Info("broker link up", "kex", "X25519MLKEM768", "alpn", api.BrokerALPN)
			if l.OnState != nil {
				l.OnState(true)
			}
			ServeBroker(ctx, tc, l.Handler)
			if l.OnState != nil {
				l.OnState(false)
			}
			if ctx.Err() != nil {
				return
			}
			if time.Since(start) >= linkStable {
				backoff = linkBackoffMin
			}
			lg.Info("broker link down", "retryIn", backoff.String())
		}
		// Full jitter in [backoff/2, backoff].
		wait := backoff/2 + rand.N(backoff/2+1)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(2*backoff, linkBackoffMax)
	}
}
