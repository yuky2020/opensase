package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// Connector side of the broker (ADR-0013). Connectors dial the Edge on BrokerAddr with
// mTLS; over that connection the Edge is the HTTP/2 client.
const (
	brokerHandshakeTimeout = 10 * time.Second
	brokerReadIdle         = 15 * time.Second // HTTP/2 PING after this much silence
	brokerPingTimeout      = 5 * time.Second
	maxBrokerConns         = 4096
)

// brokerConn is one live connector connection.
type brokerConn struct {
	id, tenant, group string
	cc                *http2.ClientConn //nolint:staticcheck // SA1019: http.ClientConn cannot wrap an existing (accepted) conn
	nc                net.Conn
	done              chan struct{} // closed when the connection is gone
	once              sync.Once
	expiry            *time.Timer
}

func (b *brokerConn) close() {
	b.once.Do(func() {
		_ = b.nc.Close()
		_ = b.cc.Close()
	})
}

// watchedConn reports the first read error (peer gone, PING timeout, Close) on done.
type watchedConn struct {
	*tls.Conn
	once sync.Once
	done chan struct{}
}

func (w *watchedConn) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if err != nil {
		w.once.Do(func() { close(w.done) })
	}
	return n, err
}

func (w *watchedConn) Close() error {
	w.once.Do(func() { close(w.done) })
	return w.Conn.Close()
}

// connectorHub holds the connectors allowed by the latest peer feed and the live broker
// connections, by tenant and group.
type connectorHub struct {
	log *slog.Logger
	tr  *http2.Transport //nolint:staticcheck // SA1019: http.Transport.NewClientConn dials itself; we wrap an accepted conn

	mu      sync.Mutex
	allowed map[string]api.EdgeConnector // connector ID -> latest EdgePeers entry
	conns   []*brokerConn                // in admission order (round-robin base)
	rr      atomic.Uint64
}

func newConnectorHub(log *slog.Logger) *connectorHub {
	return &connectorHub{
		log:     log,
		tr:      &http2.Transport{ReadIdleTimeout: brokerReadIdle, PingTimeout: brokerPingTimeout}, //nolint:staticcheck // SA1019: see connectorHub.tr
		allowed: map[string]api.EdgeConnector{},
	}
}

// setAllowed applies the connector list of a fresh peer feed and closes the connections of
// connectors that are gone (revoked) or whose tenant or group changed.
func (h *connectorHub) setAllowed(list []api.EdgeConnector) {
	m := make(map[string]api.EdgeConnector, len(list))
	for _, c := range list {
		if pki.ValidID(c.ConnectorID) && pki.ValidID(c.TenantID) {
			m[c.ConnectorID] = c
		}
	}
	h.mu.Lock()
	h.allowed = m
	var drop []*brokerConn
	keep := h.conns[:0]
	for _, b := range h.conns {
		if a, ok := m[b.id]; ok && a.TenantID == b.tenant && a.Group == b.group {
			keep = append(keep, b)
		} else {
			drop = append(drop, b)
		}
	}
	clear(h.conns[len(keep):])
	h.conns = keep
	h.mu.Unlock()
	for _, b := range drop {
		h.log.Info("connector dropped: no longer in peer feed", "connector", b.id, "tenant", b.tenant)
		b.close()
	}
}

func (h *connectorHub) isAllowed(id pki.Identity) (api.EdgeConnector, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.allowed[id.ConnectorID]
	return a, ok && a.TenantID == id.TenantID
}

// admit runs the handshake of an accepted connection and checks PQ TLS and the ALPN.
func (h *connectorHub) admit(ctx context.Context, tc *tls.Conn) error {
	hctx, cancel := context.WithTimeout(ctx, brokerHandshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	cs := tc.ConnectionState()
	if err := pqsession.CheckPostQuantum(cs); err != nil {
		return err
	}
	if cs.NegotiatedProtocol != api.BrokerALPN {
		return fmt.Errorf("ALPN %q, want %q", cs.NegotiatedProtocol, api.BrokerALPN)
	}
	return nil
}

// register wraps an authenticated connector connection as an HTTP/2 client connection.
func (h *connectorHub) register(tc *tls.Conn, id pki.Identity, notAfter time.Time) (*brokerConn, error) {
	a, ok := h.isAllowed(id)
	if !ok {
		return nil, errors.New("connector not in the peer feed (unknown, revoked or other tenant)")
	}
	wc := &watchedConn{Conn: tc, done: make(chan struct{})}
	cc, err := h.tr.NewClientConn(wc) //nolint:staticcheck // SA1019: see connectorHub.tr
	if err != nil {
		return nil, fmt.Errorf("http2: %w", err)
	}
	b := &brokerConn{id: id.ConnectorID, tenant: id.TenantID, group: a.Group, cc: cc, nc: wc, done: wc.done}
	h.mu.Lock()
	// Re-check under the lock: a peer sync may have revoked it meanwhile.
	cur, ok := h.allowed[id.ConnectorID]
	if !ok || cur.TenantID != id.TenantID || cur.Group != a.Group || len(h.conns) >= maxBrokerConns {
		h.mu.Unlock()
		b.close()
		return nil, errors.New("connector revoked during setup or too many connections")
	}
	h.conns = append(h.conns, b)
	h.mu.Unlock()
	// The connection never outlives the certificate that authenticated it.
	b.expiry = time.AfterFunc(time.Until(notAfter), b.close)
	go func() {
		<-b.done
		b.expiry.Stop()
		h.remove(b)
		_ = cc.Close()
		h.log.Info("connector disconnected", "connector", b.id, "tenant", b.tenant, "group", b.group)
	}()
	return b, nil
}

func (h *connectorHub) remove(b *brokerConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i := slices.Index(h.conns, b); i >= 0 {
		h.conns = slices.Delete(h.conns, i, i+1)
	}
}

// pick returns the live connections of (tenant, group), rotated round-robin.
func (h *connectorHub) pick(tenant, group string) []*brokerConn {
	h.mu.Lock()
	var c []*brokerConn
	for _, b := range h.conns {
		if b.tenant == tenant && b.group == group {
			c = append(c, b)
		}
	}
	h.mu.Unlock()
	if len(c) == 0 {
		return nil
	}
	n := int(h.rr.Add(1) % uint64(len(c)))
	out := append(c[n:len(c):len(c)], c[:n]...)
	return slices.DeleteFunc(out, func(b *brokerConn) bool { return !b.cc.CanTakeNewRequest() })
}

// liveIDs returns the sorted, de-duplicated IDs of connectors with a live connection.
func (h *connectorHub) liveIDs() []string {
	h.mu.Lock()
	ids := make([]string, 0, len(h.conns))
	for _, b := range h.conns {
		ids = append(ids, b.id)
	}
	h.mu.Unlock()
	slices.Sort(ids)
	return slices.Compact(ids)
}

func (h *connectorHub) closeAll() {
	h.mu.Lock()
	conns := h.conns
	h.conns = nil
	h.mu.Unlock()
	for _, b := range conns {
		b.close()
	}
}

// brokerTLSConfig requires a connector certificate chained to a tenant CA from the PKI
// bundle, TLS 1.3 with X25519MLKEM768 and ALPN api.BrokerALPN.
func (e *Edge) brokerTLSConfig() *tls.Config {
	base := pqsession.Harden(&tls.Config{
		Certificates: []tls.Certificate{e.cfg.Cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{api.BrokerALPN},
	})
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		t := e.trust.Load()
		if t == nil {
			return nil, errors.New("edge: PKI bundle not loaded yet")
		}
		c.ClientCAs = t.pool
		return c, nil
	}
	return base
}

// serveConnectors accepts Connector connections on ln until ctx is done.
func (e *Edge) serveConnectors(ctx context.Context, ln net.Listener) {
	cfg := e.brokerTLSConfig()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		e.hub.closeAll()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			e.log.Warn("connector listener stopped", "err", err)
			return
		}
		go e.acceptConnector(ctx, tls.Server(c, cfg))
	}
}

func (e *Edge) acceptConnector(ctx context.Context, tc *tls.Conn) {
	remote := tc.RemoteAddr().String()
	if err := e.hub.admit(ctx, tc); err != nil {
		e.log.Info("connector refused", "remote", remote, "err", err)
		_ = tc.Close()
		return
	}
	cs := tc.ConnectionState()
	id, err := pki.VerifyPeerChains(cs.VerifiedChains, e.cfg.Root)
	if err != nil || id.Kind != pki.PeerConnector {
		e.log.Info("connector refused: not a connector certificate", "remote", remote, "kind", id.Kind.String(), "err", err)
		_ = tc.Close()
		return
	}
	// Enrolled after the last peer sync? Refresh on demand (rate-limited, negative cache).
	sctx, cancel := context.WithTimeout(ctx, minSyncInterval+5*time.Second)
	allowed := e.connectorAllowed(sctx, id, cs.VerifiedChains[0][0].SerialNumber.String())
	cancel()
	if !allowed {
		e.log.Info("connector refused: not in the peer feed (unknown, revoked, other tenant or superseded certificate)", "remote", remote, "connector", id.ConnectorID, "tenant", id.TenantID)
		_ = tc.Close()
		return
	}
	b, err := e.hub.register(tc, id, cs.PeerCertificates[0].NotAfter)
	if err != nil {
		e.log.Info("connector refused", "remote", remote, "connector", id.ConnectorID, "tenant", id.TenantID, "err", err)
		_ = tc.Close()
		return
	}
	e.triggerReport()
	e.log.Info("connector connected", "remote", remote, "connector", b.id, "tenant", b.tenant, "group", b.group, "kex", "X25519MLKEM768")
}
