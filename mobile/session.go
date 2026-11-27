package mobile

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

const defaultRotateAfter = 10 * time.Minute

// wgKey is a WireGuard (Curve25519) key pair generated with crypto/ecdh.
type wgKey struct {
	priv *ecdh.PrivateKey
	pub  []byte // 32 bytes
}

func newWGKey() (*wgKey, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &wgKey{priv: k, pub: k.PublicKey().Bytes()}, nil
}

// session is the state of one Edge session (one WireGuard key, many epochs).
type session struct {
	edge     api.EdgeInfo
	key      *wgKey
	resp     api.SessionResponse
	edgePub  []byte   // 32 bytes
	endpoint string   // resolved ip:port
	psk      [32]byte // current epoch; wiped on rotation and stop
	pq       bool     // the last session-setup connection was verified X25519MLKEM768
	kex      string
}

func (s *session) wipe() {
	clear(s.psk[:])
}

// rotateAfter is the time until the next epoch.
func (s *session) rotateAfter() time.Duration {
	if s.resp.RotateAfterSec > 0 {
		return time.Duration(s.resp.RotateAfterSec) * time.Second
	}
	return defaultRotateAfter
}

// setupSession runs POST /v1/session on the Edge over a fresh PQ mTLS connection and
// derives the PSK on that same connection. For epoch 0 a new key is generated (prev nil);
// for rotation, prev supplies the key and session id and is not modified.
func (e *Engine) setupSession(ctx context.Context, en *enrollment, edge api.EdgeInfo, prev *session) (*session, error) {
	s := &session{edge: edge}
	req := api.SessionRequest{}
	if prev != nil {
		s.key = prev.key
		req.SessionID = prev.resp.SessionID
		req.Epoch = prev.resp.Epoch + 1
	} else {
		k, err := newWGKey()
		if err != nil {
			return nil, err
		}
		s.key = k
	}
	req.WGPublicKey = base64.StdEncoding.EncodeToString(s.key.pub)

	// A dedicated client without keep-alives: every epoch is a fresh TLS handshake and
	// therefore a fresh ML-KEM encapsulation (ADR-0002).
	// The Edge must prove spiffe://opensase/edge/<EdgeInfo.ID> (review #1).
	client := &http.Client{Transport: pqTransport(mtlsConfig(en, pki.ServerEdge, edge.ID), e.protect, e.hosts, false), Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	var remoteAddr atomic.Pointer[netip.Addr]
	traceCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if a, ok := addrFromNetAddr(info.Conn.RemoteAddr()); ok {
				remoteAddr.Store(&a)
			}
		},
	})
	httpResp, err := doJSON(traceCtx, client, http.MethodPost, joinURL(edge.SessionURL, "/v1/session"), nil, &req, &s.resp)
	if err != nil {
		return nil, fmt.Errorf("session setup: %w", err)
	}
	if httpResp.TLS == nil {
		return nil, errors.New("session setup: no TLS state")
	}
	cs := *httpResp.TLS
	if err := pqsession.CheckPostQuantum(cs); err != nil {
		return nil, err
	}
	if s.resp.SessionID == "" {
		return nil, errors.New("session setup: empty sessionId")
	}
	if prev != nil && s.resp.Epoch != req.Epoch {
		return nil, fmt.Errorf("session setup: edge returned epoch %d, want %d", s.resp.Epoch, req.Epoch)
	}
	edgeKey := s.resp.EdgeWGKey
	if edgeKey == "" {
		edgeKey = edge.WGPublicKey
	}
	s.edgePub, err = base64.StdEncoding.DecodeString(edgeKey)
	if err != nil || len(s.edgePub) != 32 {
		return nil, errors.New("session setup: invalid edge WireGuard key")
	}
	if prev != nil && !bytes.Equal(s.edgePub, prev.edgePub) {
		return nil, errors.New("session setup: edge WireGuard key changed during rotation")
	}
	ep := s.resp.WGEndpoint
	if ep == "" {
		ep = edge.WGEndpoint
	}
	var sessionIP netip.Addr
	if p := remoteAddr.Load(); p != nil {
		sessionIP = *p
	}
	if s.endpoint, err = e.resolveEndpointFor(ctx, ep, sessionIP); err != nil {
		return nil, err
	}
	s.psk, err = pqsession.DerivePSK(cs, s.key.pub, s.edgePub, s.resp.SessionID, s.resp.Epoch)
	if err != nil {
		return nil, err
	}
	s.pq, s.kex = true, cs.CurveID.String()
	return s, nil
}

// resolveEndpoint turns host:port into ip:port (wireguard-go's UAPI needs an IP).
func (e *Engine) resolveEndpoint(ctx context.Context, hostport string) (string, error) {
	return e.resolveEndpointFor(ctx, hostport, netip.Addr{})
}

// resolveEndpointFor turns host:port into ip:port, preferring prefer (and its address
// family) when DNS returns multiple records, then falling back across families.
func (e *Engine) resolveEndpointFor(ctx context.Context, hostport string, prefer netip.Addr) (string, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()).String(), nil
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", fmt.Errorf("invalid WireGuard endpoint %q: %w", hostport, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("invalid WireGuard endpoint port %q: %w", hostport, err)
	}
	ips, err := e.hosts.resolve(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve WireGuard endpoint %q: %w", host, err)
	}
	ip, ok := selectEndpointAddr(ips, prefer)
	if !ok {
		return "", fmt.Errorf("resolve WireGuard endpoint %q: no usable address", host)
	}
	return netip.AddrPortFrom(ip, uint16(p)).String(), nil
}

// selectEndpointAddr picks one WireGuard endpoint IP from ips.
//
// When prefer is valid (the remote IP that succeeded for the TLS session-setup
// connection):
//  1. If prefer itself is present in ips, select it so WireGuard targets the same Edge IP.
//  2. Otherwise select the first address matching prefer's address family (IPv6 or IPv4).
//  3. Otherwise fall back to the first valid address in ips (cross-family fallback).
//
// When prefer is zero, preserve the resolver's address order instead of hard-preferring IPv4.
func selectEndpointAddr(ips []netip.Addr, prefer netip.Addr) (netip.Addr, bool) {
	if prefer.IsValid() {
		prefer = prefer.Unmap().WithZone("")
	}
	var first, familyMatch netip.Addr
	for _, raw := range ips {
		a := raw.Unmap().WithZone("")
		if !a.IsValid() {
			continue
		}
		if !first.IsValid() {
			first = a
		}
		if !prefer.IsValid() {
			return first, true
		}
		if a == prefer {
			return a, true
		}
		if !familyMatch.IsValid() && a.Is6() == prefer.Is6() {
			familyMatch = a
		}
	}
	if familyMatch.IsValid() {
		return familyMatch, true
	}
	if first.IsValid() {
		return first, true
	}
	return netip.Addr{}, false
}

// addrFromNetAddr extracts a normalized (unmapped, zoneless) IP from a net.Addr.
func addrFromNetAddr(a net.Addr) (netip.Addr, bool) {
	if a == nil {
		return netip.Addr{}, false
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		if ap := ta.AddrPort(); ap.IsValid() {
			return ap.Addr().Unmap().WithZone(""), true
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// uapiFull is the complete wireguard-go configuration for s. The caller must clear it.
func uapiFull(s *session) []byte {
	var b bytes.Buffer
	b.Grow(512) // no reallocation: every byte of secret material lives in one buffer
	priv := s.key.priv.Bytes()
	b.WriteString("private_key=")
	writeHex(&b, priv)
	clear(priv)
	b.WriteString("\nreplace_peers=true\npublic_key=")
	b.WriteString(hex.EncodeToString(s.edgePub))
	b.WriteString("\npreshared_key=")
	writeHex(&b, s.psk[:])
	b.WriteString("\nendpoint=")
	b.WriteString(s.endpoint)
	b.WriteString("\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
	return b.Bytes()
}

// uapiPSK updates only the pre-shared key of the existing Edge peer. The caller must clear it.
func uapiPSK(s *session) []byte {
	var b bytes.Buffer
	b.Grow(256)
	b.WriteString("public_key=")
	b.WriteString(hex.EncodeToString(s.edgePub))
	b.WriteString("\nupdate_only=true\npreshared_key=")
	writeHex(&b, s.psk[:])
	b.WriteString("\n")
	return b.Bytes()
}

// writeHex hex-encodes secret material without creating an immutable string copy.
func writeHex(b *bytes.Buffer, secret []byte) {
	var tmp [64]byte
	hex.Encode(tmp[:], secret)
	b.Write(tmp[:2*len(secret)])
	clear(tmp[:])
}
