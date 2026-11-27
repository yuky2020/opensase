package edge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// wgConfigurer is the subset of *device.Device the session server needs.
type wgConfigurer interface {
	IpcSetOperation(r io.Reader) error
}

// sessionServer handles POST /v1/session.
type sessionServer struct {
	e *Edge
}

func (s *sessionServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/session", s.handleSession)
	mux.HandleFunc("GET /v1/session/{id}", s.handleSessionProbe)
	return mux
}

// tlsConfig requires a device certificate chained to a tenant CA from the PKI bundle.
func (e *Edge) sessionTLSConfig() *tls.Config {
	base := pqsession.Harden(&tls.Config{
		Certificates: []tls.Certificate{e.cfg.Cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h2", "http/1.1"},
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *sessionServer) handleSession(w http.ResponseWriter, r *http.Request) {
	e := s.e
	if r.TLS == nil || pqsession.CheckPostQuantum(*r.TLS) != nil {
		writeErr(w, http.StatusUpgradeRequired, "post-quantum TLS required")
		return
	}
	id, err := pki.VerifyPeerChains(r.TLS.VerifiedChains, e.cfg.Root)
	if err != nil || id.Kind != pki.PeerDevice {
		writeErr(w, http.StatusForbidden, "device certificate required")
		return
	}
	var req api.SessionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	clientPub, err := base64.StdEncoding.DecodeString(req.WGPublicKey)
	if err != nil || len(clientPub) != 32 || isZero(clientPub) {
		writeErr(w, http.StatusBadRequest, "wgPublicKey must be a base64 Curve25519 public key")
		return
	}

	// Possibly enrolled after the last peer sync: lookupDevice refreshes, rate-limited.
	ctx, cancel := context.WithTimeout(r.Context(), minSyncInterval+5*time.Second)
	d := e.lookupDevice(ctx, id.DeviceID)
	cancel()
	if d == nil || d.tenantID != id.TenantID || d.compiled.Load() == nil {
		writeErr(w, http.StatusForbidden, "unknown or revoked device")
		return
	}
	// Only the device's current certificate (ST-01): a just-renewed one may be newer than the
	// last feed, so a mismatch triggers the same rate-limited on-demand sync.
	serial := r.TLS.VerifiedChains[0][0].SerialNumber.String()
	sctx, scancel := context.WithTimeout(r.Context(), minSyncInterval+5*time.Second)
	current := e.findAfterSync(sctx, "serial:"+id.DeviceID+"/"+serial, func() bool {
		s := e.reg.serial(id.DeviceID)
		return s != "" && s == serial
	})
	scancel()
	if !current {
		writeErr(w, http.StatusForbidden, "certificate superseded or not issued to this device")
		return
	}

	resp, code, err := e.setupSession(r.Context(), d, *r.TLS, [32]byte(clientPub), req)
	if err != nil {
		if code >= 500 {
			e.log.ErrorContext(r.Context(), "session setup failed", "device", id.DeviceID, "err", err)
			writeErr(w, code, "internal error")
		} else {
			writeErr(w, code, err.Error())
		}
		return
	}
	e.triggerReport()
	// The device's first connection must already take the right path (issue #22).
	e.reconcileInspect(r.Context())
	e.log.InfoContext(r.Context(), "session established", "tenant", id.TenantID, "device", id.DeviceID,
		"session", resp.SessionID, "epoch", resp.Epoch, "ipv4", resp.TunnelIPv4, "ipv6", resp.TunnelIPv6, "kex", "X25519MLKEM768")
	writeJSON(w, http.StatusOK, resp)
}

// handleSessionProbe answers 204 if the calling device's current session on this Edge is id,
// 404 otherwise (issue #70). Clients probe it when the tunnel is idle: after an Edge restart
// the session is gone and the client sets up a new one at once instead of waiting for the
// WireGuard handshake to go stale.
func (s *sessionServer) handleSessionProbe(w http.ResponseWriter, r *http.Request) {
	e := s.e
	if r.TLS == nil || pqsession.CheckPostQuantum(*r.TLS) != nil {
		writeErr(w, http.StatusUpgradeRequired, "post-quantum TLS required")
		return
	}
	id, err := pki.VerifyPeerChains(r.TLS.VerifiedChains, e.cfg.Root)
	if err != nil || id.Kind != pki.PeerDevice {
		writeErr(w, http.StatusForbidden, "device certificate required")
		return
	}
	want := r.PathValue("id")
	e.reg.mu.Lock()
	d := e.reg.devices[id.DeviceID]
	live := d != nil && d.tenantID == id.TenantID && d.hasPeer && want != "" && d.sessionID == want
	e.reg.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	if !live {
		writeErr(w, http.StatusNotFound, "no such session; start a new one with epoch 0")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setupSession allocates the tunnel address, derives the PSK on this TLS connection and
// installs or rotates the WireGuard peer. Serialized by the registry lock.
//
// Epochs: 0 starts a new session; current+1 rotates; current again re-derives the PSK of the
// current epoch on this new connection and replaces it (idempotent retry after a lost
// response, security review #5). Older epochs and skips are rejected.
func (e *Edge) setupSession(_ context.Context, d *device, cs tls.ConnectionState, clientPub [32]byte, req api.SessionRequest) (api.SessionResponse, int, error) {
	r := e.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.devices[d.id] != d {
		return api.SessionResponse{}, http.StatusForbidden, errors.New("device was removed")
	}
	sessionID, epoch := d.sessionID, req.Epoch
	switch {
	case req.Epoch == 0:
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return api.SessionResponse{}, http.StatusInternalServerError, err
		}
		sessionID = hex.EncodeToString(b[:])
	case d.sessionID == "" || req.SessionID != d.sessionID:
		return api.SessionResponse{}, http.StatusConflict, errors.New("unknown session; start a new one with epoch 0")
	case req.Epoch != d.epoch && req.Epoch != d.epoch+1:
		return api.SessionResponse{}, http.StatusConflict, fmt.Errorf("epoch must be %d or %d", d.epoch, d.epoch+1)
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return api.SessionResponse{}, http.StatusForbidden, errors.New("device certificate required")
	}
	notAfter := cs.VerifiedChains[0][0].NotAfter
	if req.Epoch == 0 {
		r.placeLocked(d)
	}
	if err := r.allocateLocked(d); err != nil {
		return api.SessionResponse{}, http.StatusServiceUnavailable, err
	}
	psk, err := pqsession.DerivePSK(cs, clientPub[:], e.wgPub[:], sessionID, epoch)
	if err != nil {
		return api.SessionResponse{}, http.StatusUpgradeRequired, err
	}
	defer clear(psk[:])

	var buf bytes.Buffer
	buf.Grow(512) // no reallocation, so no stray copies of the PSK
	if d.hasPeer && d.wgPub != clientPub {
		writePeerRemove(&buf, d.wgPub)
	}
	writePeerConfig(&buf, clientPub, psk, d, e.ipv6)
	err = e.wg.IpcSetOperation(bytes.NewReader(buf.Bytes()))
	clear(buf.Bytes())
	if err != nil {
		return api.SessionResponse{}, http.StatusInternalServerError, fmt.Errorf("configure wireguard peer: %w", err)
	}
	d.wgPub, d.hasPeer, d.sessionID, d.epoch, d.certNotAfter = clientPub, true, sessionID, epoch, notAfter
	d.sessionSerial, d.staleSince = cs.VerifiedChains[0][0].SerialNumber.String(), time.Time{}

	dns := []string{EdgeIPv4.String()}
	var tunnelIPv6 string
	if e.ipv6 {
		dns = append(dns, EdgeIPv6.String())
		tunnelIPv6 = d.ip6.String() + "/128"
	}
	return api.SessionResponse{
		SessionID:      sessionID,
		Epoch:          epoch,
		TunnelIPv4:     d.ip4.String() + "/32",
		TunnelIPv6:     tunnelIPv6,
		DNSServers:     dns,
		EdgeWGKey:      base64.StdEncoding.EncodeToString(e.wgPub[:]),
		WGEndpoint:     e.cfg.WGEndpoint,
		RotateAfterSec: int(e.cfg.RotateAfter / time.Second),
		MTU:            e.cfg.MTU,
	}, http.StatusOK, nil
}

// removePeer deletes a device's WireGuard peer (revoked or unknown device).
func (e *Edge) removePeer(d *device) {
	if !d.hasPeer {
		return
	}
	var buf bytes.Buffer
	writePeerRemove(&buf, d.wgPub)
	if err := e.wg.IpcSetOperation(&buf); err != nil {
		e.log.Error("remove wireguard peer", "device", d.id, "err", err)
		return
	}
	e.log.Info("device removed", "device", d.id, "tenant", d.tenantID)
}

// UAPI writers (keys are hex in the UAPI protocol).

func writePeerRemove(b *bytes.Buffer, pub [32]byte) {
	b.WriteString("public_key=")
	writeHex(b, pub[:])
	b.WriteString("\nremove=true\n")
}

func writePeerConfig(b *bytes.Buffer, pub [32]byte, psk [32]byte, d *device, ipv6 bool) {
	b.WriteString("public_key=")
	writeHex(b, pub[:])
	b.WriteString("\npreshared_key=")
	writeHex(b, psk[:])
	writeAllowedIPs(b, d, ipv6)
}

func writePeerAllowedIPs(b *bytes.Buffer, pub [32]byte, d *device, ipv6 bool) {
	b.WriteString("public_key=")
	writeHex(b, pub[:])
	writeAllowedIPs(b, d, ipv6)
}

func writeAllowedIPs(b *bytes.Buffer, d *device, ipv6 bool) {
	b.WriteString("\nreplace_allowed_ips=true\nallowed_ip=")
	b.WriteString(d.ip4.String())
	b.WriteString("/32\n")
	if ipv6 {
		b.WriteString("allowed_ip=")
		b.WriteString(d.ip6.String())
		b.WriteString("/128\n")
	}
	for _, r := range d.routes {
		if !ipv6 && r.Addr().Is6() {
			continue
		}
		b.WriteString("allowed_ip=")
		b.WriteString(r.String())
		b.WriteString("\n")
	}
}

func writeHex(b *bytes.Buffer, p []byte) {
	var tmp [64]byte
	hex.Encode(tmp[:], p)
	b.Write(tmp[:2*len(p)])
	clear(tmp[:])
}

func isZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
