package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
	"github.com/yuky2020/opensase/pkg/store"
)

type ctxKey int

const (
	keyPeer ctxKey = iota
	keyAdmin
)

// peer is the authenticated identity of a request.
type peer struct {
	id        pki.Identity
	device    store.Device    // set for devices
	connector store.Connector // set for Connectors
}

func peerFrom(ctx context.Context) (peer, bool) {
	p, ok := ctx.Value(keyPeer).(peer)
	return p, ok
}

// statusRecorder captures the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the connection (per-route deadlines).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// logRequests logs method, path (never the query or body), status and duration.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		lvl := slog.LevelInfo
		if rec.code >= 500 {
			lvl = slog.LevelError
		}
		attrs := []any{"method", r.Method, "path", r.URL.Path, "status", rec.code, "dur", time.Since(start).Round(time.Microsecond)}
		if p, ok := peerFrom(r.Context()); ok {
			attrs = append(attrs, "peer", p.id.Kind.String(), "tenant", p.id.TenantID, "device", p.id.DeviceID, "edge", p.id.EdgeID, "connector", p.id.ConnectorID)
		}
		s.log.Log(r.Context(), lvl, "http", attrs...)
	})
}

// requirePQ rejects any request whose connection did not negotiate X25519MLKEM768.
// Harden already restricts the curves; this is defence in depth.
func (s *Server) requirePQ(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || pqsession.CheckPostQuantum(*r.TLS) != nil {
			writeErr(w, http.StatusUpgradeRequired, "post-quantum TLS required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// identify extracts the peer identity from the verified client certificate chain.
func (s *Server) identify(r *http.Request) (pki.Identity, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return pki.Identity{}, errors.New("client certificate required")
	}
	return pki.VerifyPeerChains(r.TLS.VerifiedChains, s.cfg.Authority.Root.Cert)
}

// authDevice checks that the certificate belongs to a known, non-revoked device of the
// tenant in the certificate, with the serial currently on record. With allowPrev, the serial
// superseded by the last renewal is accepted too (only for retrying POST /v1/renew).
func (s *Server) authDevice(r *http.Request, id pki.Identity, allowPrev bool) (store.Device, int, error) {
	d, err := s.cfg.Store.GetDevice(r.Context(), id.DeviceID)
	if errors.Is(err, store.ErrNotFound) {
		return d, http.StatusForbidden, errors.New("unknown device")
	}
	if err != nil {
		return d, http.StatusInternalServerError, err
	}
	serial := r.TLS.VerifiedChains[0][0].SerialNumber.String()
	match := d.CertSerial == serial || (allowPrev && d.PrevCertSerial != "" && d.PrevCertSerial == serial)
	if d.TenantID != id.TenantID || !match {
		return d, http.StatusForbidden, errors.New("certificate does not match device")
	}
	if d.Revoked {
		return d, http.StatusForbidden, errors.New("device revoked")
	}
	if d.PrevCertSerial != "" && serial == d.CertSerial {
		// The renewed certificate is in use: the superseded one is now dead (ST-02).
		if err := s.cfg.Store.ForgetPrevDeviceSerial(r.Context(), d.ID, serial); err != nil {
			return d, http.StatusInternalServerError, err
		}
		d.PrevCertSerial = ""
	}
	return d, 0, nil
}

// authConnector is authDevice for Connectors (ADR-0013): the connector must exist in the
// certificate's tenant, be enrolled and not revoked, and the certificate serial must be the
// current one (or, with allowPrev, the one superseded by the last renewal).
func (s *Server) authConnector(r *http.Request, id pki.Identity, allowPrev bool) (store.Connector, int, error) {
	c, err := s.cfg.Store.GetConnector(r.Context(), id.ConnectorID)
	if errors.Is(err, store.ErrNotFound) {
		return c, http.StatusForbidden, errors.New("unknown connector")
	}
	if err != nil {
		return c, http.StatusInternalServerError, err
	}
	serial := r.TLS.VerifiedChains[0][0].SerialNumber.String()
	match := (c.CertSerial != "" && c.CertSerial == serial) || (allowPrev && c.PrevCertSerial != "" && c.PrevCertSerial == serial)
	if c.TenantID != id.TenantID || !match {
		return c, http.StatusForbidden, errors.New("certificate does not match connector")
	}
	if c.Revoked {
		return c, http.StatusForbidden, errors.New("connector revoked")
	}
	if c.PrevCertSerial != "" && serial == c.CertSerial {
		if err := s.cfg.Store.ForgetPrevConnectorSerial(r.Context(), c.ID, serial); err != nil {
			return c, http.StatusInternalServerError, err
		}
		c.PrevCertSerial = ""
	}
	return c, 0, nil
}

// authEdge checks that the edge ID is registered and not revoked (security review #9).
func (s *Server) authEdge(r *http.Request, id pki.Identity) (int, error) {
	e, err := s.cfg.Store.GetEdge(r.Context(), id.EdgeID)
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusForbidden, errors.New("edge not registered")
	}
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if e.Revoked {
		return http.StatusForbidden, errors.New("edge revoked")
	}
	return 0, nil
}

// Roles accepted by requireRole.
const (
	roleDevice    = 1 << iota
	roleEdge      // registered, non-revoked edges
	roleRenewal   // with roleDevice or roleConnector: also the certificate superseded by the last renewal
	roleConnector // enrolled, non-revoked Connectors (ADR-0013)
)

func (s *Server) requireRole(roles int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := s.identify(r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "valid client certificate required")
				return
			}
			p := peer{id: id}
			var code int
			switch {
			case id.Kind == pki.PeerDevice && roles&roleDevice != 0:
				p.device, code, err = s.authDevice(r, id, roles&roleRenewal != 0)
			case id.Kind == pki.PeerEdge && roles&roleEdge != 0:
				code, err = s.authEdge(r, id)
			case id.Kind == pki.PeerConnector && roles&roleConnector != 0:
				p.connector, code, err = s.authConnector(r, id, roles&roleRenewal != 0)
			default:
				code, err = http.StatusForbidden, errors.New("certificate role not allowed on this route")
			}
			if err != nil {
				if code >= 500 {
					s.internalErr(w, r, "peer lookup", err)
					return
				}
				writeErr(w, code, err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyPeer, p)))
		})
	}
}

func (s *Server) requireDevice(next http.Handler) http.Handler {
	return s.requireRole(roleDevice)(next)
}
func (s *Server) requireEdge(next http.Handler) http.Handler { return s.requireRole(roleEdge)(next) }
func (s *Server) requireDeviceOrEdge(next http.Handler) http.Handler {
	return s.requireRole(roleDevice | roleEdge)(next)
}
