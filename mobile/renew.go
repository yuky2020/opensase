package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
)

// Device certificate renewal (review #4). Device certificates are short-lived (24h); the
// device renews at 50% of the lifetime with a NEW key over mTLS with the current
// certificate (POST /v1/renew). An expired certificate cannot be renewed: the device must
// enroll again.

// errCertExpired is reported when the device certificate has expired.
var errCertExpired = errors.New("certificate expired, re-enrollment required")

const (
	defaultRenewRetryMin = 30 * time.Second
	renewRetryMax        = 10 * time.Minute
)

// renewAt is the point at which 50% of the certificate lifetime has elapsed.
func renewAt(c *x509.Certificate) time.Time {
	return c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2)
}

// checkCertValid returns errCertExpired once the device certificate is past NotAfter.
func checkCertValid(en *enrollment, now time.Time) error {
	if now.After(en.leaf().NotAfter) {
		return errCertExpired
	}
	return nil
}

// renewLoop renews the device certificate at 50% of its lifetime (immediately if that
// point has passed), retrying with backoff. It stops when the certificate has expired.
func (e *Engine) renewLoop(rs *runState) {
	defer rs.wg.Done()
	bo := backoff{min: e.renewRetryMin, max: renewRetryMax}
	for {
		leaf := rs.id.leaf()
		if wait := time.Until(renewAt(leaf)); wait > 0 && !sleep(rs.ctx, wait) {
			return
		}
		if rs.ctx.Err() != nil {
			return
		}
		if err := e.renew(rs.ctx, rs.id); err != nil {
			if rs.ctx.Err() != nil {
				return
			}
			if errors.Is(err, errCertExpired) {
				e.log.Error("device certificate expired", "notAfter", leaf.NotAfter)
				e.setState(StateError, errCertExpired.Error())
				return
			}
			e.log.Warn("certificate renewal failed", "err", err, "notAfter", leaf.NotAfter)
			e.emitError("renew", err)
			// Retry with backoff, but always once more shortly before expiry.
			d := bo.next()
			if left := time.Until(leaf.NotAfter); left > time.Second && d > left/2 {
				d = left / 2
			}
			if !sleep(rs.ctx, d) {
				return
			}
			continue
		}
		// A renewal that did not move the 50% point (a misbehaving CA) must not spin.
		if time.Until(renewAt(rs.id.leaf())) <= 0 {
			if !sleep(rs.ctx, bo.next()) {
				return
			}
			continue
		}
		bo.reset()
	}
}

// RenewNow renews the device certificate immediately. Go-only (gomobile skips methods with
// a context parameter): used by cmd/opensase-client -renew-now and the e2e test.
func (e *Engine) RenewNow(ctx context.Context) error {
	id := e.en.Load()
	if id == nil {
		return errors.New("mobile: not enrolled")
	}
	return e.renew(ctx, id)
}

// renew generates a new key and CSR, calls POST /v1/renew over the verified Control Plane
// connection, verifies the result, persists it atomically and hot-swaps the certificate
// for all clients: the Control Plane transport is replaced now; Edge session clients are
// built per epoch from the current certificate.
func (e *Engine) renew(ctx context.Context, id *identity) error {
	e.renewMu.Lock()
	defer e.renewMu.Unlock()
	cur := id.leaf()
	if err := checkCertValid(id.enrollment, time.Now()); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cur.Subject.CommonName},
	}, key)
	if err != nil {
		return err
	}
	req := api.RenewRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var resp api.RenewResponse
	httpResp, err := doJSON(rctx, id.cp, http.MethodPost, joinURL(id.resp.ControlURL, "/v1/renew"), nil, &req, &resp)
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	if httpResp.TLS == nil {
		return errors.New("renew: no TLS state")
	}
	if err := pki.ExpectServer(pki.ServerControlPlane, "")(*httpResp.TLS); err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	cert, err := checkRenewResponse(&resp, key, cur, id.ca, time.Now())
	if err != nil {
		return err
	}
	if err := saveRenewedCert(e.stateDir, key, cert.Certificate); err != nil {
		return fmt.Errorf("renew: persist: %w", err)
	}
	id.cert.Store(cert)
	id.tr.swap(pqTransport(mtlsConfig(id.enrollment, pki.ServerControlPlane, ""), e.protect, true))
	e.log.Info("device certificate renewed", "notAfter", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// checkRenewResponse verifies that the renewed certificate is for key, carries the same
// device identity as old, chains to the trusted tenant CA (roots from enrollment, not
// from the response) and does not expire before old.
func checkRenewResponse(r *api.RenewResponse, key *ecdsa.PrivateKey, old *x509.Certificate, roots *x509.CertPool, now time.Time) (*tls.Certificate, error) {
	certs, err := pki.ParseCertsPEM([]byte(r.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("renew: certificate is not for the new key")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if extra, err := pki.ParseCertsPEM([]byte(r.CAPEM)); err == nil {
		for _, c := range extra {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("renew: certificate does not chain to the tenant CA: %w", err)
	}
	if leaf.SerialNumber.Cmp(old.SerialNumber) == 0 {
		return nil, errors.New("renew: certificate reuses the current serial")
	}
	if !sameIdentity(leaf, old) {
		return nil, errors.New("renew: certificate is for another device identity")
	}
	// Equal is accepted: NotAfter has second precision, and a renewal right after
	// enrollment (e.g. -renew-now) can land in the same second.
	if leaf.NotAfter.Before(old.NotAfter) {
		return nil, errors.New("renew: certificate expires earlier than the current one")
	}
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

// sameIdentity reports whether both certificates carry exactly one device SPIFFE URI SAN
// and it is the same (spiffe://opensase/tenant/<t>/device/<d>).
func sameIdentity(a, b *x509.Certificate) bool {
	if len(a.URIs) != 1 || len(b.URIs) != 1 {
		return false
	}
	ia, err := pki.ParseURI(a.URIs[0].String())
	if err != nil || ia.Kind != pki.PeerDevice {
		return false
	}
	ib, err := pki.ParseURI(b.URIs[0].String())
	return err == nil && ia == ib
}
