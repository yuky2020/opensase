package securitytest

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
)

// mint issues a leaf from parent (or self-signed when parent is nil) and returns it with
// the chain [leaf, parent...]. mod adjusts the template.
func mint(parent *pki.CA, mod func(*x509.Certificate)) (tls.Certificate, error) {
	k := newKey()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "sectest-forged"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if mod != nil {
		mod(tmpl)
	}
	pc, pk := tmpl, any(k)
	if parent != nil {
		pc, pk = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, &k.PublicKey, pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	c := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
	if parent != nil {
		c.Certificate = append(c.Certificate, parent.Cert.Raw)
	}
	return c, nil
}

func uris(ss ...string) func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		for _, s := range ss {
			u, _ := url.Parse(s)
			c.URIs = append(c.URIs, u)
		}
	}
}

// foreignTenantCA builds a CA chain that mimics the real one (root -> tenant CA with the
// same SPIFFE URI) under a root the stack has never seen.
func foreignTenantCA(tenant string) (*pki.CA, error) {
	root, err := pki.NewRootCA("OpenSASE Root CA")
	if err != nil {
		return nil, err
	}
	return root.NewTenantCA(tenant)
}

// handshake dials addr with only the given curves / version and reports the result.
func handshake(e *env, addr string, cert *tls.Certificate, curves []tls.CurveID, maxVer uint16, alpn []string) (tls.ConnectionState, error) {
	c := &tls.Config{RootCAs: e.rootPool, ServerName: e.serverSNI, CurvePreferences: curves, MinVersion: tls.VersionTLS12, MaxVersion: maxVer, NextProtos: alpn}
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, c)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

func hostPort(u string) string {
	p, _ := url.Parse(u)
	return p.Host
}

func TestPKIAndTLS(t *testing.T) {
	f := stack(t)
	listeners := map[string]*tls.Certificate{
		hostPort(f.cpURL):   nil,
		hostPort(f.edgeURL): &f.devA1.cert,
		f.broker:            &f.connA.cert,
	}

	// Classic key exchange (X25519 or P-256 only) and TLS 1.2 must fail the handshake on
	// every listener. Control: the hybrid group succeeds.
	check(t, "SEC-TLS-001", "classic TLS (X25519/P-256 only, TLS 1.2) refused on CP, Edge and broker", "", func(t *testing.T) error {
		var errs []error
		for addr, cert := range listeners {
			alpn := []string(nil)
			if addr == f.broker {
				alpn = []string{api.BrokerALPN}
			}
			if cs, err := handshake(f.env, addr, cert, []tls.CurveID{tls.X25519MLKEM768}, tls.VersionTLS13, alpn); err != nil || cs.CurveID != tls.X25519MLKEM768 {
				errs = append(errs, fmt.Errorf("control: PQ handshake to %s failed: %w", addr, err))
			}
			for name, curves := range map[string][]tls.CurveID{"X25519": {tls.X25519}, "P-256": {tls.CurveP256}, "P-384": {tls.CurveP384}} {
				if cs, err := handshake(f.env, addr, cert, curves, tls.VersionTLS13, alpn); err == nil {
					errs = append(errs, fmt.Errorf("%s accepted classic %s (curve %v)", addr, name, cs.CurveID))
				}
			}
			if _, err := handshake(f.env, addr, cert, nil, tls.VersionTLS12, alpn); err == nil {
				errs = append(errs, fmt.Errorf("%s accepted TLS 1.2", addr))
			}
		}
		return errors.Join(errs...)
	})

	// A client offering classic groups first must still end up on the hybrid group.
	check(t, "SEC-TLS-002", "mixed offer (X25519 first) still negotiates X25519MLKEM768", "", func(t *testing.T) error {
		for addr, cert := range listeners {
			alpn := []string(nil)
			if addr == f.broker {
				alpn = []string{api.BrokerALPN}
			}
			cs, err := handshake(f.env, addr, cert, []tls.CurveID{tls.X25519, tls.CurveP256, tls.X25519MLKEM768}, tls.VersionTLS13, alpn)
			if err != nil {
				return fmt.Errorf("%s: %w", addr, err)
			}
			if cs.CurveID != tls.X25519MLKEM768 {
				return fmt.Errorf("%s negotiated %v", addr, cs.CurveID)
			}
		}
		return nil
	})

	// Forged identities issued by a real tenant CA (tenant A's, from the dev PKI): the
	// chain verifies, so only the SPIFFE/role/serial checks stand in the way.
	check(t, "SEC-TLS-010", "wrong SPIFFE URIs from a valid tenant CA refused (CP and Edge)", "", func(t *testing.T) error {
		ca, err := f.tenantCA(f.tA)
		if err != nil {
			return skipf("tenant CA: %v", err)
		}
		const sp = "spiffe://opensase"
		cases := map[string]func(*x509.Certificate){
			"other-tenant device":   uris(sp + "/tenant/" + f.tB + "/device/" + f.devB1.id),
			"other trust domain":    uris("spiffe://evil/tenant/" + f.tA + "/device/" + f.devA1.id),
			"two URIs":              uris(sp+"/tenant/"+f.tA+"/device/"+f.devA1.id, sp+"/tenant/"+f.tA+"/device/x"),
			"no URI":                nil,
			"edge URI via tenantCA": uris(sp + "/edge/" + f.edgeID),
			"cp URI via tenantCA":   uris(sp + "/controlplane"),
			"traversal device id":   uris(sp + "/tenant/" + f.tA + "/device/../" + f.devA1.id),
			"extra path segment":    uris(sp + "/tenant/" + f.tA + "/device/" + f.devA1.id + "/x"),
			"real id, wrong serial": uris(sp + "/tenant/" + f.tA + "/device/" + f.devA1.id),
			"connector URI forged":  uris(sp + "/tenant/" + f.tA + "/connector/" + f.connA.id),
			"server EKU only": func(c *x509.Certificate) {
				uris(sp + "/tenant/" + f.tA + "/device/" + f.devA1.id)(c)
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
		}
		var errs []error
		for name, mod := range cases {
			cert, err := mint(ca, mod)
			if err != nil {
				return err
			}
			for _, rt := range [][2]string{{"GET", "/v1/snapshot"}, {"GET", "/v1/edge/peers"}, {"GET", "/v1/connector/config"}} {
				if err := refused(do(f.cp(cert), rt[0], f.cpURL+rt[1], nil, nil), name+" on "+rt[1], 401, 403); err != nil {
					errs = append(errs, err)
				}
			}
			if name != "real id, wrong serial" { // that case: SEC-TLS-012
				if err := edgeDenied(f.session(cert), name); err != nil {
					errs = append(errs, err)
				}
			}
			if name != "real id, wrong serial" && name != "connector URI forged" && brokerProbe(f.env, cert, api.BrokerALPN) == nil {
				errs = append(errs, fmt.Errorf("%s accepted by the broker", name))
			}
		}
		return errors.Join(errs...)
	})

	// A forged connector cert with a real connector ID but a serial the CP never issued.
	// The CP checks serials; the Edge broker only checks the peer feed (ID + tenant).
	check(t, "SEC-TLS-011", "tenant-CA-signed connector cert with unknown serial refused by the broker (ST-04)", "", func(t *testing.T) error {
		ca, err := f.tenantCA(f.tA)
		if err != nil {
			return skipf("tenant CA: %v", err)
		}
		cert, err := mint(ca, uris("spiffe://opensase/tenant/"+f.tA+"/connector/"+f.connA.id))
		if err != nil {
			return err
		}
		if err := refused(do(f.cp(cert), "GET", f.cpURL+"/v1/connector/config", nil, nil), "CP connector config", 403); err != nil {
			return err
		}
		if err := brokerProbe(f.env, f.connA.cert, api.BrokerALPN); err != nil {
			return fmt.Errorf("control: real connector A on the broker: %w", err)
		}
		if brokerProbe(f.env, cert, api.BrokerALPN) == nil {
			return errors.New("edge broker accepted a connector cert whose serial the CP never issued (no serial check at the Edge)")
		}
		return nil
	})

	// Same for devices: a tenant-CA-signed cert for a real device ID with a serial the CP
	// never issued. The CP refuses it (serial check); the Edge session channel must too.
	check(t, "SEC-TLS-012", "tenant-CA-signed device cert with unknown serial refused by the Edge (ST-01)", "", func(t *testing.T) error {
		ca, err := f.tenantCA(f.tA)
		if err != nil {
			return skipf("tenant CA: %v", err)
		}
		cert, err := mint(ca, uris("spiffe://opensase/tenant/"+f.tA+"/device/"+f.devA1.id))
		if err != nil {
			return err
		}
		if err := refused(do(f.cp(cert), "GET", f.cpURL+"/v1/snapshot", nil, nil), "CP snapshot", 403); err != nil {
			return err
		}
		if err := f.sessionOK(f.devA1.cert, 20*time.Second); err != nil {
			return fmt.Errorf("control: real device A1 on the edge: %w", err)
		}
		r := f.session(cert)
		if r.code != http.StatusForbidden {
			return fmt.Errorf("device cert with a serial the CP never issued: want 403, got %s", r)
		}
		return nil
	})

	// The same identity under a root the stack does not know.
	check(t, "SEC-TLS-020", "certificate chain from another root refused (CP, Edge, broker)", "", func(t *testing.T) error {
		ca, err := foreignTenantCA(f.tA)
		if err != nil {
			return err
		}
		dev, _ := mint(ca, uris("spiffe://opensase/tenant/"+f.tA+"/device/"+f.devA1.id))
		con, _ := mint(ca, uris("spiffe://opensase/tenant/"+f.tA+"/connector/"+f.connA.id))
		// Also with the foreign root appended (full chain).
		var errs []error
		if err := refused(do(f.cp(dev), "GET", f.cpURL+"/v1/snapshot", nil, nil), "foreign device on CP", 401, 403); err != nil {
			errs = append(errs, err)
		}
		if err := edgeDenied(f.session(dev), "foreign-root device"); err != nil {
			errs = append(errs, err)
		}
		if brokerProbe(f.env, con, api.BrokerALPN) == nil {
			errs = append(errs, errors.New("foreign connector accepted by broker"))
		}
		// An edge cert from a foreign root.
		froot, _ := pki.NewRootCA("OpenSASE Root CA")
		cp, kp, _ := froot.IssueServerCert(pki.ServerCertOptions{Kind: pki.KindEdge, ID: f.edgeID, DNSNames: []string{"localhost"}})
		fe, _ := tls.X509KeyPair(cp, kp)
		if err := refused(do(f.cp(fe), "GET", f.cpURL+"/v1/edge/peers", nil, nil), "foreign edge on CP", 401, 403); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	})

	// Expired and not-yet-valid certificates (otherwise valid chain from tenant A's CA).
	check(t, "SEC-TLS-021", "expired and not-yet-valid certificates refused", "", func(t *testing.T) error {
		ca, err := f.tenantCA(f.tA)
		if err != nil {
			return skipf("tenant CA: %v", err)
		}
		u := "spiffe://opensase/tenant/" + f.tA + "/device/" + f.devA1.id
		var errs []error
		for name, mod := range map[string]func(*x509.Certificate){
			"expired": func(c *x509.Certificate) {
				uris(u)(c)
				c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
			},
			"not yet valid": func(c *x509.Certificate) {
				uris(u)(c)
				c.NotBefore, c.NotAfter = time.Now().Add(time.Hour), time.Now().Add(48*time.Hour)
			},
		} {
			cert, err := mint(ca, mod)
			if err != nil {
				return err
			}
			if r := do(f.cp(cert), "GET", f.cpURL+"/v1/snapshot", nil, nil); r.err == nil {
				errs = append(errs, fmt.Errorf("%s cert got an HTTP response from the CP: %s", name, r))
			}
			if r := do(f.edge(cert), "POST", f.edgeURL+"/v1/session", `{"wgPublicKey":"`+randWGKey()+`","epoch":0}`, nil); r.err == nil {
				errs = append(errs, fmt.Errorf("%s cert got an HTTP response from the edge: %s", name, r))
			}
		}
		return errors.Join(errs...)
	})

	// Chain-shape: a device identity signed directly by the root (skipping the tenant CA),
	// and an Edge identity signed by a tenant CA.
	check(t, "SEC-TLS-022", "device cert issued directly by root refused (chain shape)", "", func(t *testing.T) error {
		root, err := f.rootCA()
		if err != nil {
			return skipf("root CA: %v", err)
		}
		cert, err := mint(root, uris("spiffe://opensase/tenant/"+f.tA+"/device/"+f.devA1.id))
		if err != nil {
			return err
		}
		if err := refused(do(f.cp(cert), "GET", f.cpURL+"/v1/snapshot", nil, nil), "root-signed device on CP", 401, 403); err != nil {
			return err
		}
		return edgeDenied(f.session(cert), "root-signed device")
	})

	// The broker requires ALPN opensase-broker/1: none, or another protocol, is refused.
	check(t, "SEC-TLS-030", "broker refuses a missing or wrong ALPN", "", func(t *testing.T) error {
		if err := brokerProbe(f.env, f.connA.cert, api.BrokerALPN); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		for _, alpn := range []string{"", "h2", "http/1.1", "opensase-broker/2"} {
			if brokerProbe(f.env, f.connA.cert, alpn) == nil {
				return fmt.Errorf("broker accepted ALPN %q", alpn)
			}
		}
		return nil
	})

	// The CP sends its full chain and its SPIFFE identity; the Edge answers as edge-1.
	// A client expecting the CP must not accept the Edge (review #1 regression).
	check(t, "SEC-TLS-040", "Edge certificate cannot pass as the Control Plane (review #1)", "", func(t *testing.T) error {
		c := httpClient(f.clientTLS([]tls.Certificate{f.devA1.cert}, pki.ServerControlPlane, ""))
		if r := do(c, "GET", f.edgeURL+"/v1/pki/ca", nil, nil); r.err == nil {
			return fmt.Errorf("client expecting the CP accepted the Edge: %s", r)
		}
		c = httpClient(f.clientTLS(nil, pki.ServerEdge, f.edgeID))
		if r := do(c, "GET", f.cpURL+"/v1/pki/ca", nil, nil); r.err == nil {
			return fmt.Errorf("client expecting the Edge accepted the CP: %s", r)
		}
		return nil
	})
}
