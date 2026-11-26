package mobile

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/yuky2020/opensase/pkg/api"
)

// Files in stateDir. All are written with mode 0600 via write-to-temp + rename.
const (
	fileDeviceKey     = "device.key"      // PKCS#8 PEM, ECDSA P-256
	fileDeviceCert    = "device.crt"      // PEM
	fileDeviceBundle  = "device.pem"      // renewed key + cert chain in one file (one atomic rename); preferred over key/crt
	fileEnrollment    = "enrollment.json" // api.EnrollResponse
	fileSnapshot      = "snapshot.json"   // last verified policy.Envelope
	fileUserRules     = "user_rules.json" // last api.UserRules sent with SetUserRules
	fileBootstrapCA   = "bootstrap-ca.pem"
	stateDirMode      = 0o700
	stateFileMode     = 0o600
	maxStateFileBytes = 16 << 20
)

// enrollment is the persisted device identity. cert is swapped on renewal; Leaf is set.
type enrollment struct {
	resp api.EnrollResponse
	cert atomic.Pointer[tls.Certificate]
	ca   *x509.CertPool
}

// leaf returns the current device certificate.
func (en *enrollment) leaf() *x509.Certificate { return en.cert.Load().Leaf }

func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(stateFileMode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := restrictPath(tmp.Name(), false); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

func readStateFile(dir, name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, name)) //nolint:gosec // G304: state dir from the app, name is a package constant
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxStateFileBytes {
		return nil, fmt.Errorf("mobile: %s too large", name)
	}
	b := make([]byte, st.Size())
	_, err = f.ReadAt(b, 0)
	return b, err
}

func saveEnrollment(dir string, key *ecdsa.PrivateKey, resp *api.EnrollResponse) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(keyPEM)
	js, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	// A bundle left over from a previous identity would shadow the new key pair.
	// Neither may the Edge list refreshed for a previous identity (issue #71).
	if err := os.Remove(filepath.Join(dir, fileEdges)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(filepath.Join(dir, fileDeviceBundle)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Key first, enrollment.json last: IsEnrolled checks the last file written.
	if err := writeFileAtomic(dir, fileDeviceKey, keyPEM); err != nil {
		return err
	}
	if err := writeFileAtomic(dir, fileDeviceCert, []byte(resp.CertificatePEM)); err != nil {
		return err
	}
	return writeFileAtomic(dir, fileEnrollment, js)
}

func loadEnrollment(dir string) (*enrollment, error) {
	js, err := readStateFile(dir, fileEnrollment)
	if err != nil {
		return nil, err
	}
	var resp api.EnrollResponse
	if err := json.Unmarshal(js, &resp); err != nil {
		return nil, fmt.Errorf("mobile: corrupt enrollment: %w", err)
	}
	var keyPEM, certPEM []byte
	if b, berr := readStateFile(dir, fileDeviceBundle); berr == nil {
		keyPEM, certPEM = b, b // tls.X509KeyPair skips blocks of the other kind
	} else if !errors.Is(berr, os.ErrNotExist) {
		return nil, berr
	} else {
		if keyPEM, err = readStateFile(dir, fileDeviceKey); err != nil {
			return nil, err
		}
		if certPEM, err = readStateFile(dir, fileDeviceCert); err != nil {
			clear(keyPEM)
			return nil, err
		}
	}
	defer clear(keyPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mobile: device key pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(resp.CAPEM)) {
		return nil, errors.New("mobile: enrollment has no usable CA")
	}
	en := &enrollment{resp: resp, ca: pool}
	en.cert.Store(&cert)
	return en, nil
}

// saveRenewedCert persists a renewed key and certificate chain as one file, written
// atomically, so a crash never leaves a key that does not match its certificate.
func saveRenewedCert(dir string, key *ecdsa.PrivateKey, chain [][]byte) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	var certs []byte
	for _, c := range chain {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	// Pre-sized: the key is copied exactly once, and both copies are wiped.
	buf := make([]byte, 0, len(keyPEM)+len(certs))
	buf = append(append(buf, keyPEM...), certs...)
	clear(keyPEM)
	defer clear(buf)
	return writeFileAtomic(dir, fileDeviceBundle, buf)
}

func removeState(dir string) error {
	var errs []error
	for _, n := range []string{fileEnrollment, fileDeviceBundle, fileDeviceCert, fileDeviceKey, fileSnapshot, fileUserRules, fileEdges} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
