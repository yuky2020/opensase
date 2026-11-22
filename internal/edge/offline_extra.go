package edge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/pki"
)

// Offline caches beyond state.json (issue #23, ADR-0014 addendum): the web categories in force
// and each tenant's inspection intermediate. Both are signed with the Edge's certificate key
// like state.json (ST-06), checked on load, and loaded at start, so a Private Edge restarted
// while the Control Plane is down keeps enforcing categories and inspecting TLS.

const categoriesCacheFile = "categories.cache"

func inspectCacheFile(tenant string) string { return "inspect-" + tenant + ".cache" }

type cachedCategories struct {
	SavedAt time.Time `json:"savedAt"`
	Tenant  string    `json:"tenant"` // the Edge's -tenant, "" for a public Edge
	Names   []string  `json:"names"`
	ETag    string    `json:"etag"`
	Data    []byte    `json:"data"` // pkg/categories wire format
}

// saveCategories persists the category data just fetched.
func (e *Edge) saveCategories(names []string, etag string, data []byte) {
	if e.cfg.StateDir == "" {
		return
	}
	body, err := json.Marshal(cachedCategories{SavedAt: time.Now().UTC(), Tenant: e.cfg.TenantID, Names: names, ETag: etag, Data: data})
	if err == nil {
		var j []byte
		if j, err = e.signState(body); err == nil {
			err = writeFileAtomic(filepath.Join(e.cfg.StateDir, categoriesCacheFile), j)
		}
	}
	if err != nil {
		e.log.Warn("web category cache not saved", "err", err)
	}
}

// loadCategories restores the cached categories. They are refreshed from the Control Plane as
// soon as it answers, because the load time counts as their age.
func (e *Edge) loadCategories() error {
	if e.cfg.StateDir == "" {
		return os.ErrNotExist
	}
	j, err := os.ReadFile(filepath.Join(e.cfg.StateDir, categoriesCacheFile))
	if err != nil {
		return err
	}
	body, err := e.verifyState(j)
	if err != nil {
		return fmt.Errorf("edge: category cache: %w", err)
	}
	var c cachedCategories
	if err := json.Unmarshal(body, &c); err != nil {
		return fmt.Errorf("edge: category cache: %w", err)
	}
	if c.Tenant != e.cfg.TenantID {
		return fmt.Errorf("edge: category cache is for tenant %q, edge runs as %q", c.Tenant, e.cfg.TenantID)
	}
	db, err := categories.Decode(bytes.NewReader(c.Data))
	if err != nil {
		return fmt.Errorf("edge: category cache: %w", err)
	}
	slices.Sort(c.Names)
	// Age zero: the next sync revalidates them with their ETag.
	e.cats.Store(&catSet{db: db, names: c.Names, etag: c.ETag, at: time.Time{}})
	e.log.Info("web categories loaded from cache", "categories", len(c.Names), "savedAt", c.SavedAt)
	return nil
}

type cachedInspection struct {
	Tenant  string   `json:"tenant"`
	Chain   [][]byte `json:"chain"` // DER: intermediate, root
	Key     []byte   `json:"key"`   // PKCS#8 of the intermediate key
	LeafKey []byte   `json:"leafKey"`
}

// saveInspection persists a tenant's inspection intermediate and keys. The file holds a
// signing key valid for at most 7 days; it is 0600 in the state directory, next to the
// Edge's own certificate key, so it adds no exposure beyond that key's.
func (e *Edge) saveInspection(tenant string, ca *inspectCA) {
	if e.cfg.StateDir == "" {
		return
	}
	k, err := x509.MarshalPKCS8PrivateKey(ca.key)
	var lk []byte
	if err == nil {
		lk, err = x509.MarshalPKCS8PrivateKey(ca.leafKey)
	}
	if err == nil {
		var body, j []byte
		if body, err = json.Marshal(cachedInspection{Tenant: tenant, Chain: ca.chain, Key: k, LeafKey: lk}); err == nil {
			if j, err = e.signState(body); err == nil {
				err = writeFileAtomic(filepath.Join(e.cfg.StateDir, inspectCacheFile(tenant)), j)
			}
		}
	}
	if err != nil {
		e.log.Warn("inspection intermediate not cached", "tenant", tenant, "err", err)
	}
}

// loadInspection restores every cached intermediate that is still valid, belongs to a
// tenant the Edge may serve, matches its key and chains to its root.
func (e *Edge) loadInspection() {
	if e.cfg.StateDir == "" || e.insp == nil {
		return
	}
	files, _ := filepath.Glob(filepath.Join(e.cfg.StateDir, "inspect-*.cache"))
	for _, path := range files {
		ca, tenant, err := e.readInspection(path)
		if err != nil {
			e.log.Warn("inspection cache unusable", "file", filepath.Base(path), "err", err)
			continue
		}
		e.insp.mu.Lock()
		if cur := e.insp.cas[tenant]; cur == nil || !cur.usable(time.Now()) {
			e.insp.cas[tenant] = ca
		}
		e.insp.mu.Unlock()
		e.log.Info("inspection intermediate loaded from cache", "tenant", tenant, "notAfter", ca.cert.NotAfter)
	}
}

func (e *Edge) readInspection(path string) (*inspectCA, string, error) {
	j, err := os.ReadFile(path) //nolint:gosec // G304: a file of the operator-configured state dir
	if err != nil {
		return nil, "", err
	}
	body, err := e.verifyState(j)
	if err != nil {
		return nil, "", err
	}
	var c cachedInspection
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, "", err
	}
	if !pki.ValidID(c.Tenant) || filepath.Base(path) != inspectCacheFile(c.Tenant) {
		return nil, "", errors.New("tenant does not match the file")
	}
	if e.cfg.TenantID != "" && c.Tenant != e.cfg.TenantID {
		return nil, "", fmt.Errorf("cache is for tenant %q, edge runs as %q", c.Tenant, e.cfg.TenantID)
	}
	if len(c.Chain) != 2 {
		return nil, "", errors.New("chain must be intermediate and root")
	}
	ic, err := x509.ParseCertificate(c.Chain[0])
	if err != nil {
		return nil, "", err
	}
	root, err := x509.ParseCertificate(c.Chain[1])
	if err != nil {
		return nil, "", err
	}
	if err := ic.CheckSignatureFrom(root); err != nil || !ic.IsCA || !ic.MaxPathLenZero {
		return nil, "", errors.New("intermediate does not chain to its root as a leaf-only CA")
	}
	if !time.Now().Before(ic.NotAfter) {
		return nil, "", errors.New("intermediate expired")
	}
	k, err := x509.ParsePKCS8PrivateKey(c.Key)
	if err != nil {
		return nil, "", err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(ic.PublicKey) {
		return nil, "", errors.New("key does not match the intermediate")
	}
	lk, err := x509.ParsePKCS8PrivateKey(c.LeafKey)
	if err != nil {
		return nil, "", err
	}
	leafKey, ok := lk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, "", errors.New("leaf key is not ECDSA")
	}
	return &inspectCA{cert: ic, chain: c.Chain, key: key, leafKey: leafKey, leaves: map[string]*tls.Certificate{}}, c.Tenant, nil
}
