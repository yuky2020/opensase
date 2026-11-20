package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// Private Edge support (ADR-0014): single-tenant scoping, a local cache of the last good
// Control Plane state for offline operation, and a local flow log.

// stateFile is the cache file inside Config.StateDir.
const stateFile = "state.json"

// cachedState is the content of stateFile.
type cachedState struct {
	SavedAt time.Time     `json:"savedAt"`
	Tenant  string        `json:"tenant,omitempty"`
	Bundle  api.PKIBundle `json:"bundle"`
	Peers   api.EdgePeers `json:"peers"`
}

// scopePeers drops devices and connectors of other tenants when the Edge is single-tenant.
// The Control Plane already scopes a Private Edge's feed, so a drop means a
// misconfiguration (the -tenant flag does not match the registration) and is logged.
func (e *Edge) scopePeers(p api.EdgePeers) api.EdgePeers {
	t := e.cfg.TenantID
	if t == "" {
		return p
	}
	out := api.EdgePeers{Devices: make([]api.EdgeDevice, 0, len(p.Devices)), Connectors: make([]api.EdgeConnector, 0, len(p.Connectors))}
	for _, d := range p.Devices {
		if d.TenantID == t {
			out.Devices = append(out.Devices, d)
		}
	}
	for _, c := range p.Connectors {
		if c.TenantID == t {
			out.Connectors = append(out.Connectors, c)
		}
	}
	if dropped := len(p.Devices) + len(p.Connectors) - len(out.Devices) - len(out.Connectors); dropped > 0 {
		e.log.Warn("peer feed holds other tenants; dropped (check -tenant against the edge registration)", "tenant", t, "dropped", dropped)
	}
	return out
}

// stateHash identifies the cached content, so that an unchanged state is not rewritten on
// every peer sync.
func stateHash(b api.PKIBundle, p api.EdgePeers) ([32]byte, error) {
	j, err := json.Marshal(struct {
		B api.PKIBundle
		P api.EdgePeers
	}{b, p})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(j), nil
}

// saveState writes the state to StateDir atomically (temp file, fsync, rename, mode 0600)
// when it changed since the last write. No-op without StateDir.
func (e *Edge) saveState(b api.PKIBundle, p api.EdgePeers) error {
	if e.cfg.StateDir == "" {
		return nil
	}
	h, err := stateHash(b, p)
	if err != nil {
		return err
	}
	if h == e.stateSum {
		return nil
	}
	body, err := json.Marshal(cachedState{SavedAt: time.Now().UTC(), Tenant: e.cfg.TenantID, Bundle: b, Peers: p})
	if err != nil {
		return err
	}
	j, err := e.signState(body)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(e.cfg.StateDir, stateFile), j); err != nil {
		return fmt.Errorf("edge: save state: %w", err)
	}
	e.stateSum = h
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) //nolint:errcheck // best effort: gone after a successful rename
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir) //nolint:gosec // G304: dir is the operator-configured state dir
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// loadState applies the cached state, as untrusted input: tenant CAs must chain to the root
// and every snapshot must verify, exactly as for a live Control Plane response. It returns
// the save time, or an error (fs.ErrNotExist when there is no cache).
func (e *Edge) loadState() (time.Time, error) {
	if e.cfg.StateDir == "" {
		return time.Time{}, fs.ErrNotExist
	}
	j, err := os.ReadFile(filepath.Join(e.cfg.StateDir, stateFile))
	if err != nil {
		return time.Time{}, err
	}
	body, err := e.verifyState(j)
	if err != nil {
		return time.Time{}, fmt.Errorf("edge: cached state: %w", err)
	}
	var st cachedState
	if err := json.Unmarshal(body, &st); err != nil {
		return time.Time{}, fmt.Errorf("edge: cached state: %w", err)
	}
	if st.Tenant != e.cfg.TenantID {
		return time.Time{}, fmt.Errorf("edge: cached state is for tenant %q, edge runs as %q", st.Tenant, e.cfg.TenantID)
	}
	// The cache may have been relabelled or edited: scope it again (ST-07).
	st.Peers = e.scopePeers(st.Peers)
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	if err := e.applyState(st.Bundle, st.Peers); err != nil {
		return time.Time{}, fmt.Errorf("edge: cached state: %w", err)
	}
	if h, err := stateHash(st.Bundle, st.Peers); err == nil {
		e.stateSum = h
	}
	return st.SavedAt, nil
}

// signedState is the on-disk form of stateFile: the cachedState JSON signed with the Edge's
// own certificate key (ST-06). Snapshot signatures alone do not protect the cache, because
// the cache also carries the snapshot keys; with this signature, writing a usable cache
// requires the Edge private key, not only write access to the state dir.
type signedState struct {
	State     json.RawMessage `json:"state"`
	Signature []byte          `json:"signature"`
}

func (e *Edge) signState(body []byte) ([]byte, error) {
	signer, ok := e.cfg.Cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("edge: certificate key cannot sign the state cache")
	}
	msg, opts := body, crypto.Hash(0) // Ed25519 signs the message itself
	if _, isEd := signer.(ed25519.PrivateKey); !isEd {
		d := sha256.Sum256(body)
		msg, opts = d[:], crypto.SHA256
	}
	sig, err := signer.Sign(rand.Reader, msg, opts)
	if err != nil {
		return nil, fmt.Errorf("edge: sign state: %w", err)
	}
	return json.Marshal(signedState{State: body, Signature: sig})
}

func (e *Edge) verifyState(j []byte) ([]byte, error) {
	var ss signedState
	if err := json.Unmarshal(j, &ss); err != nil {
		return nil, err
	}
	if len(e.cfg.Cert.Certificate) == 0 {
		return nil, errors.New("no edge certificate")
	}
	leaf, err := x509.ParseCertificate(e.cfg.Cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(ss.State)
	var ok bool
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(pub, d[:], ss.Signature)
	case ed25519.PublicKey:
		ok = ed25519.Verify(pub, ss.State, ss.Signature)
	default:
		return nil, fmt.Errorf("unsupported edge key type %T", pub)
	}
	if !ok {
		return nil, errors.New("signature does not verify with the edge certificate (tampered, or written by another edge)")
	}
	return ss.State, nil
}

// localFlowLog appends flow records as JSON lines to a local file, rotated to <path>.1 at
// maxBytes. Writes happen on a background goroutine; records are dropped (and counted) when
// it falls behind, so the packet path never blocks on disk.
type localFlowLog struct {
	path     string
	maxBytes int64
	ch       chan []api.FlowRecord
	dropped  atomic.Uint64
	log      *slog.Logger
}

const (
	flowLogMaxBytes = 64 << 20
	flowLogQueue    = 1024
)

func newLocalFlowLog(path string, log *slog.Logger) *localFlowLog {
	return &localFlowLog{path: path, maxBytes: flowLogMaxBytes, ch: make(chan []api.FlowRecord, flowLogQueue), log: log}
}

func (l *localFlowLog) add(recs []api.FlowRecord) {
	if l == nil || len(recs) == 0 {
		return
	}
	select {
	case l.ch <- append([]api.FlowRecord(nil), recs...):
	default:
		l.dropped.Add(uint64(len(recs)))
	}
}

// run writes queued records until ctx ends, then drains the queue.
func (l *localFlowLog) run(ctx context.Context) error {
	f, size, err := l.open()
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	defer func() {
		if f != nil {
			_ = w.Flush()
			_ = f.Close()
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var line bytes.Buffer
	write := func(recs []api.FlowRecord) {
		for _, r := range recs {
			if f == nil {
				return // reopen failed; the next rotation attempt is at restart
			}
			line.Reset()
			if err := json.NewEncoder(&line).Encode(r); err != nil {
				continue
			}
			if size+int64(line.Len()) > l.maxBytes {
				if err := l.rotate(w, f); err != nil {
					l.log.Warn("flow log rotate failed", "err", err)
				}
				nf, ns, err := l.open()
				if err != nil {
					l.log.Warn("flow log reopen failed; local flow logging stopped", "err", err)
					f = nil
					return
				}
				f, size = nf, ns
				w.Reset(f)
			}
			n, _ := w.Write(line.Bytes())
			size += int64(n)
		}
	}
	for {
		select {
		case recs := <-l.ch:
			write(recs)
		case <-tick.C:
			if f != nil {
				_ = w.Flush()
			}
			if n := l.dropped.Swap(0); n > 0 {
				l.log.Warn("flow log fell behind; records dropped", "dropped", n)
			}
		case <-ctx.Done():
			for {
				select {
				case recs := <-l.ch:
					write(recs)
				default:
					return nil
				}
			}
		}
	}
}

func (l *localFlowLog) open() (*os.File, int64, error) {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: operator-configured path
	if err != nil {
		return nil, 0, fmt.Errorf("edge: flow log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func (l *localFlowLog) rotate(w *bufio.Writer, f *os.File) error {
	err := errors.Join(w.Flush(), f.Close())
	if rerr := os.Rename(l.path, l.path+".1"); rerr != nil {
		err = errors.Join(err, rerr)
	}
	return err
}
