package connector

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

const (
	dialTimeout = 5 * time.Second
	streamIdle  = 5 * time.Minute
	copyChunk   = 32 << 10
)

// Resolver resolves app names; *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialHandler serves POST /v1/dial (ADR-0013, the connector side of the broker channel).
// It is the second enforcement point: only name:port pairs of Apps are dialled, and resolved
// addresses that are loopback (unless AllowLoopback), link-local, multicast or unspecified
// are refused, so a compromised Edge cannot use the connector to scan its LAN.
type DialHandler struct {
	Apps          func() []policy.PrivateApp // current ConnectorConfig.Apps
	Resolver      Resolver                   // default net.DefaultResolver
	AllowLoopback bool                       // tests only
	Log           *slog.Logger
	EdgeID        string // for logs
	Idle          time.Duration
	Dialer        *net.Dialer
}

func (h *DialHandler) log() *slog.Logger {
	if h.Log == nil {
		return slog.Default()
	}
	return h.Log
}

// allowedAddr reports whether a resolved address may be dialled.
func (h *DialHandler) allowedAddr(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsMulticast(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return false
	case a.IsLoopback():
		return h.AllowLoopback
	}
	return true
}

func (h *DialHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/dial" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	target := r.Header.Get(api.BrokerHeaderTarget)
	device := r.Header.Get(api.BrokerHeaderDevice)
	appHdr := r.Header.Get(api.BrokerHeaderApp)
	lg := h.log().With("edge", h.EdgeID, "target", target, "app", appHdr, "device", device)
	host, portStr, err := net.SplitHostPort(target)
	port, perr := strconv.ParseUint(portStr, 10, 16)
	if err != nil || perr != nil || port == 0 || host == "" {
		lg.Info("dial refused: bad target")
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	var apps []policy.PrivateApp
	if h.Apps != nil {
		apps = h.Apps()
	}
	app, ok := MatchApp(apps, host, uint16(port))
	if !ok {
		lg.Info("dial refused: target not in connector apps")
		http.Error(w, "target not allowed", http.StatusForbidden)
		return
	}
	lg = lg.With("app", app.ID)
	res := h.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()
	addrs, err := res.LookupNetIP(ctx, "ip", normalize(host))
	if err != nil {
		lg.Info("dial failed: resolve", "err", err)
		http.Error(w, "resolve failed", http.StatusBadGateway)
		return
	}
	var ok2 []netip.Addr
	for _, a := range addrs {
		if h.allowedAddr(a) {
			ok2 = append(ok2, a.Unmap())
		}
	}
	if len(ok2) == 0 {
		lg.Warn("dial refused: name resolves only to forbidden addresses", "addrs", addrs)
		http.Error(w, "address not allowed", http.StatusForbidden)
		return
	}
	d := h.Dialer
	if d == nil {
		d = &net.Dialer{KeepAlive: 30 * time.Second}
	}
	var backend net.Conn
	for _, a := range ok2 {
		backend, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			break
		}
	}
	if backend == nil {
		lg.Info("dial failed", "err", err)
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	defer backend.Close()
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex() // HTTP/1 only; HTTP/2 is already full duplex
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		lg.Info("dial aborted: flush", "err", err)
		return
	}
	start := time.Now()
	lg.Info("connection opened", "remote", backend.RemoteAddr().String())
	idle := h.Idle
	if idle <= 0 {
		idle = streamIdle
	}
	out, in, abnormal := pipe(r.Context(), backend, r.Body, flushWriter{w, rc}, idle)
	lg.Info("connection closed", "bytesToApp", out, "bytesFromApp", in, "abnormal", abnormal, "duration", time.Since(start).Round(time.Millisecond).String())
	if abnormal {
		// Make the HTTP/2 stream end with RST_STREAM rather than a clean END_STREAM.
		panic(http.ErrAbortHandler)
	}
}

// flushWriter flushes every write so app bytes are not held in the response buffer.
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		err = f.rc.Flush()
	}
	return n, err
}

type counter struct {
	w    io.Writer
	n    *atomic.Uint64
	last *atomic.Int64
}

func (c counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(uint64(n))
	c.last.Store(time.Now().UnixNano())
	return n, err
}

// pipe copies body -> backend (then half-closes backend) and backend -> resp. When the app
// finishes sending (backend EOF), the stream ends: an HTTP/2 handler cannot end its response
// and keep reading the request. It also ends on error, when ctx is done, or after idle
// without bytes in either direction; abnormal reports those cases.
func pipe(ctx context.Context, backend net.Conn, body io.ReadCloser, resp io.Writer, idle time.Duration) (out, in uint64, abnormal bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var nOut, nIn atomic.Uint64
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var bad, downDone atomic.Bool
	upDone, down := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(upDone)
		_, err := io.CopyBuffer(counter{backend, &nOut, &last}, body, make([]byte, copyChunk))
		if err != nil {
			if !downDone.Load() {
				bad.Store(true)
				cancel()
			}
			return
		}
		if hc, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}()
	go func() {
		defer close(down)
		_, err := io.CopyBuffer(counter{resp, &nIn, &last}, backend, make([]byte, copyChunk))
		if err != nil {
			bad.Store(true)
			cancel()
			return
		}
		downDone.Store(true)
		_ = body.Close() // unblock the upstream copy; the handler returns and ends the stream
	}()
	tick := time.NewTicker(min(idle/4, 30*time.Second))
	defer tick.Stop()
	finish := func() (uint64, uint64, bool) {
		<-upDone
		<-down
		return nOut.Load(), nIn.Load(), bad.Load()
	}
	for {
		select {
		case <-down:
			return finish()
		case <-ctx.Done():
			bad.Store(true)
		case <-tick.C:
			if time.Since(time.Unix(0, last.Load())) < idle {
				continue
			}
			bad.Store(true)
		}
		cancel()
		_ = backend.Close()
		_ = body.Close()
		return finish()
	}
}
