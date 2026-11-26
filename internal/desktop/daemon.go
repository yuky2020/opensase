// Package desktop runs the client engine as a desktop daemon with a local API for the
// desktop UI (issue #31, ADR-0032).
package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/internal/clientnet"
	"github.com/yuky2020/opensase/internal/posture"
	"github.com/yuky2020/opensase/mobile"
)

const (
	maxRequestBodySize = 64 * 1024 // 64 KiB
	maxEventStreams    = 8
	eventRingCap       = 200
)

// Engine is the interface of mobile.Engine needed by the desktop daemon.
type Engine interface {
	IsEnrolled() bool
	Enroll(controlURL, provisioningKey, deviceName string) error
	Unenroll() error
	TunnelConfig() (string, error)
	StartDevice(dev tun.Device, networkType string) error
	Stop()
	Status() string
	RecentFlows(limit int) string
	BypassHosts() []string
	KillSwitch() bool
	SetPosture(postureJSON string) error
}

// NetworkManager abstracts TUN creation and network/route configuration.
type NetworkManager interface {
	CreateTUN(name string, mtu int) (tun.Device, error)
	Configure(ctx context.Context, dev tun.Device, c clientnet.Config, log *slog.Logger) (undo func(), err error)
}

type defaultNetworkManager struct{}

func (defaultNetworkManager) CreateTUN(name string, mtu int) (tun.Device, error) {
	return clientnet.CreateTUN(name, mtu)
}

func (defaultNetworkManager) Configure(ctx context.Context, dev tun.Device, c clientnet.Config, log *slog.Logger) (undo func(), err error) {
	return clientnet.Configure(ctx, dev, c, log)
}

// Config defines daemon parameters.
type Config struct {
	StateDir       string
	SocketGroup    string
	TUNName        string
	NetworkType    string
	ControlURL     string
	Logger         *slog.Logger
	Engine         Engine         // optional, for tests
	NetworkManager NetworkManager // optional, for tests
}

// Daemon manages the client engine and exposes a local HTTP API.
type Daemon struct {
	cfg     Config
	eng     Engine
	netMgr  NetworkManager
	log     *slog.Logger
	group   string
	tunName string
	netType string

	connMu    sync.Mutex
	connected bool
	undo      func()
	dev       tun.Device

	events *ringBuffer

	subMu       sync.Mutex
	subscribers map[chan Event]struct{}
	activeSubs  int
}

type daemonPlatform struct {
	d *Daemon
}

func (daemonPlatform) ConnectionOwnerUID(int, string, int, string, int) int { return -1 }
func (daemonPlatform) PackagesForUID(int) string                            { return "" }
func (daemonPlatform) Protect(int) bool                                     { return true }
func (p daemonPlatform) OnEvent(kind, payload string) {
	if p.d != nil {
		p.d.RecordEvent(kind, payload)
	}
}

// NewDaemon initializes a new daemon instance.
func NewDaemon(cfg Config) (*Daemon, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.NetworkManager == nil {
		cfg.NetworkManager = defaultNetworkManager{}
	}
	if cfg.NetworkType == "" {
		cfg.NetworkType = "ethernet"
	}
	if cfg.TUNName == "" {
		cfg.TUNName = clientnet.DefaultTUNName()
	}

	d := &Daemon{
		cfg:         cfg,
		netMgr:      cfg.NetworkManager,
		log:         cfg.Logger,
		group:       cfg.SocketGroup,
		tunName:     cfg.TUNName,
		netType:     cfg.NetworkType,
		events:      newRingBuffer(eventRingCap),
		subscribers: make(map[chan Event]struct{}),
	}

	if cfg.Engine != nil {
		d.eng = cfg.Engine
	} else {
		if cfg.StateDir == "" {
			return nil, errors.New("desktop: stateDir is required")
		}
		eng, err := mobile.NewEngine(cfg.StateDir, &daemonPlatform{d: d})
		if err != nil {
			return nil, fmt.Errorf("desktop: initialize engine: %w", err)
		}
		eng.SetLogHandler(d.log.Handler())
		d.eng = eng
		// A kill switch left by a daemon that crashed would keep the machine offline.
		if err := clientnet.CleanupKillSwitch(context.Background()); err != nil {
			d.log.Warn("leftover kill switch not removed", "err", err)
		}
	}

	return d, nil
}

// Engine returns the underlying engine.
func (d *Daemon) Engine() Engine {
	return d.eng
}

// IsConnected reports whether the tunnel is currently active.
func (d *Daemon) IsConnected() bool {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	return d.connected
}

func (d *Daemon) updatePosture() {
	p := posture.Collect()
	b, err := json.Marshal(p)
	if err != nil {
		d.log.Warn("marshal posture failed", "err", err)
		return
	}
	if err := d.eng.SetPosture(string(b)); err != nil {
		d.log.Warn("set posture failed", "err", err)
	}
}

// RecordEvent records an engine event in the ring buffer and dispatches to active event streams.
func (d *Daemon) RecordEvent(kind, payload string) {
	ev := Event{Kind: kind, Payload: payload}
	d.events.Add(ev)

	d.subMu.Lock()
	for ch := range d.subscribers {
		select {
		case ch <- ev:
		default:
			// Non-blocking write to avoid stalling daemon on slow SSE clients
		}
	}
	d.subMu.Unlock()
}

type tunnelConfigData struct {
	IPv4 string   `json:"ipv4"`
	IPv6 string   `json:"ipv6"`
	DNS  []string `json:"dns"`
	MTU  int      `json:"mtu"`
}

// Connect starts the tunnel interface and routing. It is idempotent.
func (d *Daemon) Connect(ctx context.Context) error {
	d.connMu.Lock()
	defer d.connMu.Unlock()

	if d.connected {
		return nil
	}

	if !d.eng.IsEnrolled() {
		return errors.New("not enrolled")
	}

	d.updatePosture()

	cfgJSON, err := d.eng.TunnelConfig()
	if err != nil {
		return fmt.Errorf("tunnel config: %w", err)
	}

	var tc tunnelConfigData
	if err := json.Unmarshal([]byte(cfgJSON), &tc); err != nil {
		return fmt.Errorf("parse tunnel config: %w", err)
	}

	dev, err := d.netMgr.CreateTUN(d.tunName, tc.MTU)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}

	devName := d.tunName
	if name, err := dev.Name(); err == nil && name != "" {
		devName = name
	}

	if err := d.eng.StartDevice(dev, d.netType); err != nil {
		// dev is closed by StartDevice on error
		return fmt.Errorf("start engine device: %w", err)
	}

	netCfg := clientnet.Config{
		Dev:        devName,
		IPv4:       tc.IPv4,
		IPv6:       tc.IPv6,
		MTU:        tc.MTU,
		Bypass:     d.eng.BypassHosts(),
		DNS:        tc.DNS,
		KillSwitch: d.eng.KillSwitch(),
	}

	undo, err := d.netMgr.Configure(ctx, dev, netCfg, d.log)
	if err != nil {
		d.eng.Stop()
		return fmt.Errorf("configure network: %w", err)
	}

	d.undo = undo
	d.dev = dev
	d.connected = true
	d.log.Info("tunnel connected", "dev", devName)
	return nil
}

// Disconnect stops the tunnel and undoes routing. It is idempotent.
func (d *Daemon) Disconnect() error {
	d.connMu.Lock()
	defer d.connMu.Unlock()

	if !d.connected {
		return nil
	}

	if d.undo != nil {
		d.undo()
		d.undo = nil
	}

	d.eng.Stop()
	d.connected = false
	d.dev = nil
	d.log.Info("tunnel disconnected")
	return nil
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func sanitizeError(err error, key string) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if key != "" && strings.Contains(s, key) {
		s = strings.ReplaceAll(s, key, "[REDACTED]")
	}
	return s
}

// Handler returns the HTTP handler for the daemon API.
func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/status", d.handleStatus)
	mux.HandleFunc("POST /v1/connect", d.handleConnect)
	mux.HandleFunc("POST /v1/disconnect", d.handleDisconnect)
	mux.HandleFunc("POST /v1/enroll", d.handleEnroll)
	mux.HandleFunc("POST /v1/unenroll", d.handleUnenroll)
	mux.HandleFunc("GET /v1/flows", d.handleFlows)
	mux.HandleFunc("GET /v1/events", d.handleEvents)

	// Wrap with access control and host header defense
	return hostHeaderMiddleware(d.peerAccessMiddleware(d.adminOpMiddleware(mux)))
}

type adminOpOverrideKey struct{}

// withAdminOpAllowed injects an allowAdminOp override into the context for testing.
func withAdminOpAllowed(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, adminOpOverrideKey{}, allow)
}

func (d *Daemon) adminOpMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimSuffix(r.URL.Path, "/")
		if (p == "/v1/enroll" || p == "/v1/unenroll") && r.Method == http.MethodPost {
			if !allowAdminOp(r.Context()) {
				writeJSONError(w, http.StatusForbidden, "forbidden: administrator privileges required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func hostHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Host
		if h != "" {
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			if h != "localhost" {
				writeJSONError(w, http.StatusForbidden, "forbidden: invalid host")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d *Daemon) peerAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkPeerAccess(r.Context(), d.group); err != nil {
			writeJSONError(w, http.StatusForbidden, err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (d *Daemon) handleStatus(w http.ResponseWriter, _ *http.Request) {
	stJSON := d.eng.Status()
	var stMap map[string]any
	if err := json.Unmarshal([]byte(stJSON), &stMap); err != nil {
		stMap = map[string]any{"raw": stJSON}
	}
	stMap["connected"] = d.IsConnected()
	writeJSON(w, http.StatusOK, stMap)
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	if err := d.Connect(r.Context()); err != nil {
		if strings.Contains(err.Error(), "not enrolled") {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true})
}

func (d *Daemon) handleDisconnect(w http.ResponseWriter, _ *http.Request) {
	if err := d.Disconnect(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": false})
}

type enrollRequest struct {
	ControlURL      string `json:"controlUrl"`
	ProvisioningKey string `json:"provisioningKey"`
	DeviceName      string `json:"deviceName"`
}

func (d *Daemon) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if d.IsConnected() {
		writeJSONError(w, http.StatusConflict, "cannot enroll while connected")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req enrollRequest
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.ControlURL == "" && d.cfg.ControlURL != "" {
		req.ControlURL = d.cfg.ControlURL
	}
	if req.ControlURL == "" || req.ProvisioningKey == "" || req.DeviceName == "" {
		writeJSONError(w, http.StatusBadRequest, "controlUrl, provisioningKey, and deviceName are required")
		return
	}

	d.updatePosture()

	if err := d.eng.Enroll(req.ControlURL, req.ProvisioningKey, req.DeviceName); err != nil {
		msg := sanitizeError(err, req.ProvisioningKey)
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"enrolled": true})
}

func (d *Daemon) handleUnenroll(w http.ResponseWriter, _ *http.Request) {
	_ = d.Disconnect()

	if err := d.eng.Unenroll(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrolled": false})
}

func (d *Daemon) handleFlows(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid limit parameter")
			return
		}
		limit = parsed
	}

	recsJSON := d.eng.RecentFlows(limit)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if recsJSON == "" {
		recsJSON = "[]"
	}
	_, _ = w.Write([]byte(recsJSON))
}

func formatSSE(kind, payload string) []byte {
	var b bytes.Buffer
	if kind != "" {
		fmt.Fprintf(&b, "event: %s\n", kind)
	}
	for _, line := range strings.Split(payload, "\n") {
		fmt.Fprintf(&b, "data: %s\n", line)
	}
	b.WriteString("\n")
	return b.Bytes()
}

func (d *Daemon) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	d.subMu.Lock()
	if d.activeSubs >= maxEventStreams {
		d.subMu.Unlock()
		writeJSONError(w, http.StatusTooManyRequests, "too many event streams")
		return
	}
	d.activeSubs++
	ch := make(chan Event, 64)
	d.subscribers[ch] = struct{}{}
	history := d.events.Snapshot()
	d.subMu.Unlock()

	defer func() {
		d.subMu.Lock()
		delete(d.subscribers, ch)
		d.activeSubs--
		d.subMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Replay ring buffer
	for _, ev := range history {
		if _, err := w.Write(formatSSE(ev.Kind, ev.Payload)); err != nil {
			return
		}
	}
	flusher.Flush()

	// Stream new events
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(formatSSE(ev.Kind, ev.Payload)); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// Serve starts the HTTP server on the provided listener until ctx is cancelled.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           d.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       connContextWithPeerCred,
	}

	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.updatePosture()
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
