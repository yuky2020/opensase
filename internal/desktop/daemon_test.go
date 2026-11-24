package desktop

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/internal/clientnet"
)

// fakeDevice implements tun.Device for testing.
type fakeDevice struct {
	closed bool
}

func (f *fakeDevice) File() *os.File                         { return nil }
func (f *fakeDevice) Read([][]byte, []int, int) (int, error) { return 0, io.EOF }
func (f *fakeDevice) Write([][]byte, int) (int, error)       { return 0, nil }
func (f *fakeDevice) BatchSize() int                         { return 1 }
func (f *fakeDevice) Name() (string, error)                  { return "fake0", nil }
func (f *fakeDevice) Events() <-chan tun.Event               { return nil }
func (f *fakeDevice) Close() error                           { f.closed = true; return nil }
func (f *fakeDevice) MTU() (int, error)                      { return 1420, nil }

type fakeEngine struct {
	mu          sync.Mutex
	enrolled    bool
	statusJSON  string
	flowsJSON   string
	tcJSON      string
	enrollCalls int
	lastURL     string
	lastKey     string
	lastName    string
	enrollErr   error
	startCalls  int
	stopCalls   int
}

func (f *fakeEngine) IsEnrolled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enrolled
}

func (f *fakeEngine) Enroll(controlURL, provisioningKey, deviceName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollCalls++
	f.lastURL = controlURL
	f.lastKey = provisioningKey
	f.lastName = deviceName
	if f.enrollErr != nil {
		return f.enrollErr
	}
	f.enrolled = true
	return nil
}

func (f *fakeEngine) Unenroll() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled = false
	return nil
}

func (f *fakeEngine) TunnelConfig() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tcJSON == "" {
		return `{"ipv4":"100.64.0.2","ipv6":"fd00::2","dns":["100.64.0.1"],"mtu":1420}`, nil
	}
	return f.tcJSON, nil
}

func (f *fakeEngine) StartDevice(dev tun.Device, networkType string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	return nil
}

func (f *fakeEngine) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
}

func (f *fakeEngine) Status() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusJSON == "" {
		return `{"state":"connected","enrolled":true,"deviceId":"dev-1"}`
	}
	return f.statusJSON
}

func (f *fakeEngine) RecentFlows(limit int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.flowsJSON == "" {
		return `[{"where":"device","deviceId":"dev-1"}]`
	}
	return f.flowsJSON
}

func (f *fakeEngine) BypassHosts() []string {
	return []string{"cp.example.com", "edge.example.com"}
}

type fakeNetManager struct {
	mu          sync.Mutex
	createCalls int
	configCalls int
	undoCalls   int
	createErr   error
	configErr   error
}

func (m *fakeNetManager) CreateTUN(name string, mtu int) (tun.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	if m.createErr != nil {
		return nil, m.createErr
	}
	return &fakeDevice{}, nil
}

func (m *fakeNetManager) Configure(ctx context.Context, dev tun.Device, c clientnet.Config, log *slog.Logger) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configCalls++
	if m.configErr != nil {
		return nil, m.configErr
	}
	return func() {
		m.mu.Lock()
		m.undoCalls++
		m.mu.Unlock()
	}, nil
}

func setupTestDaemon(t *testing.T, eng *fakeEngine, netMgr *fakeNetManager) *Daemon {
	t.Helper()
	if eng == nil {
		eng = &fakeEngine{enrolled: true}
	}
	if netMgr == nil {
		netMgr = &fakeNetManager{}
	}
	d, err := NewDaemon(Config{
		StateDir:       t.TempDir(),
		SocketGroup:    "",
		TUNName:        "test-tun0",
		NetworkType:    "ethernet",
		Logger:         slog.New(slog.DiscardHandler),
		Engine:         eng,
		NetworkManager: netMgr,
	})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	return d
}

func TestStatus(t *testing.T) {
	eng := &fakeEngine{enrolled: true, statusJSON: `{"state":"connected","edge":"edge-1"}`}
	d := setupTestDaemon(t, eng, nil)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/status", nil)
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code %d: %s", w.Code, w.Body.String())
	}

	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["connected"] != false {
		t.Errorf("expected connected=false, got %v", m["connected"])
	}
	if m["edge"] != "edge-1" {
		t.Errorf("expected edge=edge-1, got %v", m["edge"])
	}
}

func TestConnectDisconnectIdempotent(t *testing.T) {
	eng := &fakeEngine{enrolled: true}
	netMgr := &fakeNetManager{}
	d := setupTestDaemon(t, eng, netMgr)

	// First connect
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/connect", nil)
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("connect 1 failed: %d: %s", w.Code, w.Body.String())
	}
	if !d.IsConnected() {
		t.Errorf("expected connected=true")
	}
	if netMgr.createCalls != 1 || netMgr.configCalls != 1 {
		t.Fatalf("expected 1 create and 1 config call, got %d, %d", netMgr.createCalls, netMgr.configCalls)
	}

	// Second connect (idempotent)
	req2 := httptest.NewRequest(http.MethodPost, "http://localhost/v1/connect", nil)
	w2 := httptest.NewRecorder()
	d.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("connect 2 failed: %d: %s", w2.Code, w2.Body.String())
	}
	if netMgr.createCalls != 1 || netMgr.configCalls != 1 {
		t.Fatalf("expected create and config calls to remain 1, got %d, %d", netMgr.createCalls, netMgr.configCalls)
	}

	// First disconnect
	req3 := httptest.NewRequest(http.MethodPost, "http://localhost/v1/disconnect", nil)
	w3 := httptest.NewRecorder()
	d.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("disconnect 1 failed: %d: %s", w3.Code, w3.Body.String())
	}
	if d.IsConnected() {
		t.Errorf("expected connected=false")
	}
	if netMgr.undoCalls != 1 || eng.stopCalls != 1 {
		t.Fatalf("expected 1 undo and 1 stop call, got %d, %d", netMgr.undoCalls, eng.stopCalls)
	}

	// Second disconnect (idempotent)
	req4 := httptest.NewRequest(http.MethodPost, "http://localhost/v1/disconnect", nil)
	w4 := httptest.NewRecorder()
	d.Handler().ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("disconnect 2 failed: %d: %s", w4.Code, w4.Body.String())
	}
	if netMgr.undoCalls != 1 || eng.stopCalls != 1 {
		t.Fatalf("expected undo and stop calls to remain 1, got %d, %d", netMgr.undoCalls, eng.stopCalls)
	}
}

func TestEnrollRefusedWhileConnected(t *testing.T) {
	eng := &fakeEngine{enrolled: true}
	d := setupTestDaemon(t, eng, nil)

	// Connect first
	if err := d.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	body := `{"controlUrl":"https://cp:8443","provisioningKey":"secret-key","deviceName":"test-dev"}`
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/enroll", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnrollPassesValuesAndKeyNeverAppearsInResponses(t *testing.T) {
	secretKey := "super-secret-provisioning-key-XYZ"
	eng := &fakeEngine{
		enrolled:  false,
		enrollErr: fmt.Errorf("upstream rejected key %s during enrollment", secretKey),
	}
	d := setupTestDaemon(t, eng, nil)

	body := fmt.Sprintf(`{"controlUrl":"https://cp:8443","provisioningKey":%q,"deviceName":"my-laptop"}`, secretKey)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/enroll", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d: %s", w.Code, w.Body.String())
	}

	respStr := w.Body.String()
	if strings.Contains(respStr, secretKey) {
		t.Fatalf("CRITICAL SECURITY: response contains provisioning key! Response: %s", respStr)
	}
	if !strings.Contains(respStr, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in error response, got %s", respStr)
	}

	// Verify values passed to engine
	if eng.lastURL != "https://cp:8443" || eng.lastKey != secretKey || eng.lastName != "my-laptop" {
		t.Errorf("unexpected engine arguments: url=%s, key=%s, name=%s", eng.lastURL, eng.lastKey, eng.lastName)
	}
}

func TestUnknownFields400(t *testing.T) {
	eng := &fakeEngine{enrolled: false}
	d := setupTestDaemon(t, eng, nil)

	body := `{"controlUrl":"https://cp:8443","provisioningKey":"pk","deviceName":"dev","extraField":"not-allowed"}`
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/enroll", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unknown field") {
		t.Errorf("expected error message to mention unknown field, got: %s", w.Body.String())
	}
}

func TestBodyOver64KiB413(t *testing.T) {
	eng := &fakeEngine{enrolled: false}
	d := setupTestDaemon(t, eng, nil)

	largeData := strings.Repeat("A", 65*1024)
	body := fmt.Sprintf(`{"controlUrl":"https://cp:8443","provisioningKey":"%s","deviceName":"dev"}`, largeData)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/enroll", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEventsReplayOrder(t *testing.T) {
	d := setupTestDaemon(t, nil, nil)

	// Emit 5 events
	for i := 1; i <= 5; i++ {
		d.RecordEvent(fmt.Sprintf("kind-%d", i), fmt.Sprintf(`{"seq":%d}`, i))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/events", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		d.Handler().ServeHTTP(w, req)
		close(done)
	}()

	// Wait briefly for events to be written
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")

	var kinds []string
	var payloads []string
	for _, l := range lines {
		if strings.HasPrefix(l, "event: ") {
			kinds = append(kinds, strings.TrimPrefix(l, "event: "))
		} else if strings.HasPrefix(l, "data: ") {
			payloads = append(payloads, strings.TrimPrefix(l, "data: "))
		}
	}

	if len(kinds) != 5 {
		t.Fatalf("expected 5 replayed events, got %d: %s", len(kinds), body)
	}

	for i := 1; i <= 5; i++ {
		wantKind := fmt.Sprintf("kind-%d", i)
		wantPayload := fmt.Sprintf(`{"seq":%d}`, i)
		if kinds[i-1] != wantKind {
			t.Errorf("event %d: got kind %s, want %s", i, kinds[i-1], wantKind)
		}
		if payloads[i-1] != wantPayload {
			t.Errorf("event %d: got payload %s, want %s", i, payloads[i-1], wantPayload)
		}
	}
}

func TestSSEStreamReceivesNewEvent(t *testing.T) {
	d := setupTestDaemon(t, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/events", nil).WithContext(ctx)
	w := &pipeResponseWriter{header: make(http.Header), writer: pw}

	go func() {
		d.Handler().ServeHTTP(w, req)
		_ = pw.Close()
	}()

	reader := bufio.NewReader(pr)

	// Emit an event after the client connects
	time.Sleep(50 * time.Millisecond)
	d.RecordEvent("new-state", `{"state":"connected"}`)

	lineChan := make(chan string, 10)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			lineChan <- strings.TrimSpace(line)
		}
	}()

	var receivedEvent, receivedData bool
	timeout := time.After(2 * time.Second)
	for !receivedEvent || !receivedData {
		select {
		case line := <-lineChan:
			if line == "event: new-state" {
				receivedEvent = true
			}
			if line == `data: {"state":"connected"}` {
				receivedData = true
			}
		case <-timeout:
			t.Fatalf("timed out waiting for event on SSE stream; got event=%v, data=%v", receivedEvent, receivedData)
		}
	}
}

type pipeResponseWriter struct {
	header http.Header
	writer *io.PipeWriter
	status int
}

func (p *pipeResponseWriter) Header() http.Header         { return p.header }
func (p *pipeResponseWriter) Write(b []byte) (int, error) { return p.writer.Write(b) }
func (p *pipeResponseWriter) WriteHeader(status int)      { p.status = status }
func (p *pipeResponseWriter) Flush()                      {}

func TestHostHeaderCheck(t *testing.T) {
	d := setupTestDaemon(t, nil, nil)

	tests := []struct {
		name       string
		host       string
		wantStatus int
	}{
		{"localhost", "localhost", http.StatusOK},
		{"localhost with port", "localhost:8080", http.StatusOK},
		{"empty host", "", http.StatusOK},
		{"evil host", "evil.com", http.StatusForbidden},
		{"evil host with port", "evil.com:8080", http.StatusForbidden},
		{"ip literal", "192.168.1.1", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/status", nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			d.Handler().ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("host %q: got status %d, want %d", tc.host, w.Code, tc.wantStatus)
			}
		})
	}
}

func TestEventStreamLimit8(t *testing.T) {
	d := setupTestDaemon(t, nil, nil)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()
	// The test server's Host is 127.0.0.1:port; the API only accepts "localhost".
	open := func(ctx context.Context) (int, func()) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "localhost"
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, func() { _ = resp.Body.Close() }
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancels []context.CancelFunc
	for i := range 8 {
		cctx, ccancel := context.WithCancel(ctx)
		cancels = append(cancels, ccancel)
		code, closeBody := open(cctx)
		defer closeBody()
		if code != http.StatusOK {
			t.Fatalf("stream %d: got %d, want 200", i+1, code)
		}
	}
	if code, closeBody := open(ctx); code != http.StatusServiceUnavailable && code != http.StatusTooManyRequests {
		closeBody()
		t.Fatalf("9th stream: got %d, want 503 or 429", code)
	} else {
		closeBody()
	}
	cancels[0]()
	deadline := time.Now().Add(2 * time.Second)
	for {
		code, closeBody := open(ctx)
		closeBody()
		if code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream slot not released after cancellation: %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFlows(t *testing.T) {
	eng := &fakeEngine{flowsJSON: `[{"flow":{"domain":"example.org"}}]`}
	d := setupTestDaemon(t, eng, nil)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/flows?limit=10", nil)
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "example.org") {
		t.Errorf("expected flow record in response, got %s", w.Body.String())
	}
}

func TestServeWithUnixSocket(t *testing.T) {
	d := setupTestDaemon(t, nil, nil)

	sockPath := fmt.Sprintf("%s/test-%d.sock", t.TempDir(), time.Now().UnixNano())
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- d.Serve(ctx, ln)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get("http://localhost/v1/status")
	if err != nil {
		t.Fatalf("get status via unix socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serve error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("serve did not terminate on cancel")
	}
}
