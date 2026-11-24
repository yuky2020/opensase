//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startTestServer(t *testing.T, eng *fakeEngine, allowAdmin bool) (*Client, *Daemon, func()) {
	t.Helper()
	d := setupTestDaemon(t, eng, nil)

	sockPath := filepath.Join(t.TempDir(), fmt.Sprintf("test-%d.sock", time.Now().UnixNano()))
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	handler := d.Handler()
	if !allowAdmin {
		baseHandler := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			baseHandler.ServeHTTP(w, r.WithContext(withAdminOpAllowed(r.Context(), false)))
		})
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       connContextWithPeerCred,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}

	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
	}

	client := NewClient(dial)
	return client, d, cleanup
}

func TestClient(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "Status",
			run: func(t *testing.T) {
				eng := &fakeEngine{
					enrolled:   true,
					statusJSON: `{"state":"connected","edge":"edge-1","pq":true,"kex":"X25519MLKEM768","snapshotVersion":3}`,
				}
				client, _, cleanup := startTestServer(t, eng, true)
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				st, err := client.Status(ctx)
				if err != nil {
					t.Fatalf("Status error: %v", err)
				}
				if st["state"] != "connected" {
					t.Errorf("expected state=connected, got %v", st["state"])
				}
				if st["edge"] != "edge-1" {
					t.Errorf("expected edge=edge-1, got %v", st["edge"])
				}
				if st["pq"] != true {
					t.Errorf("expected pq=true, got %v", st["pq"])
				}
				if st["kex"] != "X25519MLKEM768" {
					t.Errorf("expected kex=X25519MLKEM768, got %v", st["kex"])
				}
			},
		},
		{
			name: "ConnectWhenNotEnrolled",
			run: func(t *testing.T) {
				eng := &fakeEngine{enrolled: false}
				client, _, cleanup := startTestServer(t, eng, true)
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				err := client.Connect(ctx)
				if err == nil {
					t.Fatal("expected Connect to fail when not enrolled")
				}
				if !strings.Contains(err.Error(), "not enrolled") {
					t.Errorf("expected daemon error 'not enrolled' in %q", err.Error())
				}
				if !strings.Contains(err.Error(), "400") {
					t.Errorf("expected status code 400 in %q", err.Error())
				}
			},
		},
		{
			name: "EnrollValidationError",
			run: func(t *testing.T) {
				eng := &fakeEngine{enrolled: false}
				client, _, cleanup := startTestServer(t, eng, true)
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				err := client.Enroll(ctx, "", "", "")
				if err == nil {
					t.Fatal("expected Enroll with empty params to fail")
				}
				expectedMsg := "controlUrl, provisioningKey, and deviceName are required"
				if !strings.Contains(err.Error(), expectedMsg) {
					t.Errorf("expected error %q in %q", expectedMsg, err.Error())
				}
				if !strings.Contains(err.Error(), "400") {
					t.Errorf("expected status code 400 in %q", err.Error())
				}
			},
		},
		{
			name: "FlowsLimit",
			run: func(t *testing.T) {
				eng := &fakeEngine{
					flowsJSON: `[{"flow":{"domain":"example.org"}},{"flow":{"domain":"test.org"}}]`,
				}
				client, _, cleanup := startTestServer(t, eng, true)
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				flows, err := client.Flows(ctx, 2)
				if err != nil {
					t.Fatalf("Flows error: %v", err)
				}
				if len(flows) != 2 {
					t.Fatalf("expected 2 flows, got %d", len(flows))
				}
				flow0, ok := flows[0]["flow"].(map[string]any)
				if !ok || flow0["domain"] != "example.org" {
					t.Errorf("unexpected flow[0]: %v", flows[0])
				}
			},
		},
		{
			name: "EventsParsing",
			run: func(t *testing.T) {
				eng := &fakeEngine{enrolled: true}
				client, d, cleanup := startTestServer(t, eng, true)
				defer cleanup()

				// Record two events: one single-line, one multi-line
				d.RecordEvent("state", "connected")
				d.RecordEvent("log", "line 1\nline 2\nline 3")

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				var received []Event
				err := client.Events(ctx, func(ev Event) error {
					received = append(received, ev)
					if len(received) == 2 {
						cancel()
					}
					return nil
				})
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("Events returned unexpected error: %v", err)
				}

				if len(received) != 2 {
					t.Fatalf("expected 2 events, got %d", len(received))
				}
				if received[0].Kind != "state" || received[0].Payload != "connected" {
					t.Errorf("event 0 mismatch: %+v", received[0])
				}
				if received[1].Kind != "log" || received[1].Payload != "line 1\nline 2\nline 3" {
					t.Errorf("event 1 mismatch: %+v", received[1])
				}
			},
		},
		{
			name: "Forbidden403Message",
			run: func(t *testing.T) {
				eng := &fakeEngine{enrolled: true}
				client, _, cleanup := startTestServer(t, eng, false) // allowAdmin = false
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				err := client.Unenroll(ctx)
				if err == nil {
					t.Fatal("expected Unenroll to return 403 error")
				}

				errMsg := err.Error()
				if !strings.Contains(errMsg, "403") {
					t.Errorf("expected '403' in error message: %s", errMsg)
				}
				if !strings.Contains(errMsg, "administrator privileges required") {
					t.Errorf("expected daemon error message in %s", errMsg)
				}
				if !strings.Contains(errMsg, "opensase") {
					t.Errorf("expected opensase group mention in %s", errMsg)
				}
				if !strings.Contains(errMsg, "root") && !strings.Contains(errMsg, "administrator") {
					t.Errorf("expected root or administrator mention in %s", errMsg)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}
