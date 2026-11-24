package desktop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminOpMiddlewareTable(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		allowAdmin bool
		wantStatus int
	}{
		{
			name:       "status allowed for non-admin",
			method:     http.MethodGet,
			path:       "/v1/status",
			allowAdmin: false,
			wantStatus: http.StatusOK,
		},
		{
			name:       "status allowed for admin",
			method:     http.MethodGet,
			path:       "/v1/status",
			allowAdmin: true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "connect allowed for non-admin",
			method:     http.MethodPost,
			path:       "/v1/connect",
			allowAdmin: false,
			wantStatus: http.StatusBadRequest, // reaches the handler (not 403): the fake engine is not enrolled
		},
		{
			name:       "disconnect allowed for non-admin",
			method:     http.MethodPost,
			path:       "/v1/disconnect",
			allowAdmin: false,
			wantStatus: http.StatusOK,
		},
		{
			name:       "flows allowed for non-admin",
			method:     http.MethodGet,
			path:       "/v1/flows",
			allowAdmin: false,
			wantStatus: http.StatusOK,
		},
		{
			name:       "enroll 403 when not admin",
			method:     http.MethodPost,
			path:       "/v1/enroll",
			body:       `{"controlUrl":"https://cp:8443","provisioningKey":"key","deviceName":"dev"}`,
			allowAdmin: false,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unenroll 403 when not admin",
			method:     http.MethodPost,
			path:       "/v1/unenroll",
			allowAdmin: false,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "enroll 200 path reached when admin",
			method:     http.MethodPost,
			path:       "/v1/enroll",
			body:       `{"controlUrl":"https://cp:8443","provisioningKey":"key","deviceName":"dev"}`,
			allowAdmin: true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "unenroll 200 path reached when admin",
			method:     http.MethodPost,
			path:       "/v1/unenroll",
			allowAdmin: true,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := setupTestDaemon(t, &fakeEngine{enrolled: false}, nil)
			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, "http://localhost"+tc.path, bodyReader)
			req = req.WithContext(withAdminOpAllowed(req.Context(), tc.allowAdmin))
			w := httptest.NewRecorder()
			d.Handler().ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("got status %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestAdminOpEnroll409PathReachedWhenAdmin(t *testing.T) {
	d := setupTestDaemon(t, &fakeEngine{enrolled: true}, nil)
	if err := d.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	body := `{"controlUrl":"https://cp:8443","provisioningKey":"key","deviceName":"dev"}`
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/enroll", strings.NewReader(body))
	req = req.WithContext(withAdminOpAllowed(req.Context(), true))
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when admin enrolls while connected, got %d: %s", w.Code, w.Body.String())
	}
}
