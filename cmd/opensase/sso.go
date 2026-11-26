package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ssoKey runs the identity provider sign-in for enrolment (issue #68): it listens on a
// loopback port, prints the sign-in URL for the user to open, and returns the single-use
// provisioning key the Control Plane sends back to the loopback URL.
func ssoKey(ctx context.Context, controlURL, tenant string) ([]byte, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = ln.Close() }()
	stateRaw := make([]byte, 16)
	if _, err := rand.Read(stateRaw); err != nil {
		return nil, err
	}
	state := hex.EncodeToString(stateRaw)
	returnTo := "http://" + ln.Addr().String() + "/callback"
	start := strings.TrimSuffix(controlURL, "/") + "/v1/enroll/oidc/" + url.PathEscape(tenant) + "/start?" +
		url.Values{"return_to": {returnTo}, "state": {state}}.Encode()

	got := make(chan []byte, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" || r.URL.Query().Get("state") != state || r.URL.Query().Get("code") == "" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>OpenSASE</title><p>"+html.EscapeString("Signed in. You can close this window and return to the terminal.")+"</p>")
		select {
		case got <- []byte(r.URL.Query().Get("code")):
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	fmt.Fprintf(os.Stderr, "Open this URL in a browser on this computer and sign in:\n\n  %s\n\nWaiting for the sign-in (5 minutes)...\n", start)
	select {
	case k := <-got:
		return k, nil
	case <-ctx.Done():
		return nil, errors.New("sign-in not completed in time")
	}
}
