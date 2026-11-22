package mobile

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestHostCache_Resolve(t *testing.T) {
	ctx := context.Background()

	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")
	ipLiteral := netip.MustParseAddr("198.51.100.1")

	lookupErr := errors.New("dns lookup failed")

	var (
		mu           sync.Mutex
		lookupIPs    []netip.Addr
		lookupErrRet error
		lookupCalls  int
	)

	hc := &hostCache{
		cache: make(map[string][]netip.Addr),
		lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			mu.Lock()
			defer mu.Unlock()
			lookupCalls++
			if lookupErrRet != nil {
				return nil, lookupErrRet
			}
			return lookupIPs, nil
		},
	}

	tests := []struct {
		name        string
		host        string
		setupLookup func()
		wantIPs     []netip.Addr
		wantErr     bool
		wantCalls   int
	}{
		{
			name: "first lookup succeeds and is cached",
			host: "cp.test",
			setupLookup: func() {
				mu.Lock()
				lookupErrRet = nil
				lookupIPs = []netip.Addr{ip1}
				mu.Unlock()
			},
			wantIPs:   []netip.Addr{ip1},
			wantErr:   false,
			wantCalls: 1,
		},
		{
			name: "later lookup fails and the cached address is returned",
			host: "cp.test",
			setupLookup: func() {
				mu.Lock()
				lookupErrRet = lookupErr
				lookupIPs = nil
				mu.Unlock()
			},
			wantIPs:   []netip.Addr{ip1},
			wantErr:   false,
			wantCalls: 2,
		},
		{
			name: "failure with an empty cache returns the error",
			host: "unknown.test",
			setupLookup: func() {
				mu.Lock()
				lookupErrRet = lookupErr
				lookupIPs = nil
				mu.Unlock()
			},
			wantErr:   true,
			wantCalls: 3,
		},
		{
			name: "IP literal bypasses lookup",
			host: ipLiteral.String(),
			setupLookup: func() {
				mu.Lock()
				lookupErrRet = lookupErr
				lookupIPs = nil
				mu.Unlock()
			},
			wantIPs:   []netip.Addr{ipLiteral},
			wantErr:   false,
			wantCalls: 3,
		},
		{
			name: "a new successful lookup replaces the cache",
			host: "cp.test",
			setupLookup: func() {
				mu.Lock()
				lookupErrRet = nil
				lookupIPs = []netip.Addr{ip2}
				mu.Unlock()
			},
			wantIPs:   []netip.Addr{ip2},
			wantErr:   false,
			wantCalls: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupLookup != nil {
				tt.setupLookup()
			}
			got, err := hc.resolve(ctx, tt.host)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolve(%q) err = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.wantIPs) {
				t.Fatalf("resolve(%q) = %v, want %v", tt.host, got, tt.wantIPs)
			}
			mu.Lock()
			calls := lookupCalls
			mu.Unlock()
			if calls != tt.wantCalls {
				t.Fatalf("lookupCalls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestHostCache_DialContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		close(accepted)
	}()

	fakeIP := netip.MustParseAddr("127.0.0.1")
	hc := &hostCache{
		cache: make(map[string][]netip.Addr),
		lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "cp.test" {
				return []netip.Addr{fakeIP}, nil
			}
			return nil, errors.New("unknown host")
		},
	}

	d := &net.Dialer{Timeout: 5 * time.Second}
	dial := hc.dialContext(d)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dial(ctx, "tcp", net.JoinHostPort("cp.test", port))
	if err != nil {
		t.Fatalf("dialContext failed: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}
}

func TestNewHostCache(t *testing.T) {
	hc := newHostCache(nil)
	if hc == nil {
		t.Fatal("newHostCache returned nil")
	}
	if hc.cache == nil {
		t.Fatal("newHostCache cache map is nil")
	}
	if hc.lookup == nil {
		t.Fatal("newHostCache lookup func is nil")
	}
}
