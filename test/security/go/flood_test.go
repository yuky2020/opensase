package securitytest

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

// Destructive checks: floods against the local stack only (loopback), opt-in with
// SECTEST_DESTRUCTIVE=1. They may slow the dev stack down for a few seconds.
func TestFlood(t *testing.T) {
	f := stack(t)
	if os.Getenv("SECTEST_DESTRUCTIVE") != "1" {
		check(t, "SEC-IN-201", "idle-connection flood (slowloris) does not starve the CP", "", func(*testing.T) error {
			return skipf("destructive: set SECTEST_DESTRUCTIVE=1")
		})
		return
	}

	// 1500 TCP connections that never send a ClientHello, held open: a legitimate client
	// must still be served, and the idle ones must be closed by the server's timeouts.
	check(t, "SEC-IN-201", "idle-connection flood (slowloris) does not starve the CP", "", func(t *testing.T) error {
		u, _ := url.Parse(f.cpURL)
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
		for range 1500 {
			c, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
			if err != nil {
				break
			}
			conns = append(conns, c)
		}
		if len(conns) < 1000 {
			return skipf("only %d connections could be opened", len(conns))
		}
		start := time.Now()
		r := do(f.anon(), "GET", f.cpURL+"/v1/pki/ca", nil, nil)
		if r.code != 200 {
			return fmt.Errorf("with %d idle connections: %s", len(conns), r)
		}
		if d := time.Since(start); d > 5*time.Second {
			return fmt.Errorf("with %d idle connections a request took %v", len(conns), d)
		}
		// The server must drop connections that never handshake (ReadHeaderTimeout 10s).
		time.Sleep(13 * time.Second)
		alive := 0
		for _, c := range conns[:min(50, len(conns))] {
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := c.Read(make([]byte, 1)); err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					alive++
				}
			}
		}
		if alive > 0 {
			return fmt.Errorf("%d of 50 idle pre-handshake connections still open after 13s", alive)
		}
		return nil
	})
}
