package peek

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// clientHello captures the ClientHello crypto/tls sends for serverName, with a post-quantum
// key share so that it is larger than one TCP segment.
func clientHello(t testing.TB, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, //nolint:gosec // only the ClientHello is captured
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, MinVersion: tls.VersionTLS12})
		_ = cl.Handshake()
		_ = c.Close()
	}()
	var out []byte
	buf := make([]byte, 4096)
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := s.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
		if h, _, r := Host(out); r != NeedMore {
			_ = h
			break
		}
	}
	return out
}

func TestTLSSNI(t *testing.T) {
	ch := clientHello(t, "Www.Example.COM")
	if len(ch) < 1400 {
		t.Fatalf("ClientHello is only %d bytes; want one larger than a segment", len(ch))
	}
	// Every strict prefix needs more; the whole message gives the name.
	for _, cut := range []int{1, 4, 5, 6, 9, 100, 1300, len(ch) - 1} {
		if _, p, r := Host(ch[:cut]); r != NeedMore || p != ProtoTLS {
			t.Fatalf("prefix %d: %v %q", cut, r, p)
		}
	}
	if h, p, r := Host(ch); r != Found || h != "www.example.com" || p != ProtoTLS {
		t.Fatalf("got %q %q %v", h, p, r)
	}
	// Bytes after the ClientHello (early data) do not matter.
	if h, _, r := Host(append(ch, 0x17, 3, 3, 0, 1, 0)); r != Found || h != "www.example.com" {
		t.Fatalf("with trailing data: %q %v", h, r)
	}
}

func TestTLSNoSNI(t *testing.T) {
	ch := clientHello(t, "") // InsecureSkipVerify with no name: no server_name extension
	if h, _, r := Host(ch); r != Found || h != "" {
		t.Fatalf("got %q %v", h, r)
	}
}

func TestTLSSplitRecords(t *testing.T) {
	ch := clientHello(t, "split.example")
	body := ch[5:]
	// Re-frame the handshake message in 200-byte records, as some stacks do.
	var framed []byte
	for len(body) > 0 {
		n := min(200, len(body))
		framed = append(framed, 0x16, 3, 1, byte(n>>8), byte(n))
		framed = append(framed, body[:n]...)
		body = body[n:]
	}
	if h, _, r := Host(framed); r != Found || h != "split.example" {
		t.Fatalf("got %q %v", h, r)
	}
}

func TestHTTP(t *testing.T) {
	for _, tc := range []struct {
		in   string
		host string
		r    Result
	}{
		{"GET / HTTP/1.1\r\nHost: Example.org:8080\r\nAccept: */*\r\n\r\n", "example.org", Found},
		{"GET / HTTP/1.1\r\nhost:a.test\r\n\r\n", "a.test", Found},
		{"GET http://proxy.test/x HTTP/1.1\r\nHost: other.test\r\n\r\n", "proxy.test", Found},
		{"CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n", "tunnel.test", Found},
		{"GET / HTTP/1.0\r\n\r\n", "", Found},
		{"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n", "", NotApplicable},
		{"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n", "", NotApplicable},
		{"GET / HTTP/1.1\r\nHost: a.te", "", NeedMore},
		{"GE", "", NeedMore},
		{"GET / SPDY/3\r\n\r\n", "", NotApplicable},
		{"SSH-2.0-OpenSSH\r\n", "", NotApplicable},
		{"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00", "", NotApplicable}, // ServerHello, not ClientHello
	} {
		h, _, r := Host([]byte(tc.in))
		if h != tc.host || r != tc.r {
			t.Errorf("%q: got %q %v want %q %v", tc.in, h, r, tc.host, tc.r)
		}
	}
}

func TestLimits(t *testing.T) {
	big := append([]byte("GET / HTTP/1.1\r\nX: "), make([]byte, 9000)...)
	if _, _, r := Host(big); r != NotApplicable {
		t.Fatalf("unterminated HTTP head: %v", r)
	}
	// A ClientHello claiming 1 MiB is refused at once.
	if _, _, r := Host([]byte{0x16, 3, 1, 0x40, 0, 1, 0x10, 0, 0}); r != NotApplicable {
		t.Fatalf("huge ClientHello: %v", r)
	}
}

func FuzzHost(f *testing.F) {
	f.Add(clientHello(f, "fuzz.example"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, _, r := Host(b)
		if r != Found && h != "" {
			t.Fatal("host without Found")
		}
		if len(h) > 253 {
			t.Fatal("host too long")
		}
	})
}
