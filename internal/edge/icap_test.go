package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
)

// fakeICAP parses RESPMOD requests strictly and answers with reply(body, header).
func fakeICAP(t *testing.T, reply func(body []byte, req textproto.MIMEHeader) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				tp := textproto.NewReader(br)
				line, _ := tp.ReadLine()
				if !strings.HasPrefix(line, "RESPMOD icap://") || !strings.HasSuffix(line, " ICAP/1.0") {
					_, _ = io.WriteString(c, "ICAP/1.0 400 Bad Request\r\n\r\n")
					return
				}
				h, _ := tp.ReadMIMEHeader()
				enc := h.Get("Encapsulated")
				var hdrLen int
				if _, err := fmt.Sscanf(enc, "res-hdr=0, res-body=%d", &hdrLen); err != nil {
					_, _ = io.WriteString(c, "ICAP/1.0 400 Bad Request\r\n\r\n")
					return
				}
				resHdr := make([]byte, hdrLen)
				if _, err := io.ReadFull(br, resHdr); err != nil || !bytes.HasPrefix(resHdr, []byte("HTTP/1.1 200")) {
					return
				}
				var body bytes.Buffer
				for {
					sz, _ := tp.ReadLine()
					n, err := strconv.ParseInt(sz, 16, 64)
					if err != nil {
						return
					}
					if n == 0 {
						_, _ = tp.ReadLine()
						break
					}
					if _, err := io.CopyN(&body, br, n); err != nil {
						return
					}
					_, _ = tp.ReadLine()
				}
				_, _ = io.WriteString(c, reply(body.Bytes(), h))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestICAPScanner(t *testing.T) {
	addr := fakeICAP(t, func(body []byte, h textproto.MIMEHeader) string {
		switch {
		case h.Get("Allow") != "204":
			return "ICAP/1.0 400 Bad Request\r\n\r\n"
		case bytes.HasPrefix(body, []byte(eicar)):
			return "ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;\r\nEncapsulated: null-body=0\r\n\r\n"
		case bytes.Contains(body, []byte("policy")):
			return "ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n"
		case bytes.Contains(body, []byte("broken")):
			return "ICAP/1.0 500 Server Error\r\n\r\n"
		}
		return "ICAP/1.0 204 No Content\r\n\r\n"
	})
	s, err := newICAP("icap://" + addr + "/avscan")
	if err != nil {
		t.Fatal(err)
	}
	big := append([]byte(eicar), bytes.Repeat([]byte("x"), 3*avChunkSize)...)
	for name, tc := range map[string]struct {
		in      []byte
		want    string
		wantErr bool
	}{
		"clean":            {[]byte("hello"), "", false},
		"eicar":            {[]byte(eicar), "Eicar-Test-Signature", false},
		"eicar chunked":    {big, "Eicar-Test-Signature", false},
		"blocked, no name": {[]byte("policy violation"), "icap-blocked", false},
		"server error":     {[]byte("broken"), "", true},
	} {
		sig, err := s.scan(context.Background(), tc.in)
		if sig != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: %q %v", name, sig, err)
		}
	}
	for _, bad := range []string{"http://x/avscan", "icap:///avscan", "::"} {
		if _, err := newICAP(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if s2, _ := newICAP("icap://scanner.example/srv"); s2.host != "scanner.example:1344" {
		t.Errorf("default port %q", s2.host)
	}
	down, _ := newICAP("icap://127.0.0.1:1/avscan")
	if _, err := down.scan(context.Background(), []byte("x")); err == nil {
		t.Error("unreachable server: no error")
	}
}

// TestInspectionMalwareICAP: the inspection path uses the ICAP scanner like clamd.
func TestInspectionMalwareICAP(t *testing.T) {
	web := testWeb
	web.Malware.Uploads = true
	z := newInspectFixture(t, web)
	addr := fakeICAP(t, func(body []byte, _ textproto.MIMEHeader) string {
		if bytes.HasPrefix(body, []byte(eicar)) {
			return "ICAP/1.0 200 OK\r\nX-Virus-Id: Eicar-Test-Signature\r\nEncapsulated: null-body=0\r\n\r\n"
		}
		return "ICAP/1.0 204 No Content\r\n\r\n"
	})
	s, _ := newICAP("icap://" + addr + "/srv")
	z.e.av = s
	c := tlsClientFor(t, z)
	if code, _ := post(t, c, "", "hello"); code != 200 {
		t.Fatalf("clean: %d", code)
	}
	if code, _ := post(t, c, "", eicar); code != 403 || !z.hasRecord("malware:Eicar-Test-Signature") {
		t.Fatalf("eicar via icap: %d", code)
	}
}

func tlsClientFor(t *testing.T, z *inspectFixture) net.Conn {
	t.Helper()
	return tls.Client(z.dial(), &tls.Config{ServerName: "example.com", RootCAs: z.root, MinVersion: tls.VersionTLS12})
}
