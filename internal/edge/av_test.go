package edge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// eicar is the standard antivirus test string, assembled at run time so that the source file
// itself does not trip scanners.
var eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

// fakeClamd serves the INSTREAM protocol and reports eicar as a signature.
func fakeClamd(t *testing.T, reply func([]byte) string) string {
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
				r := bufio.NewReader(c)
				cmd, err := r.ReadString(0)
				if err != nil || cmd != "zINSTREAM\x00" {
					_, _ = c.Write([]byte("UNKNOWN COMMAND\x00"))
					return
				}
				var data bytes.Buffer
				for {
					var n uint32
					if binary.Read(r, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					if _, err := io.CopyN(&data, r, int64(n)); err != nil {
						return
					}
				}
				_, _ = c.Write([]byte(reply(data.Bytes()) + "\x00"))
			}()
		}
	}()
	return ln.Addr().String()
}

// eicarReply is like clamd: the test file is recognised only at the start of the content.
func eicarReply(b []byte) string {
	if bytes.HasPrefix(b, []byte(eicar)) {
		return "stream: Eicar-Test-Signature FOUND"
	}
	return "stream: OK"
}

func TestClamdClient(t *testing.T) {
	c := clamd{addr: fakeClamd(t, eicarReply)}
	big := append([]byte(eicar), bytes.Repeat([]byte("a"), 3*avChunkSize+7)...) // several chunks
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"clean":         {[]byte("hello"), ""},
		"eicar":         {[]byte(eicar), "Eicar-Test-Signature"},
		"eicar chunked": {big, "Eicar-Test-Signature"},
		"empty":         {nil, ""},
	} {
		sig, err := c.scan(context.Background(), tc.in)
		if err != nil || sig != tc.want {
			t.Errorf("%s: %q %v", name, sig, err)
		}
	}
	if _, err := (clamd{}).scan(context.Background(), []byte("x")); err == nil {
		t.Error("no address: no error")
	}
	if _, err := (clamd{addr: "127.0.0.1:1"}).scan(context.Background(), []byte("x")); err == nil {
		t.Error("unreachable: no error")
	}
	bad := clamd{addr: fakeClamd(t, func([]byte) string { return "INSTREAM size limit exceeded. ERROR" })}
	if _, err := bad.scan(context.Background(), []byte("x")); err == nil {
		t.Error("ERROR reply accepted")
	}
	evil := clamd{addr: fakeClamd(t, func([]byte) string { return "stream: <script>Evil\nSig FOUND" })}
	if sig, _ := evil.scan(context.Background(), []byte("x")); strings.ContainsAny(sig, "<>\n ") {
		t.Errorf("signature not sanitized: %q", sig)
	}
}
