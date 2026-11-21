// Package peek extracts the destination hostname from the first bytes a client sends on a
// TCP connection: the SNI of a TLS ClientHello, or the Host header of an HTTP/1.x request
// (ADR-0017). Nothing is decrypted. The input is untrusted, and every length is checked
// before use.
package peek

import (
	"bytes"
	"strings"
)

// Result says what Host found.
type Result int

// Results.
const (
	// NeedMore means the bytes so far are a valid prefix of a ClientHello or HTTP request
	// that is not complete yet.
	NeedMore Result = iota
	// Found means the message is complete; Host holds the hostname, or "" if the message
	// carries none (a ClientHello without SNI, an HTTP/1.0 request without Host).
	Found
	// NotApplicable means the stream is neither TLS nor HTTP/1.x, or is malformed, or the
	// message would exceed MaxBytes.
	NotApplicable
)

// MaxBytes bounds how much of a stream is buffered to find the hostname. A ClientHello with
// a post-quantum key share is about 2 KiB; 16 KiB leaves room for large extension sets.
const MaxBytes = 16 << 10

// Protocols reported by Host.
const (
	ProtoTLS  = "tls"
	ProtoHTTP = "http"
)

// Host inspects the start of a client stream. It returns the hostname (lowercase, no port,
// no trailing dot), the protocol and the result.
func Host(b []byte) (host, proto string, r Result) {
	if len(b) == 0 {
		return "", "", NeedMore
	}
	if b[0] == 0x16 { // TLS handshake record
		h, r := tlsSNI(b)
		return h, ProtoTLS, r
	}
	if isHTTPStart(b) {
		h, r := httpHost(b)
		return h, ProtoHTTP, r
	}
	return "", "", NotApplicable
}

// tlsSNI reassembles the handshake message from consecutive handshake records and parses
// the ClientHello.
func tlsSNI(b []byte) (string, Result) {
	var hs []byte
	for len(b) > 0 {
		if len(b) < 5 {
			return "", more(b)
		}
		if b[0] != 0x16 || b[1] != 3 { // handshake, TLS 1.x record version
			return "", NotApplicable
		}
		n := int(b[3])<<8 | int(b[4])
		if n == 0 || n > 1<<14+256 {
			return "", NotApplicable
		}
		partial := len(b) < 5+n
		if partial {
			hs = append(hs, b[5:]...)
			b = nil
		} else {
			hs = append(hs, b[5:5+n]...)
			b = b[5+n:]
		}
		// The handshake header, as soon as it is visible, says whether to keep going.
		if len(hs) > 0 && hs[0] != 1 { // client_hello
			return "", NotApplicable
		}
		if len(hs) >= 4 {
			l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if l > MaxBytes {
				return "", NotApplicable
			}
			if !partial && len(hs) >= 4+l {
				return parseClientHello(hs[4 : 4+l])
			}
		}
		if partial {
			break
		}
	}
	return "", moreTotal(len(hs))
}

func more(b []byte) Result { return moreTotal(len(b)) }

func moreTotal(n int) Result {
	if n >= MaxBytes {
		return NotApplicable
	}
	return NeedMore
}

// parseClientHello returns the server_name of a complete ClientHello body.
func parseClientHello(m []byte) (string, Result) {
	r := reader{b: m}
	r.skip(2 + 32) // legacy_version, random
	r.skip(int(r.u8()))
	r.skip(int(r.u16()))
	r.skip(int(r.u8()))
	if r.bad {
		return "", NotApplicable
	}
	if r.len() == 0 {
		return "", Found // no extensions
	}
	ext := reader{b: r.bytes(int(r.u16()))}
	if r.bad {
		return "", NotApplicable
	}
	for ext.len() > 0 {
		typ := ext.u16()
		data := ext.bytes(int(ext.u16()))
		if ext.bad {
			return "", NotApplicable
		}
		if typ != 0 { // server_name
			continue
		}
		sn := reader{b: data}
		list := reader{b: sn.bytes(int(sn.u16()))}
		for list.len() > 0 && !list.bad {
			nameType := list.u8()
			name := list.bytes(int(list.u16()))
			if list.bad {
				break
			}
			if nameType == 0 { // host_name
				h, ok := cleanHost(string(name))
				if !ok {
					return "", NotApplicable
				}
				return h, Found
			}
		}
		return "", NotApplicable
	}
	return "", Found
}

var methods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func isHTTPStart(b []byte) bool {
	for _, m := range methods {
		n := min(len(b), len(m))
		if string(b[:n]) == m[:n] {
			return true
		}
	}
	return false
}

// httpHost parses the request head (up to the empty line) for the Host header, or for the
// authority of a CONNECT or absolute-form request target.
func httpHost(b []byte) (string, Result) {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		if len(b) >= 8<<10 {
			return "", NotApplicable
		}
		return "", NeedMore
	}
	lines := strings.Split(string(b[:end]), "\r\n")
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return "", NotApplicable
	}
	target := parts[1]
	if parts[0] == "CONNECT" {
		h, ok := cleanHost(target)
		if !ok {
			return "", NotApplicable
		}
		return h, Found
	}
	if rest, ok := strings.CutPrefix(target, "http://"); ok {
		h, _, _ := strings.Cut(rest, "/")
		if h, ok := cleanHost(h); ok {
			return h, Found
		}
		return "", NotApplicable
	}
	host := ""
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "host") {
			continue
		}
		if host != "" {
			return "", NotApplicable // two Host headers: ambiguous, refuse to guess
		}
		h, ok := cleanHost(strings.TrimSpace(v))
		if !ok {
			return "", NotApplicable
		}
		host = h
	}
	return host, Found
}

// cleanHost lowercases a host, drops a port and a trailing dot, and checks the characters.
// IP literals are returned as they are (brackets removed for IPv6).
func cleanHost(h string) (string, bool) {
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return "", false
		}
		return strings.ToLower(h[1:end]), true
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && c != '-' && c != '.' && c != '_' {
			return "", false
		}
	}
	return h, true
}

// reader is a bounds-checked cursor; any short read sets bad.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) len() int { return len(r.b) }

func (r *reader) bytes(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.bytes(n) }

func (r *reader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}
