package edge

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ICAP scanning (RFC 3507, issue #25): an alternative to clamd for engines that speak ICAP.
// The content is sent as the body of an encapsulated HTTP response with RESPMOD and
// "Allow: 204". 204 means clean. A 200 answer means the server modified (blocked) the
// response, and the virus name comes from X-Infection-Found or X-Violations-Found. Anything
// else is an error, which makes the content unscanned, so blockUnscanned applies.

type icapScanner struct {
	host    string // host:port
	path    string // service, e.g. /avscan
	rawHost string
}

func newICAP(raw string) (*icapScanner, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "icap" || u.Host == "" {
		return nil, fmt.Errorf("edge: -icap must be icap://host[:port]/service, got %q", raw)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "1344")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &icapScanner{host: host, path: path, rawHost: u.Host}, nil
}

var (
	icapThreatRe = regexp.MustCompile(`(?i)threat\s*=\s*([^;]+)`)
	icapStatusRe = regexp.MustCompile(`^ICAP/1\.0 (\d{3})`)
)

func (s *icapScanner) scan(ctx context.Context, b []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, avTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.host)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoScanner, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	resHdr := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n"
	var req bytes.Buffer
	fmt.Fprintf(&req, "RESPMOD icap://%s%s ICAP/1.0\r\nHost: %s\r\nAllow: 204\r\nConnection: close\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n",
		s.rawHost, s.path, s.rawHost, len(resHdr))
	req.WriteString(resHdr)
	w := bufio.NewWriter(conn)
	if _, err := w.Write(req.Bytes()); err != nil {
		return "", err
	}
	for len(b) > 0 {
		n := min(len(b), avChunkSize)
		fmt.Fprintf(w, "%x\r\n", n)
		_, _ = w.Write(b[:n])
		_, _ = w.WriteString("\r\n")
		b = b[n:]
	}
	if _, err := w.WriteString("0\r\n\r\n"); err != nil {
		return "", err
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	tp := textproto.NewReader(bufio.NewReader(io.LimitReader(conn, 1<<20)))
	status, err := tp.ReadLine()
	if err != nil {
		return "", fmt.Errorf("icap: %w", err)
	}
	m := icapStatusRe.FindStringSubmatch(status)
	if m == nil {
		return "", fmt.Errorf("icap: bad status line %q", status)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		return "", fmt.Errorf("icap: %w", err)
	}
	switch m[1] {
	case "204":
		return "", nil
	case "200":
		for _, h := range []string{"X-Infection-Found", "X-Violations-Found", "X-Virus-Id"} {
			if v := hdr.Get(h); v != "" {
				if t := icapThreatRe.FindStringSubmatch(v); t != nil {
					v = t[1]
				}
				return sanitizeSignature(strings.TrimSpace(v)), nil
			}
		}
		// A modified response without a name: the server blocked it for a reason we cannot
		// read. Treat it as a detection rather than as clean.
		return "icap-blocked", nil
	default:
		return "", errors.New("icap: server answered " + m[1])
	}
}
