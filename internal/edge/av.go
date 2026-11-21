package edge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Malware scanning (ADR-0020) through a clamd daemon (ClamAV), with its INSTREAM command:
// the Edge streams the bytes and reads one verdict line.

// Malware scanning limits. clamd refuses streams over its StreamMaxLength (25 MiB by default).
const (
	maxAVScan   = 20 << 20
	avTimeout   = 30 * time.Second
	avChunkSize = 64 << 10
)

// errNoScanner means no scanner is configured or reachable: the content is unscanned.
var errNoScanner = errors.New("malware scanner unavailable")

// scanner scans content for malware. It returns the signature name, or "" when clean.
type scanner interface {
	scan(ctx context.Context, b []byte) (string, error)
}

// clamd talks to a clamd TCP socket.
type clamd struct{ addr string }

func (c clamd) scan(ctx context.Context, b []byte) (string, error) {
	if c.addr == "" {
		return "", errNoScanner
	}
	ctx, cancel := context.WithTimeout(ctx, avTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoScanner, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	w := bufio.NewWriter(conn)
	if _, err := w.WriteString("zINSTREAM\x00"); err != nil {
		return "", err
	}
	var hdr [4]byte
	for len(b) > 0 {
		n := min(len(b), avChunkSize)
		binary.BigEndian.PutUint32(hdr[:], uint32(n)) //nolint:gosec // G115: n <= avChunkSize
		if _, err := w.Write(hdr[:]); err != nil {
			return "", err
		}
		if _, err := w.Write(b[:n]); err != nil {
			return "", err
		}
		b = b[n:]
	}
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString(0)
	if err != nil && reply == "" {
		return "", fmt.Errorf("clamd reply: %w", err)
	}
	return parseClamdReply(reply)
}

// parseClamdReply reads "stream: OK", "stream: <signature> FOUND" or "... ERROR".
func parseClamdReply(r string) (string, error) {
	r = strings.TrimSpace(strings.TrimRight(r, "\x00"))
	r = strings.TrimPrefix(r, "stream: ")
	switch {
	case r == "OK":
		return "", nil
	case strings.HasSuffix(r, " FOUND"):
		sig := strings.TrimSpace(strings.TrimSuffix(r, " FOUND"))
		if sig == "" {
			sig = "unknown"
		}
		return sanitizeSignature(sig), nil
	default:
		return "", fmt.Errorf("clamd: %q", r)
	}
}

// sanitizeSignature keeps a signature name safe for flow records and block pages.
func sanitizeSignature(s string) string {
	var b bytes.Buffer
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".-_:", c) >= 0 {
			b.WriteByte(c)
		}
		if b.Len() >= 128 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// OCR for DLP (ADR-0024): images are sent to an ocrd service, which returns their text.

const ocrTimeout = 35 * time.Second

// ocrFunc returns the OCR function for one extraction, or nil when no OCR service is set.
func (e *Edge) ocrFunc(ctx context.Context) func([]byte) ([]byte, error) {
	if e.cfg.OCRURL == "" {
		return nil
	}
	return func(img []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, ocrTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.cfg.OCRURL, "/")+"/v1/ocr", bytes.NewReader(img))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ocr: %s", resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	}
}
