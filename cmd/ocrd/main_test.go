package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fakeTesseract writes a script that prints its stdin size, or fails on "FAIL".
func fakeTesseract(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tesseract")
	script := "#!/bin/sh\nin=$(cat)\ncase \"$in\" in *FAIL*) exit 1;; esac\necho \"text of $1 $2 $3 $4\"\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil { //nolint:gosec // G306: test helper must be executable
		t.Fatal(err)
	}
	return p
}

func TestOCRD(t *testing.T) {
	srv := httptest.NewServer(newMux(fakeTesseract(t), "eng", 1, slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer srv.Close()
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n'}
	for name, tc := range map[string]struct {
		body []byte
		want int
	}{
		"image":     {png, 200},
		"not image": {[]byte("hello"), http.StatusUnsupportedMediaType},
		"too large": {append(png, make([]byte, maxImage)...), http.StatusRequestEntityTooLarge},
		"ocr fails": {append(png, []byte("FAIL")...), http.StatusUnprocessableEntity},
	} {
		resp, err := http.Post(srv.URL+"/v1/ocr", "application/octet-stream", bytes.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
		if name == "image" && string(b) != "text of stdin stdout -l eng\n" {
			t.Errorf("image: %q", b)
		}
	}
	if resp, _ := http.Get(srv.URL + "/v1/ocr"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", resp.StatusCode)
	}
}
