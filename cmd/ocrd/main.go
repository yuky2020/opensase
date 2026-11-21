// Command ocrd is the OCR service of the Edge's DLP (ADR-0024): POST /v1/ocr with an image
// body returns its text, read by Tesseract. It runs in its own unprivileged container, next to
// the Edge, because image decoders are a classic attack surface: a parser bug stays there.
//
// Limits: 10 MiB per image, 30 s per job, a few concurrent jobs; nothing is stored.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuky2020/opensase/pkg/dlp"
)

const (
	maxImage   = dlp.MaxOCRImage
	maxText    = 4 << 20
	jobTimeout = 30 * time.Second
)

func main() {
	listen := flag.String("listen", ":8090", "listen address")
	langs := flag.String("langs", "eng+ita", "Tesseract languages")
	workers := flag.Int("workers", 2, "concurrent OCR jobs")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	mux := newMux("tesseract", *langs, *workers, log)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 2 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("ocrd listening", "addr", *listen, "langs", *langs, "workers", *workers)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("ocrd", "err", err)
		os.Exit(1)
	}
}

// newMux serves the OCR API, running bin (Tesseract) for each image.
func newMux(bin, langs string, workers int, log *slog.Logger) *http.ServeMux {
	sem := make(chan struct{}, max(1, workers))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /v1/ocr", func(w http.ResponseWriter, r *http.Request) {
		img, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxImage))
		if err != nil {
			http.Error(w, "image too large", http.StatusRequestEntityTooLarge)
			return
		}
		if !dlp.IsImage(img) {
			http.Error(w, "not an image", http.StatusUnsupportedMediaType)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-r.Context().Done():
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), jobTimeout)
		defer cancel()
		var out, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, "stdin", "stdout", "-l", langs, "--psm", "3") //nolint:gosec // G204: fixed binary; langs is an operator flag
		cmd.Stdin = bytes.NewReader(img)
		cmd.Stdout = &limitedWriter{w: &out, n: maxText}
		cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
		if err := cmd.Run(); err != nil {
			code := http.StatusUnprocessableEntity
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}
			log.Warn("ocr failed", "err", err, "bytes", len(img))
			http.Error(w, "ocr failed", code)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(out.Bytes())
	})
	return mux
}

// limitedWriter keeps the first n bytes and drops the rest.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
