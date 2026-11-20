package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
)

type fakeRenewer struct {
	err   error
	calls int
}

func (f *fakeRenewer) RenewNow(context.Context) error { f.calls++; return f.err }
func (f *fakeRenewer) Status() string                 { return "{}" }

// A failed -renew-now must not stop the client (renewNow has no error to return).
func TestRenewNowFailureIsNotFatal(t *testing.T) {
	for _, err := range []error{nil, errors.New("renew: http 500")} {
		f := &fakeRenewer{err: err}
		renewNow(f, slog.New(slog.DiscardHandler))
		if f.calls != 1 {
			t.Fatalf("calls=%d", f.calls)
		}
	}
}

func TestProvisioningKey(t *testing.T) {
	files := map[string]string{"k.txt": "pk-file\n", "empty.txt": " \n"}
	readFile := func(p string) ([]byte, error) {
		s, ok := files[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
	tests := []struct {
		name             string
		o                options
		env              string
		wantKey, wantSrc string
		wantErr          bool
	}{
		{name: "file wins over env and flag", o: options{keyFile: "k.txt", key: "pk-flag"}, env: "pk-env", wantKey: "pk-file", wantSrc: "-key-file"},
		{name: "env wins over flag", o: options{key: "pk-flag"}, env: " pk-env ", wantKey: "pk-env", wantSrc: "env"},
		{name: "flag as last resort", o: options{key: "pk-flag"}, wantKey: "pk-flag", wantSrc: "-key"},
		{name: "none", wantKey: "", wantSrc: ""},
		{name: "missing file", o: options{keyFile: "nope.txt"}, wantErr: true},
		{name: "empty file", o: options{keyFile: "empty.txt"}, env: "pk-env", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string {
				if k != envProvisioningKey {
					t.Fatalf("unexpected env %s", k)
				}
				return tt.env
			}
			key, src, err := provisioningKey(tt.o, getenv, readFile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v", err)
			}
			if tt.wantErr {
				if tt.o.keyFile == "nope.txt" && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if key != tt.wantKey || src != tt.wantSrc {
				t.Fatalf("got %q/%q, want %q/%q", key, src, tt.wantKey, tt.wantSrc)
			}
		})
	}
}
