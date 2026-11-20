package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// platformResolver adapts Platform to firewall.UIDResolver.
type platformResolver struct{ p Platform }

func (r platformResolver) ConnectionOwnerUID(proto uint8, src, dst netip.AddrPort) int {
	return r.p.ConnectionOwnerUID(int(proto), src.Addr().Unmap().String(), int(src.Port()), dst.Addr().Unmap().String(), int(dst.Port()))
}

func (r platformResolver) PackagesForUID(uid int) string { return r.p.PackagesForUID(uid) }

// socketPeeker is implemented by conn.StdNetBind on Android (boundif_android.go).
type socketPeeker interface {
	PeekLookAtSocketFd4() (int, error)
	PeekLookAtSocketFd6() (int, error)
}

// protectedBind wraps the WireGuard UDP bind and protects its sockets every time they are
// (re)opened, like wireguard-android does with PeekLookAtSocketFd4/6. If a socket cannot be
// protected the bind is closed: unprotected WireGuard packets would loop into the TUN.
type protectedBind struct {
	conn.Bind
	protect protectFunc
	log     *slog.Logger
}

func newProtectedBind(protect protectFunc, log *slog.Logger) conn.Bind {
	return &protectedBind{Bind: conn.NewStdNetBind(), protect: protect, log: log}
}

func (b *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil || b.protect == nil {
		return fns, actual, err
	}
	pk, ok := b.Bind.(socketPeeker)
	if !ok {
		return fns, actual, nil // not Android: nothing to protect
	}
	protected := 0
	for _, peek := range []func() (int, error){pk.PeekLookAtSocketFd4, pk.PeekLookAtSocketFd6} {
		fd, err := peek()
		if err != nil {
			continue // that address family is not open
		}
		if !b.protect(fd) {
			b.Bind.Close()
			return nil, 0, errors.New("mobile: VpnService.protect failed for the WireGuard socket")
		}
		protected++
	}
	if protected == 0 {
		b.Bind.Close()
		return nil, 0, errors.New("mobile: no WireGuard socket to protect")
	}
	return fns, actual, nil
}

// eventHandler is a slog.Handler forwarding records to Platform.OnEvent("log", ...) and
// optionally to a second handler (stderr in the Linux client).
type eventHandler struct {
	emit  func(kind, payload string)
	next  slog.Handler
	level slog.Level
	attrs []slog.Attr
}

func (h *eventHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.level || (h.next != nil && h.next.Enabled(ctx, l))
}

func (h *eventHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.next != nil && h.next.Enabled(ctx, r.Level) {
		_ = h.next.Handle(ctx, r)
	}
	if r.Level < h.level || h.emit == nil {
		return nil
	}
	attrs := map[string]any{}
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.Any()
	}
	r.Attrs(func(a slog.Attr) bool {
		v := a.Value.Resolve().Any()
		if err, ok := v.(error); ok {
			v = err.Error()
		}
		attrs[a.Key] = v
		return true
	})
	b, err := json.Marshal(map[string]any{"level": r.Level.String(), "msg": r.Message, "time": r.Time, "attrs": attrs})
	if err != nil {
		return nil
	}
	h.emit("log", string(b))
	return nil
}

func (h *eventHandler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), as...)
	if h.next != nil {
		c.next = h.next.WithAttrs(as)
	}
	return &c
}

func (h *eventHandler) WithGroup(name string) slog.Handler {
	c := *h
	if h.next != nil {
		c.next = h.next.WithGroup(name)
	}
	return &c
}
