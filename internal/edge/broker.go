package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Broker listener (ADR-0013): the kernel REDIRECTs TCP from the tunnel to SyntheticPrefix to
// this listener; each connection is entitlement-checked and spliced onto an HTTP/2
// POST /v1/dial stream of a live Connector of the app's tenant and group.
const (
	LayerZTNA       = "ztna"
	brokerIdle      = 5 * time.Minute // no bytes in either direction for this long closes the stream
	brokerDialWait  = 15 * time.Second
	maxBrokerFlows  = 16384
	brokerCopyChunk = 32 << 10
	halfCloseLinger = 10 * time.Second
)

// serveBroker accepts redirected connections on ln until ctx is done.
func (e *Edge) serveBroker(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, maxBrokerFlows)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			e.log.Warn("broker listener stopped", "err", err)
			return
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			resetClose(tc)
			continue
		}
		go func() {
			defer func() { <-sem }()
			src := tc.RemoteAddr().(*net.TCPAddr).AddrPort()
			dst, err := e.origDst(tc)
			if err != nil {
				e.log.Debug("broker: no original destination", "src", src, "err", err)
				resetClose(tc)
				return
			}
			e.brokerConn(ctx, tc, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()))
		}()
	}
}

// resetClose closes c with an RST when it is TCP.
func resetClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// brokerConn handles one client connection from device tunnel address src to the synthetic
// address dst. Any refusal closes the connection with an RST and is recorded as a ztna flow.
func (e *Edge) brokerConn(ctx context.Context, c net.Conn, src, dst netip.AddrPort) {
	start := time.Now()
	rec := api.FlowRecord{
		Start: start, Where: "edge",
		Flow:     policy.Flow{Protocol: "tcp", SrcIP: src.Addr().String(), DstIP: dst.Addr().String(), DstPort: dst.Port()},
		Decision: policy.Decision{Action: policy.ActionBlock, Layer: LayerZTNA, Log: true},
	}
	deny := func(rule, msg string, args ...any) {
		resetClose(c)
		rec.End, rec.Decision.RuleID = time.Now(), rule
		if rec.DeviceID != "" {
			e.flows.add(rec)
		}
		e.log.Info("ztna connection refused: "+msg, append([]any{"src", src, "dst", dst, "device", rec.DeviceID, "rule", rule}, args...)...)
	}

	d := e.reg.byTunnelIP(src.Addr())
	if d == nil || !SyntheticPrefix.Contains(dst.Addr()) {
		deny("ztna:unknown-device", "not from a tunnel device")
		return
	}
	rec.DeviceID = d.id
	c4, v := d.compiled.Load(), d.ztna.Load()
	if c4 == nil || v == nil {
		deny("ztna:no-snapshot", "no snapshot")
		return
	}
	tenant, name, ok := e.synth.lookup(dst.Addr(), time.Now())
	if !ok || tenant != v.tenant {
		deny("ztna:unknown-address", "address does not map to a name of this tenant")
		return
	}
	rec.Flow.Domain = name
	app, ok := v.access(name, dst.Port())
	if !ok {
		rule := "ztna:not-entitled"
		if a, found := v.app(name); found {
			rule = "ztna:" + a.ID + ":port"
		}
		deny(rule, "name and port not entitled", "name", name)
		return
	}
	// Tenant and user rules still apply to private apps (ADR-0013, policy layer order).
	if dec := c4.Evaluate(rec.Flow, true); dec.Action == policy.ActionBlock && (dec.Layer == policy.LayerTenant || dec.Layer == policy.LayerUser) {
		rec.Decision = dec
		deny(dec.RuleID, "blocked by "+dec.Layer+" rule", "name", name)
		return
	}
	ruleID := "ztna:" + app.ID
	conns := e.hub.pick(tenant, app.ConnectorGroup)
	if len(conns) == 0 {
		deny(ruleID+":no-connector", "no live connector", "app", app.ID, "group", app.ConnectorGroup)
		return
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	target := net.JoinHostPort(name, strconv.Itoa(int(dst.Port())))
	var resp *http.Response
	var pw *io.PipeWriter
	var used *brokerConn
	for _, b := range conns[:min(len(conns), 2)] {
		pr, w := io.Pipe()
		req, err := http.NewRequestWithContext(sctx, http.MethodPost, "https://connector/v1/dial", pr)
		if err != nil {
			pw = nil
			break
		}
		req.Header.Set(api.BrokerHeaderTarget, target)
		req.Header.Set(api.BrokerHeaderApp, app.ID)
		req.Header.Set(api.BrokerHeaderDevice, d.id)
		req.ContentLength = -1
		// The connector answers once its dial to the app finished (5s timeout there).
		timer := time.AfterFunc(brokerDialWait, cancel)
		r, err := b.cc.RoundTrip(req)
		timer.Stop()
		if err != nil {
			_ = w.CloseWithError(err)
			e.log.Warn("ztna dial via connector failed", "connector", b.id, "target", target, "err", err)
			if sctx.Err() != nil {
				break
			}
			continue
		}
		resp, pw, used = r, w, b
		break
	}
	if resp == nil {
		deny(ruleID+":connector-error", "connector stream failed", "app", app.ID)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = pw.CloseWithError(errors.New("refused"))
		rule := ruleID + ":connector-" + strconv.Itoa(resp.StatusCode)
		deny(rule, "connector refused", "app", app.ID, "connector", used.id, "status", resp.StatusCode)
		return
	}
	rec.Decision = policy.Decision{Action: policy.ActionAllow, RuleID: ruleID, Layer: LayerZTNA, Log: true}
	e.log.Info("ztna connection brokered", "device", d.id, "app", app.ID, "target", target, "connector", used.id)
	out, in, abnormal := splice(sctx, c, pw, resp.Body, brokerIdle)
	if abnormal {
		resetClose(c)
	} else {
		_ = c.Close()
	}
	rec.End, rec.BytesOut, rec.BytesIn = time.Now(), out, in
	e.flows.add(rec)
}

// halfCloser is implemented by *net.TCPConn and *tls.Conn.
type halfCloser interface{ CloseWrite() error }

// activity tracks the last time bytes moved in either direction.
type activity struct{ last atomic.Int64 }

func (a *activity) touch() { a.last.Store(time.Now().UnixNano()) }

type countWriter struct {
	w   io.Writer
	n   *atomic.Uint64
	act *activity
}

func (cw countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n.Add(uint64(n))
	cw.act.touch()
	return n, err
}

// splice copies client -> up (then closes up: HTTP/2 END_STREAM) and down -> client (then
// half-closes the client) until both directions finish, an error occurs, ctx is done or
// nothing moved for idle. It returns the byte counts and whether the stream ended abnormally.
func splice(ctx context.Context, client net.Conn, up *io.PipeWriter, down io.ReadCloser, idle time.Duration) (out, in uint64, abnormal bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var nOut, nIn atomic.Uint64
	var bad, downDone atomic.Bool
	act := &activity{}
	act.touch()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, brokerCopyChunk)
		_, err := io.CopyBuffer(countWriter{up, &nOut, act}, client, buf)
		if err != nil {
			_ = up.CloseWithError(err)
			// After the app side ended, the stream is gone and further client bytes have
			// nowhere to go; that is a normal end, not an error.
			if !downDone.Load() {
				bad.Store(true)
				cancel()
			}
			return
		}
		_ = up.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, brokerCopyChunk)
		_, err := io.CopyBuffer(countWriter{client, &nIn, act}, down, buf)
		if err != nil {
			bad.Store(true)
			cancel()
			return
		}
		downDone.Store(true)
		if hc, ok := client.(halfCloser); ok {
			_ = hc.CloseWrite()
		} else {
			cancel() // cannot half-close: end the whole stream
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	tick := time.NewTicker(min(idle/4, 5*time.Second))
	defer tick.Stop()
	for {
		select {
		case <-done:
			return nOut.Load(), nIn.Load(), bad.Load()
		case <-ctx.Done():
		case <-tick.C:
			since := time.Since(time.Unix(0, act.last.Load()))
			if downDone.Load() && since >= min(idle, halfCloseLinger) {
				// The app side ended and the client did not close its side: end normally.
				cancel()
				_ = up.Close()
				_ = client.Close()
				<-done
				return nOut.Load(), nIn.Load(), false
			}
			if since < idle {
				continue
			}
			bad.Store(true)
		}
		// Abort: unblock both copies.
		cancel()
		_ = client.Close()
		_ = up.CloseWithError(context.Canceled)
		_ = down.Close()
		<-done
		return nOut.Load(), nIn.Load(), true
	}
}
