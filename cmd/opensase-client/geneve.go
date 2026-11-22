package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuky2020/opensase/pkg/geneve"
	"github.com/yuky2020/opensase/pkg/packet"
)

const (
	geneveTUNName  = "osase-gnv"
	geneveTUNMTU   = 1400
	maxFlowEntries = 65536
	tcpFlowIdle    = 5 * time.Minute
	otherFlowIdle  = 60 * time.Second
)

// packetDev abstracts packet reading and writing for the TUN device.
type packetDev interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(buf []byte) error
	Close() error
}

// realPacketDev wraps a wireguard tun.Device.
type realPacketDev struct {
	dev tun.Device
}

func (d *realPacketDev) ReadPacket(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	sizes := []int{0}
	n, err := d.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (d *realPacketDev) WritePacket(buf []byte) error {
	bufs := [][]byte{buf}
	_, err := d.dev.Write(bufs, 0)
	return err
}

func (d *realPacketDev) Close() error {
	return d.dev.Close()
}

// packetConn abstracts reading and writing datagrams over UDP.
type packetConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
	Close() error
}

// flowKey identifies a flow by inner protocol, source and destination IP addresses,
// and transport ports (0 for non-TCP/UDP).
type flowKey struct {
	proto uint8
	src   netip.Addr
	dst   netip.Addr
	sport uint16
	dport uint16
}

func (k flowKey) reverse() flowKey {
	return flowKey{
		proto: k.proto,
		src:   k.dst,
		dst:   k.src,
		sport: k.dport,
		dport: k.sport,
	}
}

// flowEntry stores the return mapping for an active workload connection.
type flowEntry struct {
	key      flowKey
	sender   net.Addr
	hdr      geneve.Header
	lastSeen time.Time
	isTCP    bool

	prev *flowEntry
	next *flowEntry
}

// flowTable tracks active flows with LRU eviction and idle timeouts.
type flowTable struct {
	mu      sync.Mutex
	entries map[flowKey]*flowEntry
	head    *flowEntry // dummy head
	tail    *flowEntry // dummy tail
	maxSize int
}

func newFlowTable(maxSize int) *flowTable {
	ft := &flowTable{
		entries: make(map[flowKey]*flowEntry),
		head:    &flowEntry{},
		tail:    &flowEntry{},
		maxSize: maxSize,
	}
	ft.head.next = ft.tail
	ft.tail.prev = ft.head
	return ft
}

func (ft *flowTable) remove(e *flowEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = nil
	e.next = nil
}

func (ft *flowTable) pushBack(e *flowEntry) {
	e.prev = ft.tail.prev
	e.next = ft.tail
	ft.tail.prev.next = e
	ft.tail.prev = e
}

func (ft *flowTable) moveToBack(e *flowEntry) {
	ft.remove(e)
	ft.pushBack(e)
}

func (ft *flowTable) evictOldest() *flowEntry {
	if ft.head.next == ft.tail {
		return nil
	}
	oldest := ft.head.next
	ft.remove(oldest)
	delete(ft.entries, oldest.key)
	return oldest
}

func (ft *flowTable) get(key flowKey, now time.Time) (*flowEntry, bool) {
	e, ok := ft.entries[key]
	if !ok {
		return nil, false
	}
	timeout := otherFlowIdle
	if e.isTCP {
		timeout = tcpFlowIdle
	}
	if now.Sub(e.lastSeen) > timeout {
		ft.remove(e)
		delete(ft.entries, key)
		return nil, false
	}
	e.lastSeen = now
	ft.moveToBack(e)
	return e, true
}

func (ft *flowTable) put(key flowKey, sender net.Addr, hdr geneve.Header, now time.Time) {
	if e, ok := ft.entries[key]; ok {
		e.sender = sender
		e.hdr = copyGeneveHeader(hdr)
		e.lastSeen = now
		ft.moveToBack(e)
		return
	}
	if len(ft.entries) >= ft.maxSize {
		ft.evictOldest()
	}
	e := &flowEntry{
		key:      key,
		sender:   sender,
		hdr:      copyGeneveHeader(hdr),
		lastSeen: now,
		isTCP:    key.proto == packet.ProtoTCP,
	}
	ft.entries[key] = e
	ft.pushBack(e)
}

func copyGeneveHeader(h geneve.Header) geneve.Header {
	var opts []geneve.Option
	if len(h.Options) > 0 {
		opts = make([]geneve.Option, len(h.Options))
		for i, o := range h.Options {
			opts[i] = geneve.Option{
				Class: o.Class,
				Type:  o.Type,
				Data:  bytes.Clone(o.Data),
			}
		}
	}
	return geneve.Header{
		VNI:      h.VNI,
		Protocol: h.Protocol,
		Options:  opts,
		OAM:      h.OAM,
		Critical: h.Critical,
	}
}

// geneveIngress encapsulates and decapsulates workload traffic behind a cloud gateway load balancer.
type geneveIngress struct {
	conn  packetConn
	dev   packetDev
	cidrs []netip.Prefix
	log   *slog.Logger
	flows *flowTable

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu                     sync.Mutex
	accepted               uint64
	droppedMalformedGeneve uint64
	droppedNonIPv4Proto    uint64
	droppedMalformedIP     uint64
	droppedNonIPv4Version  uint64
	droppedOutsideCIDR     uint64
	droppedTUNWrite        uint64
	returnAccepted         uint64
	droppedUnknownReturn   uint64
	droppedReturnParse     uint64
	droppedEncapErr        uint64
	droppedUDPSend         uint64
}

func newGeneveIngress(conn packetConn, dev packetDev, cidrs []netip.Prefix, log *slog.Logger, maxFlows int) *geneveIngress {
	return &geneveIngress{
		conn:  conn,
		dev:   dev,
		cidrs: cidrs,
		log:   log,
		flows: newFlowTable(maxFlows),
	}
}

func (g *geneveIngress) start(ctx context.Context) {
	g.ctx, g.cancel = context.WithCancel(ctx)
	g.wg.Add(3)
	go g.rxLoop()
	go g.txLoop()
	go g.statsLoop()
}

func (g *geneveIngress) Close() error {
	if g.cancel != nil {
		g.cancel()
	}
	var errs []error
	if g.conn != nil {
		errs = append(errs, g.conn.Close())
	}
	if g.dev != nil {
		errs = append(errs, g.dev.Close())
	}
	g.wg.Wait()
	return errors.Join(errs...)
}

func (g *geneveIngress) rxLoop() {
	defer g.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, sender, err := g.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-g.ctx.Done():
				return
			default:
				return
			}
		}
		g.handleReceive(buf[:n], sender)
	}
}

func (g *geneveIngress) handleReceive(datagram []byte, sender net.Addr) {
	hdr, inner, err := geneve.Parse(datagram)
	if err != nil {
		g.mu.Lock()
		g.droppedMalformedGeneve++
		g.mu.Unlock()
		return
	}
	if hdr.Protocol != geneve.ProtoIPv4 {
		g.mu.Lock()
		g.droppedNonIPv4Proto++
		g.mu.Unlock()
		return
	}
	var pkt packet.Packet
	if err := packet.Parse(inner, &pkt); err != nil {
		g.mu.Lock()
		g.droppedMalformedIP++
		g.mu.Unlock()
		return
	}
	if pkt.Version != 4 {
		g.mu.Lock()
		g.droppedNonIPv4Version++
		g.mu.Unlock()
		return
	}
	allowed := false
	for _, c := range g.cidrs {
		if c.Contains(pkt.Src) {
			allowed = true
			break
		}
	}
	if !allowed {
		g.mu.Lock()
		g.droppedOutsideCIDR++
		g.mu.Unlock()
		return
	}

	sport, dport := uint16(0), uint16(0)
	if pkt.Protocol == packet.ProtoTCP || pkt.Protocol == packet.ProtoUDP {
		sport = pkt.SrcPort
		dport = pkt.DstPort
	}
	key := flowKey{
		proto: pkt.Protocol,
		src:   pkt.Src,
		dst:   pkt.Dst,
		sport: sport,
		dport: dport,
	}

	g.flows.mu.Lock()
	g.flows.put(key, sender, hdr, time.Now())
	g.flows.mu.Unlock()

	if err := g.dev.WritePacket(inner); err != nil {
		g.mu.Lock()
		g.droppedTUNWrite++
		g.mu.Unlock()
		return
	}

	g.mu.Lock()
	g.accepted++
	g.mu.Unlock()
}

func (g *geneveIngress) txLoop() {
	defer g.wg.Done()
	buf := make([]byte, 65535)
	encapBuf := make([]byte, 65535)
	for {
		n, err := g.dev.ReadPacket(buf)
		if err != nil {
			select {
			case <-g.ctx.Done():
				return
			default:
				return
			}
		}
		g.handleReturn(buf[:n], encapBuf)
	}
}

func (g *geneveIngress) handleReturn(packetBytes []byte, encapBuf []byte) {
	var pkt packet.Packet
	if err := packet.Parse(packetBytes, &pkt); err != nil || pkt.Version != 4 {
		g.mu.Lock()
		g.droppedReturnParse++
		g.mu.Unlock()
		return
	}

	sport, dport := uint16(0), uint16(0)
	if pkt.Protocol == packet.ProtoTCP || pkt.Protocol == packet.ProtoUDP {
		sport = pkt.SrcPort
		dport = pkt.DstPort
	}
	key := flowKey{
		proto: pkt.Protocol,
		src:   pkt.Src,
		dst:   pkt.Dst,
		sport: sport,
		dport: dport,
	}

	g.flows.mu.Lock()
	entry, ok := g.flows.get(key.reverse(), time.Now())
	var sender net.Addr
	var hdr geneve.Header
	if ok {
		sender = entry.sender
		hdr = copyGeneveHeader(entry.hdr)
	}
	g.flows.mu.Unlock()

	if !ok {
		g.mu.Lock()
		g.droppedUnknownReturn++
		g.mu.Unlock()
		return
	}

	encap, err := hdr.AppendTo(encapBuf[:0], packetBytes)
	if err != nil {
		g.mu.Lock()
		g.droppedEncapErr++
		g.mu.Unlock()
		return
	}

	if _, err := g.conn.WriteTo(encap, sender); err != nil {
		g.mu.Lock()
		g.droppedUDPSend++
		g.mu.Unlock()
		return
	}

	g.mu.Lock()
	g.returnAccepted++
	g.mu.Unlock()
}

func (g *geneveIngress) statsLoop() {
	defer g.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			g.logStats()
		}
	}
}

func (g *geneveIngress) logStats() {
	g.mu.Lock()
	acc := g.accepted
	retAcc := g.returnAccepted
	dMalformed := g.droppedMalformedGeneve
	dNonIPv4 := g.droppedNonIPv4Proto
	dMalformedIP := g.droppedMalformedIP
	dNon4Ver := g.droppedNonIPv4Version
	dOutside := g.droppedOutsideCIDR
	dTUN := g.droppedTUNWrite
	dUnknown := g.droppedUnknownReturn
	dRetParse := g.droppedReturnParse
	dEncap := g.droppedEncapErr
	dUDP := g.droppedUDPSend
	g.mu.Unlock()

	g.flows.mu.Lock()
	activeFlows := len(g.flows.entries)
	g.flows.mu.Unlock()

	g.log.Info("geneve ingress stats",
		"accepted", acc,
		"return_accepted", retAcc,
		"dropped_malformed_geneve", dMalformed,
		"dropped_non_ipv4_proto", dNonIPv4,
		"dropped_malformed_ip", dMalformedIP,
		"dropped_non_ipv4_version", dNon4Ver,
		"dropped_outside_cidr", dOutside,
		"dropped_tun_write", dTUN,
		"dropped_unknown_return", dUnknown,
		"dropped_return_parse", dRetParse,
		"dropped_encap_err", dEncap,
		"dropped_udp_send", dUDP,
		"active_flows", activeFlows,
	)
}

// startGeneveIngress creates the UDP listener and osase-gnv TUN device, then starts the ingress loops.
func startGeneveIngress(ctx context.Context, listenAddr string, cidrs []netip.Prefix, log *slog.Logger) (*geneveIngress, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve -geneve-listen %s: %w", listenAddr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP %s: %w", listenAddr, err)
	}

	tunDev, err := tun.CreateTUN(geneveTUNName, geneveTUNMTU)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create TUN %s (needs NET_ADMIN): %w", geneveTUNName, err)
	}

	cmd := exec.CommandContext(ctx, "ip", "link", "set", "dev", geneveTUNName, "mtu", fmt.Sprint(geneveTUNMTU), "up") //nolint:gosec // G204: fixed binary and device name
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = tunDev.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("ip link set dev %s up: %w: %s", geneveTUNName, err, strings.TrimSpace(string(out)))
	}

	ingress := newGeneveIngress(conn, &realPacketDev{dev: tunDev}, cidrs, log, maxFlowEntries)
	ingress.start(ctx)
	return ingress, nil
}

// startHealthServer runs an HTTP server for GET /healthz answering 200 "ok" while the tunnel
// is up and 503 otherwise.
func startHealthServer(ctx context.Context, addr string, isTunnelUp func() bool, log *slog.Logger) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if isTunnelUp() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("tunnel down\n"))
		}
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("health server listen %s: %w", addr, err)
	}
	srv.Addr = ln.Addr().String()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health server failed", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		// ctx is done here: shut down on a fresh bounded context.
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	return srv, nil
}
