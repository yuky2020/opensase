package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/geneve"
	"github.com/yuky2020/opensase/pkg/packet"
)

type fakePacketDev struct {
	mu     sync.Mutex
	in     chan []byte
	out    chan []byte
	closed bool
}

func newFakePacketDev() *fakePacketDev {
	return &fakePacketDev{
		in:  make(chan []byte, 100),
		out: make(chan []byte, 100),
	}
}

func (d *fakePacketDev) ReadPacket(buf []byte) (int, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return 0, net.ErrClosed
	}
	d.mu.Unlock()
	pkt, ok := <-d.out
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(buf, pkt), nil
}

func (d *fakePacketDev) WritePacket(buf []byte) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return net.ErrClosed
	}
	d.mu.Unlock()
	d.in <- bytes.Clone(buf)
	return nil
}

func (d *fakePacketDev) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.out)
	}
	return nil
}

type fakeDatagram struct {
	b    []byte
	addr net.Addr
}

type fakePacketConn struct {
	mu     sync.Mutex
	in     chan fakeDatagram
	out    chan fakeDatagram
	closed bool
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		in:  make(chan fakeDatagram, 100),
		out: make(chan fakeDatagram, 100),
	}
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	c.mu.Unlock()
	dg, ok := <-c.in
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(b, dg.b), dg.addr, nil
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()
	c.out <- fakeDatagram{b: bytes.Clone(b), addr: addr}
	return len(b), nil
}

func (c *fakePacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.in)
	}
	return nil
}

func buildIPv4TCP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	totalLen := 20 + 20 + len(payload)
	b := make([]byte, totalLen)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	b[8] = 64
	b[9] = packet.ProtoTCP
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())

	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	binary.BigEndian.PutUint32(b[24:28], 1)
	binary.BigEndian.PutUint32(b[28:32], 1)
	b[32] = 0x50 // 20-byte TCP header
	b[33] = packet.FlagACK
	binary.BigEndian.PutUint16(b[34:36], 65535)

	copy(b[40:], payload)
	return b
}

func TestGeneveIngressReceiveAndReturn(t *testing.T) {
	conn := newFakePacketConn()
	dev := newFakePacketDev()
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingress := newGeneveIngress(conn, dev, cidrs, log, maxFlowEntries)

	encapBuf := make([]byte, 65535)
	senderAddr, _ := net.ResolveUDPAddr("udp", "192.0.2.10:6081")

	// 1. Accepted packet reaches fake TUN.
	innerTCP := buildIPv4TCP(netip.MustParseAddr("10.30.0.5"), netip.MustParseAddr("8.8.8.8"), 12345, 80, []byte("request data"))
	hdr := geneve.Header{
		VNI:      1001,
		Protocol: geneve.ProtoIPv4,
		Options: []geneve.Option{
			{Class: 0x0100, Type: 0x02, Data: []byte{1, 2, 3, 4}},
		},
	}
	geneveDatagram, err := hdr.AppendTo(nil, innerTCP)
	if err != nil {
		t.Fatalf("AppendTo failed: %v", err)
	}

	ingress.handleReceive(geneveDatagram, senderAddr)

	select {
	case pkt := <-dev.in:
		if !bytes.Equal(pkt, innerTCP) {
			t.Errorf("received packet on fake TUN mismatch: got %x, want %x", pkt, innerTCP)
		}
	default:
		t.Fatal("accepted packet did not reach fake TUN")
	}

	if ingress.accepted != 1 {
		t.Errorf("ingress.accepted = %d, want 1", ingress.accepted)
	}

	// 2. Return packet encapsulated with the same VNI and options to the original sender.
	returnTCP := buildIPv4TCP(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.30.0.5"), 80, 12345, []byte("response data"))
	ingress.handleReturn(returnTCP, encapBuf)

	select {
	case dg := <-conn.out:
		if dg.addr.String() != senderAddr.String() {
			t.Errorf("return packet sent to %v, want %v", dg.addr, senderAddr)
		}
		parsedHdr, payload, err := geneve.Parse(dg.b)
		if err != nil {
			t.Fatalf("failed to parse return GENEVE datagram: %v", err)
		}
		if parsedHdr.VNI != 1001 {
			t.Errorf("return VNI = %d, want 1001", parsedHdr.VNI)
		}
		if parsedHdr.Protocol != geneve.ProtoIPv4 {
			t.Errorf("return Protocol = 0x%04x, want 0x%04x", parsedHdr.Protocol, geneve.ProtoIPv4)
		}
		if len(parsedHdr.Options) != 1 || !slices.Equal(parsedHdr.Options[0].Data, []byte{1, 2, 3, 4}) {
			t.Errorf("return options mismatch: %+v", parsedHdr.Options)
		}
		if !bytes.Equal(payload, returnTCP) {
			t.Errorf("return payload mismatch: got %x, want %x", payload, returnTCP)
		}
	default:
		t.Fatal("return packet was not sent over UDP")
	}

	if ingress.returnAccepted != 1 {
		t.Errorf("ingress.returnAccepted = %d, want 1", ingress.returnAccepted)
	}

	// 3. Source outside the CIDRs dropped.
	outsideTCP := buildIPv4TCP(netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("8.8.8.8"), 12345, 80, []byte("outside"))
	outsideDatagram, err := hdr.AppendTo(nil, outsideTCP)
	if err != nil {
		t.Fatal(err)
	}
	ingress.handleReceive(outsideDatagram, senderAddr)
	if len(dev.in) != 0 {
		t.Error("packet outside CIDR was forwarded to TUN")
	}
	if ingress.droppedOutsideCIDR != 1 {
		t.Errorf("droppedOutsideCIDR = %d, want 1", ingress.droppedOutsideCIDR)
	}

	// 4. Non-IPv4 protocol dropped.
	nonIPv4Hdr := geneve.Header{
		VNI:      1001,
		Protocol: geneve.ProtoIPv6,
	}
	nonIPv4Datagram, err := nonIPv4Hdr.AppendTo(nil, innerTCP)
	if err != nil {
		t.Fatal(err)
	}
	ingress.handleReceive(nonIPv4Datagram, senderAddr)
	if len(dev.in) != 0 {
		t.Error("non-IPv4 protocol datagram was forwarded to TUN")
	}
	if ingress.droppedNonIPv4Proto != 1 {
		t.Errorf("droppedNonIPv4Proto = %d, want 1", ingress.droppedNonIPv4Proto)
	}

	// 5. Malformed GENEVE dropped.
	ingress.handleReceive([]byte{0x00, 0x00, 0x08}, senderAddr) // truncated
	if len(dev.in) != 0 {
		t.Error("malformed GENEVE was forwarded to TUN")
	}
	if ingress.droppedMalformedGeneve != 1 {
		t.Errorf("droppedMalformedGeneve = %d, want 1", ingress.droppedMalformedGeneve)
	}

	// 6. Unknown return dropped.
	unknownReturn := buildIPv4TCP(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.30.0.99"), 80, 54321, []byte("unknown"))
	ingress.handleReturn(unknownReturn, encapBuf)
	if len(conn.out) != 0 {
		t.Error("unknown return packet was sent over UDP")
	}
	if ingress.droppedUnknownReturn != 1 {
		t.Errorf("droppedUnknownReturn = %d, want 1", ingress.droppedUnknownReturn)
	}
}

func TestFlowTableExpiry(t *testing.T) {
	ft := newFlowTable(100)
	sender, _ := net.ResolveUDPAddr("udp", "10.0.0.1:6081")
	hdr := geneve.Header{VNI: 50, Protocol: geneve.ProtoIPv4}
	now := time.Now()

	// UDP flow expires in 60 seconds
	udpKey := flowKey{
		proto: packet.ProtoUDP,
		src:   netip.MustParseAddr("10.30.0.1"),
		dst:   netip.MustParseAddr("8.8.8.8"),
		sport: 53,
		dport: 53,
	}
	ft.put(udpKey, sender, hdr, now)

	// Within 60 seconds: present
	if _, ok := ft.get(udpKey, now.Add(50*time.Second)); !ok {
		t.Fatal("UDP flow should not have expired at 50s")
	}
	// Past 60 seconds: expired
	if _, ok := ft.get(udpKey, now.Add(120*time.Second)); ok {
		t.Fatal("UDP flow should have expired past 60s idle")
	}

	// TCP flow expires in 5 minutes
	tcpKey := flowKey{
		proto: packet.ProtoTCP,
		src:   netip.MustParseAddr("10.30.0.1"),
		dst:   netip.MustParseAddr("8.8.8.8"),
		sport: 1000,
		dport: 80,
	}
	ft.put(tcpKey, sender, hdr, now)

	// At 4 minutes: present
	if _, ok := ft.get(tcpKey, now.Add(4*time.Minute)); !ok {
		t.Fatal("TCP flow should not have expired at 4 minutes")
	}
	// Past 5 minutes idle: expired
	if _, ok := ft.get(tcpKey, now.Add(4*time.Minute+6*time.Minute)); ok {
		t.Fatal("TCP flow should have expired past 5 minutes idle")
	}
}

func TestFlowTableEvictionAtCap(t *testing.T) {
	conn := newFakePacketConn()
	dev := newFakePacketDev()
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Ingress with cap of 2 entries
	ingress := newGeneveIngress(conn, dev, cidrs, log, 2)
	sender, _ := net.ResolveUDPAddr("udp", "10.0.0.1:6081")
	hdr := geneve.Header{VNI: 1, Protocol: geneve.ProtoIPv4}
	encapBuf := make([]byte, 65535)

	flow1 := buildIPv4TCP(netip.MustParseAddr("10.30.0.1"), netip.MustParseAddr("8.8.8.8"), 1001, 80, nil)
	flow2 := buildIPv4TCP(netip.MustParseAddr("10.30.0.2"), netip.MustParseAddr("8.8.8.8"), 1002, 80, nil)
	flow3 := buildIPv4TCP(netip.MustParseAddr("10.30.0.3"), netip.MustParseAddr("8.8.8.8"), 1003, 80, nil)

	dg1, _ := hdr.AppendTo(nil, flow1)
	dg2, _ := hdr.AppendTo(nil, flow2)
	dg3, _ := hdr.AppendTo(nil, flow3)

	ingress.handleReceive(dg1, sender)
	ingress.handleReceive(dg2, sender)
	// Inserting flow3 must evict flow1 (oldest)
	ingress.handleReceive(dg3, sender)

	// Drain dev.in
	for len(dev.in) > 0 {
		<-dev.in
	}

	// Return for flow1 should be dropped as unknown
	ret1 := buildIPv4TCP(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.30.0.1"), 80, 1001, nil)
	ingress.handleReturn(ret1, encapBuf)
	if len(conn.out) != 0 {
		t.Fatal("evicted flow1 return packet was forwarded")
	}
	if ingress.droppedUnknownReturn != 1 {
		t.Errorf("droppedUnknownReturn = %d, want 1", ingress.droppedUnknownReturn)
	}

	// Return for flow2 should succeed
	ret2 := buildIPv4TCP(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.30.0.2"), 80, 1002, nil)
	ingress.handleReturn(ret2, encapBuf)
	if len(conn.out) != 1 {
		t.Fatal("flow2 return packet was not forwarded")
	}
	<-conn.out

	// Return for flow3 should succeed
	ret3 := buildIPv4TCP(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.30.0.3"), 80, 1003, nil)
	ingress.handleReturn(ret3, encapBuf)
	if len(conn.out) != 1 {
		t.Fatal("flow3 return packet was not forwarded")
	}
	<-conn.out
}

func TestHealthCheckServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tunnelUp atomic.Bool
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv, err := startHealthServer(ctx, "127.0.0.1:0", tunnelUp.Load, log)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	url := "http://" + srv.Addr + "/healthz"

	// 1. When tunnel is down: 503
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; body: %s", resp.StatusCode, body)
	}

	// 2. When tunnel is up: 200 "ok\n"
	tunnelUp.Store(true)
	resp, err = http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", resp.StatusCode, body)
	}
	if string(body) != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}
