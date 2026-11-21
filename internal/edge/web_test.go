package edge

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/peek"
)

// clientHello captures a real ClientHello for name, with a post-quantum key share so that
// it does not fit one segment.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true, //nolint:gosec // only the ClientHello is captured
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}).Handshake()
		_ = c.Close()
	}()
	var out []byte
	buf := make([]byte, 4096)
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := s.Read(buf)
		out = append(out, buf[:n]...)
		if _, _, r := peek.Host(out); err != nil || r != peek.NeedMore {
			return out
		}
	}
}

// tcpData is a client data segment with sequence number seq.
func tcpData(sport, dport uint16, seq uint32, payload []byte) []byte {
	t := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], 5001)
	t[12], t[13] = 5<<4, packet.FlagACK|packet.FlagPSH
	binary.BigEndian.PutUint16(t[14:], 65535)
	copy(t[20:], payload)
	return t
}

// TestWebControl checks ADR-0017 at the Edge: the hostname in the TLS SNI or HTTP Host is
// enforced against the DNS policy (SaaS lists included), domain rules and built-in rules,
// on the segment that completes the message.
func TestWebControl(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	_ = fx.e.syncPeers(context.Background())
	d := fx.e.reg.get("d1")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d)
	fx.e.reg.mu.Unlock()
	me := d.ip4.String()

	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)
	write := func(pkt []byte) bool {
		t.Helper()
		before := ft.nWrites()
		if _, err := f.Write([][]byte{pkt}, 0); err != nil {
			t.Fatal(err)
		}
		return ft.nWrites() > before
	}
	// open sends a SYN (ISN 1000, so data starts at 1001) and checks it passes.
	open := func(sport, dport uint16) {
		t.Helper()
		if !write(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpSeg(sport, dport, packet.FlagSYN))) {
			t.Fatalf("SYN %d dropped", sport)
		}
	}
	// send writes payload in segments of at most mss bytes; it returns how many passed.
	send := func(sport, dport uint16, payload []byte, mss int) (passed, total int) {
		t.Helper()
		seq := uint32(1001)
		for len(payload) > 0 {
			n := min(mss, len(payload))
			total++
			if write(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpData(sport, dport, seq, payload[:n]))) {
				passed++
			}
			seq += uint32(n)
			payload = payload[n:]
		}
		return passed, total
	}
	webRecord := func(rule string) bool {
		for _, r := range fx.e.flows.recs {
			if r.Decision.Layer == LayerWeb && r.Decision.RuleID == rule {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		name   string
		port   uint16
		data   []byte
		rule   string // "" = allowed
		domain string
	}{
		{"saas app by sni", 443, clientHello(t, "www.dropbox.com"), "saas:dropbox", "www.dropbox.com"},
		{"dns blocklist by http host", 80, []byte("GET / HTTP/1.1\r\nHost: ads.doubleclick.net\r\n\r\n"), "dns:ads", "ads.doubleclick.net"},
		{"domain rule by sni", 443, clientHello(t, "cdn.tracker.test"), "tenant:no-tracker", "cdn.tracker.test"},
		{"doh by sni", 443, clientHello(t, "dns.google"), RuleDNSBypass, "dns.google"},
		{"allowed sni", 443, clientHello(t, "www.example.org"), "", "www.example.org"},
		{"not tls nor http", 22, []byte("SSH-2.0-OpenSSH_9.9\r\n"), "", ""},
	} {
		sport := uint16(42000 + len(tc.name))
		open(sport, tc.port)
		passed, total := send(sport, tc.port, tc.data, 1200)
		blocked := tc.rule != ""
		switch {
		case blocked && passed != total-1:
			t.Errorf("%s: %d of %d segments passed; want all but the completing one", tc.name, passed, total)
		case !blocked && passed != total:
			t.Errorf("%s: %d of %d segments passed", tc.name, passed, total)
		}
		if blocked {
			if _, ok := readOne(t, rd); !ok {
				t.Errorf("%s: no RST to the device", tc.name)
			}
			if tc.rule != RuleDNSBypass && !webRecord(tc.rule) {
				t.Errorf("%s: no web record %q in %+v", tc.name, tc.rule, fx.e.flows.recs)
			}
			// The flow stays blocked.
			if write(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpData(sport, tc.port, 1001+uint32(len(tc.data)), []byte("x")))) {
				t.Errorf("%s: data after the block passed", tc.name)
			}
			if _, ok := readOne(t, rd); !ok {
				t.Errorf("%s: no RST for data after the block", tc.name)
			}
		}
		var p packet.Packet
		_ = packet.Parse(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpSeg(sport, tc.port, packet.FlagSYN)), &p)
		cn := f.ct.get(p.FlowKey())
		if cn == nil {
			t.Fatalf("%s: no conntrack entry", tc.name)
		}
		if rec := cn.record(time.Now()); rec.Flow.Domain != tc.domain {
			t.Errorf("%s: recorded domain %q want %q", tc.name, rec.Flow.Domain, tc.domain)
		}
	}
	if !webRecord("saas:dropbox") {
		t.Fatal("no saas record")
	}

	// Out of order while peeking: a segment beyond a gap is held back until the gap fills.
	ch := clientHello(t, "www.dropbox.com")
	open(43000, 443)
	if write(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpData(43000, 443, 1001+1000, ch[1000:]))) {
		t.Fatal("segment after a gap passed while peeking")
	}
	if !write(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpData(43000, 443, 1001, ch[:1000]))) {
		t.Fatal("first segment dropped")
	}
	// A retransmission overlapping known bytes and completing the hello is decided.
	if write(ipv4(me, "198.51.100.7", packet.ProtoTCP, tcpData(43000, 443, 1001+500, ch[500:]))) {
		t.Fatal("completing retransmission of a blocked hello passed")
	}
}
