package securitytest

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

// tunnel is a hostile Client: a real PQ session and WireGuard tunnel to the dev Edge, but
// with a channel TUN instead of the OpenSASE client, so the harness writes raw IP packets
// (any source, any destination, any flags) straight into the tunnel. Only the Edge's own
// enforcement stands between these packets and the network.
type tunnel struct {
	dev  *device.Device
	ch   *tuntest.ChannelTUN
	ip4  netip.Addr
	ip6  netip.Addr
	mu   sync.Mutex
	rx   []*packet.Packet
	cond *sync.Cond
	done chan struct{}
}

const edgeTunIP = "100.64.0.1"

func (f *fixture) openTunnel(d *ident) (*tunnel, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	r := do(f.edge(d.cert), "POST", f.edgeURL+"/v1/session", api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub)}, nil)
	sr, err := decode[api.SessionResponse](r)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	edgePub, err := base64.StdEncoding.DecodeString(sr.EdgeWGKey)
	if err != nil {
		return nil, err
	}
	psk, err := pqsession.DerivePSK(*r.tls, pub, edgePub, sr.SessionID, sr.Epoch)
	if err != nil {
		return nil, err
	}
	defer clear(psk[:])
	p4, err := netip.ParsePrefix(sr.TunnelIPv4)
	if err != nil {
		return nil, err
	}
	p6, _ := netip.ParsePrefix(sr.TunnelIPv6)
	tn := &tunnel{ch: tuntest.NewChannelTUN(), ip4: p4.Addr(), ip6: p6.Addr(), done: make(chan struct{})}
	tn.cond = sync.NewCond(&tn.mu)
	tn.dev = device.NewDevice(tn.ch.TUN(), conn.NewDefaultBind(), device.NewLogger(wgLogLevel(), "sectest-wg: "))
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\npersistent_keepalive_interval=5\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		hex.EncodeToString(priv.Bytes()), hex.EncodeToString(edgePub), hex.EncodeToString(psk[:]), f.wgAddr)
	if err := tn.dev.IpcSet(cfg); err != nil {
		tn.dev.Close()
		return nil, err
	}
	if err := tn.dev.Up(); err != nil {
		tn.dev.Close()
		return nil, err
	}
	go tn.read()
	// Ready when the Edge answers a ping on its tunnel address.
	for range 10 {
		tn.send(icmpEcho(tn.ip4, netip.MustParseAddr(edgeTunIP), 0x5ec))
		if tn.wait(time.Second, func(p *packet.Packet) bool {
			return p.Protocol == packet.ProtoICMP && p.Src == netip.MustParseAddr(edgeTunIP)
		}) != nil {
			return tn, nil
		}
	}
	tn.close()
	return nil, fmt.Errorf("no ping reply from %s through the tunnel", edgeTunIP)
}

var pingID struct {
	sync.Mutex
	n uint16
}

// ping reports whether the Edge answers an echo request on its tunnel address.
func (tn *tunnel) ping() bool {
	pingID.Lock()
	pingID.n++
	id := 0x6000 + pingID.n
	pingID.Unlock()
	tn.send(icmpEcho(tn.ip4, netip.MustParseAddr(edgeTunIP), id))
	return tn.wait(1500*time.Millisecond, func(p *packet.Packet) bool {
		return p.Protocol == packet.ProtoICMP && p.Src == netip.MustParseAddr(edgeTunIP) && p.SrcPort == id
	}) != nil
}

func (tn *tunnel) read() {
	for {
		select {
		case <-tn.done:
			return
		case b := <-tn.ch.Inbound:
			if os.Getenv("SECTEST_WG_DEBUG") == "1" {
				fmt.Printf("sectest-wg: rx %d bytes %x\n", len(b), b[:min(len(b), 40)])
			}
			var p packet.Packet
			if packet.Parse(b, &p) != nil {
				continue
			}
			p.Payload = append([]byte(nil), p.Payload...)
			p.Src, p.Dst = p.Src.Unmap(), p.Dst.Unmap()
			tn.mu.Lock()
			tn.rx = append(tn.rx, &p)
			tn.cond.Broadcast()
			tn.mu.Unlock()
		}
	}
}

func (tn *tunnel) send(b []byte) {
	select {
	case tn.ch.Outbound <- b:
	case <-time.After(2 * time.Second):
		if os.Getenv("SECTEST_WG_DEBUG") == "1" {
			fmt.Println("sectest-wg: send timed out")
		}
	}
}

// wait returns (and consumes) the first received packet matching pred within d.
func (tn *tunnel) wait(d time.Duration, pred func(*packet.Packet) bool) *packet.Packet {
	deadline := time.Now().Add(d)
	t := time.AfterFunc(d, func() { tn.mu.Lock(); tn.cond.Broadcast(); tn.mu.Unlock() })
	defer t.Stop()
	tn.mu.Lock()
	defer tn.mu.Unlock()
	for {
		for i, p := range tn.rx {
			if pred(p) {
				tn.rx = append(tn.rx[:i], tn.rx[i+1:]...)
				return p
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		tn.cond.Wait()
	}
}

func (tn *tunnel) close() {
	close(tn.done)
	tn.dev.Close()
}

// --- packet crafting ---

func csum(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func pseudo(src, dst netip.Addr, proto uint8, n int) uint32 {
	var s uint32
	for _, a := range [][]byte{src.AsSlice(), dst.AsSlice()} {
		for i := 0; i < len(a); i += 2 {
			s += uint32(binary.BigEndian.Uint16(a[i:]))
		}
	}
	return s + uint32(proto) + uint32(n)
}

// ipPacket wraps an L4 segment (checksum filled by the caller via fill) in IPv4 or IPv6.
func ipPacket(src, dst netip.Addr, proto uint8, l4 []byte, ckOff int) []byte {
	binary.BigEndian.PutUint16(l4[ckOff:], 0)
	binary.BigEndian.PutUint16(l4[ckOff:], csum(l4, pseudo(src, dst, proto, len(l4))))
	if src.Is4() {
		h := make([]byte, 20)
		h[0], h[8], h[9] = 0x45, 64, proto
		binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
		copy(h[12:16], src.AsSlice())
		copy(h[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(h[10:], csum(h, 0))
		return append(h, l4...)
	}
	h := make([]byte, 40)
	h[0], h[6], h[7] = 0x60, proto, 64
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	copy(h[8:24], src.AsSlice())
	copy(h[24:40], dst.AsSlice())
	return append(h, l4...)
}

// icmpEcho is an ICMPv4 echo request with identifier id (tuntest.Ping has invalid
// checksums, which a real kernel drops).
func icmpEcho(src, dst netip.Addr, id uint16) []byte {
	m := make([]byte, 16)
	m[0] = 8
	binary.BigEndian.PutUint16(m[4:], id)
	binary.BigEndian.PutUint16(m[6:], 1)
	copy(m[8:], "sectest!")
	binary.BigEndian.PutUint16(m[2:], csum(m, 0))
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 64, packet.ProtoICMP
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(m)))
	copy(h[12:16], src.AsSlice())
	copy(h[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(h[10:], csum(h, 0))
	return append(h, m...)
}

func tcpSeg(src, dst netip.AddrPort, flags uint8, seq, ack uint32) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:], src.Port())
	binary.BigEndian.PutUint16(l4[2:], dst.Port())
	binary.BigEndian.PutUint32(l4[4:], seq)
	binary.BigEndian.PutUint32(l4[8:], ack)
	l4[12], l4[13] = 5<<4, flags
	binary.BigEndian.PutUint16(l4[14:], 65000)
	return ipPacket(src.Addr(), dst.Addr(), packet.ProtoTCP, l4, 16)
}

func udpDgram(src, dst netip.AddrPort, payload []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(l4[0:], src.Port())
	binary.BigEndian.PutUint16(l4[2:], dst.Port())
	binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	copy(l4[8:], payload)
	return ipPacket(src.Addr(), dst.Addr(), packet.ProtoUDP, l4, 6)
}

var portSeq struct {
	sync.Mutex
	n uint16
}

func ephemeral() uint16 {
	portSeq.Lock()
	defer portSeq.Unlock()
	if portSeq.n == 0 {
		var b [2]byte
		_, _ = rand.Read(b[:])
		portSeq.n = 20000 + binary.BigEndian.Uint16(b[:])%20000
	}
	portSeq.n++
	return portSeq.n
}

// tcpResult is what came back for a crafted SYN.
type tcpResult string

const (
	synAck tcpResult = "syn-ack"
	rst    tcpResult = "rst"
	none   tcpResult = "none"
)

// probe sends a SYN from src (default: the tunnel's own address) to dst and reports the
// answer seen on rx (default: tn). With an RST from the Edge filter the flow was refused.
func (tn *tunnel) probe(dst netip.AddrPort, src netip.Addr, rx *tunnel, wait time.Duration) tcpResult {
	if !src.IsValid() {
		src = tn.ip4
		if dst.Addr().Is6() {
			src = tn.ip6
		}
	}
	if rx == nil {
		rx = tn
	}
	sp := netip.AddrPortFrom(src, ephemeral())
	tn.send(tcpSeg(sp, dst, packet.FlagSYN, 1000, 0))
	p := rx.wait(wait, func(p *packet.Packet) bool {
		return p.Protocol == packet.ProtoTCP && p.DstPort == sp.Port() && p.SrcPort == dst.Port()
	})
	switch {
	case p == nil:
		return none
	case p.RST():
		return rst
	case p.SYN() && p.ACK():
		// Be polite: abort the half-open connection.
		tn.send(tcpSeg(sp, dst, packet.FlagRST, 1001, 0))
		return synAck
	}
	return none
}

// dnsQuery sends a UDP DNS query for name/qtype to server through the tunnel and returns
// the reply (nil on timeout).
func (tn *tunnel) dnsQuery(server netip.Addr, name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	src := tn.ip4
	if server.Is6() {
		src = tn.ip6
	}
	sp := netip.AddrPortFrom(src, ephemeral())
	tn.send(udpDgram(sp, netip.AddrPortFrom(server, 53), b))
	p := tn.wait(4*time.Second, func(p *packet.Packet) bool {
		return p.Protocol == packet.ProtoUDP && p.DstPort == sp.Port() && p.SrcPort == 53
	})
	if p == nil {
		return nil
	}
	r := new(dns.Msg)
	if r.Unpack(p.Payload) != nil || r.Id != m.Id {
		return nil
	}
	return r
}

// resolve4 returns the A records of name from the Edge resolver.
func (tn *tunnel) resolve4(name string) []netip.Addr {
	r := tn.dnsQuery(netip.MustParseAddr(edgeTunIP), name, dns.TypeA)
	if r == nil {
		return nil
	}
	var out []netip.Addr
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
				out = append(out, ip)
			}
		}
	}
	return out
}

func addrsString(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ",")
}

// wgLogLevel is verbose with SECTEST_WG_DEBUG=1 (handshake troubleshooting).
func wgLogLevel() int {
	if os.Getenv("SECTEST_WG_DEBUG") == "1" {
		return device.LogLevelVerbose
	}
	return device.LogLevelSilent
}
