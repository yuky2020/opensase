package packet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// refChecksum is an independent RFC 1071 implementation used to check the package: it
// pads to an even length and sums 16-bit words in a uint64 before folding.
func refChecksum(chunks ...[]byte) uint16 {
	var all []byte
	for _, c := range chunks {
		all = append(all, c...)
	}
	if len(all)%2 == 1 {
		all = append(all, 0)
	}
	var s uint64
	for i := 0; i < len(all); i += 2 {
		s += uint64(binary.BigEndian.Uint16(all[i:]))
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func pseudo4(src, dst netip.Addr, proto uint8, n int) []byte {
	s, d := src.As4(), dst.As4()
	b := append(append([]byte{}, s[:]...), d[:]...)
	return append(b, 0, proto, byte(n>>8), byte(n))
}

func pseudo6(src, dst netip.Addr, proto uint8, n int) []byte {
	s, d := src.As16(), dst.As16()
	b := append(append([]byte{}, s[:]...), d[:]...)
	return append(b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n), 0, 0, 0, proto)
}

// verifyChecksums checks the IPv4 header checksum and the transport checksum of pkt with
// refChecksum. A correct checksum makes the complemented sum over the data zero.
func verifyChecksums(t *testing.T, pkt []byte) {
	t.Helper()
	var p Packet
	if err := Parse(pkt, &p); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	l4 := pkt[p.IPHeaderLen:p.TotalLen]
	switch p.Version {
	case 4:
		if c := refChecksum(pkt[:p.IPHeaderLen]); c != 0 {
			t.Errorf("IPv4 header checksum wrong (residue %#04x)", c)
		}
		var c uint16
		if p.Protocol == ProtoICMP {
			c = refChecksum(l4)
		} else {
			c = refChecksum(pseudo4(p.Src, p.Dst, p.Protocol, len(l4)), l4)
		}
		if c != 0 {
			t.Errorf("IPv4 L4 checksum wrong (residue %#04x)", c)
		}
	case 6:
		if c := refChecksum(pseudo6(p.Src, p.Dst, p.Protocol, len(l4)), l4); c != 0 {
			t.Errorf("IPv6 L4 checksum wrong (residue %#04x)", c)
		}
	}
}

var (
	a4src = netip.MustParseAddr("10.0.0.2")
	a4dst = netip.MustParseAddr("93.184.216.34")
	a6src = netip.MustParseAddr("fd00::2")
	a6dst = netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")
)

// ip4 builds an IPv4 packet with a correct header checksum. opts must be a multiple of 4.
func ip4(proto uint8, src, dst netip.Addr, frag uint16, opts, l4 []byte) []byte {
	ihl := 20 + len(opts)
	b := make([]byte, ihl, ihl+len(l4))
	b[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(b[2:], uint16(ihl+len(l4)))
	binary.BigEndian.PutUint16(b[4:], 0x1234)
	binary.BigEndian.PutUint16(b[6:], frag)
	b[8], b[9] = 64, proto
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], opts)
	binary.BigEndian.PutUint16(b[10:], refChecksum(b[:ihl]))
	return append(b, l4...)
}

// ip6 builds an IPv6 packet; ext is the raw extension-header chain and first is the first
// next-header value.
func ip6(first uint8, src, dst netip.Addr, ext, l4 []byte) []byte {
	b := make([]byte, 40, 40+len(ext)+len(l4))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(ext)+len(l4)))
	b[6], b[7] = first, 64
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	return append(append(b, ext...), l4...)
}

// tcpSeg builds a TCP segment with optional options (multiple of 4) and a checksum.
func tcpSeg(src, dst netip.Addr, sp, dp uint16, seq, ack uint32, flags uint8, opts, payload []byte) []byte {
	hl := 20 + len(opts)
	b := make([]byte, hl, hl+len(payload))
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12] = byte(hl/4) << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], 65535)
	copy(b[20:], opts)
	b = append(b, payload...)
	setL4Checksum(b, src, dst, ProtoTCP, 16)
	return b
}

func udpDgram(src, dst netip.Addr, sp, dp uint16, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	b = append(b, payload...)
	setL4Checksum(b, src, dst, ProtoUDP, 6)
	return b
}

func icmpMsg(src, dst netip.Addr, v6 bool, typ, code uint8, rest uint32, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	b[0], b[1] = typ, code
	binary.BigEndian.PutUint32(b[4:], rest)
	b = append(b, payload...)
	if v6 {
		setL4Checksum(b, src, dst, ProtoICMPv6, 2)
	} else {
		binary.BigEndian.PutUint16(b[2:], refChecksum(b))
	}
	return b
}

func setL4Checksum(b []byte, src, dst netip.Addr, proto uint8, off int) {
	var ph []byte
	if src.Is4() {
		ph = pseudo4(src, dst, proto, len(b))
	} else {
		ph = pseudo6(src, dst, proto, len(b))
	}
	binary.BigEndian.PutUint16(b[off:], refChecksum(ph, b))
}

func TestRefChecksumGolden(t *testing.T) {
	// Well-known IPv4 header example (checksum field 0xb861).
	h, _ := hex.DecodeString("450000730000400040110000c0a80001c0a800c7")
	if got := refChecksum(h); got != 0xb861 {
		t.Fatalf("refChecksum = %#04x, want 0xb861", got)
	}
	if got := checksum(h, 0); got != 0xb861 {
		t.Fatalf("checksum = %#04x, want 0xb861", got)
	}
	// RFC 1071 section 3 example: words 0001 f203 f4f5 f6f7 sum to 0xddf2.
	ex := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := refChecksum(ex); got != ^uint16(0xddf2) {
		t.Fatalf("RFC 1071 example = %#04x", got)
	}
	// Odd length and large buffers agree between implementations.
	big := bytes.Repeat([]byte{0xff, 0xfe, 0x01}, 50001)
	if a, b := checksum(big, 0), refChecksum(big); a != b {
		t.Fatalf("checksum %#04x != ref %#04x", a, b)
	}
}

func TestParse(t *testing.T) {
	payload := []byte("hello")
	mss := []byte{2, 4, 0x05, 0xb4}                                       // MSS 1460
	hbh := []byte{ipv6DestOpts, 0, 1, 4, 0, 0, 0, 0}                      // hop-by-hop -> dest opts, PadN
	dst := []byte{ProtoUDP, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // dest opts (16 bytes) -> UDP
	rt := []byte{ProtoTCP, 0, 0, 0, 0, 0, 0, 0}                           // routing -> TCP
	frag0 := []byte{ProtoUDP, 0, 0x00, 0x01, 0, 0, 0, 7}                  // offset 0, M=1
	frag1 := []byte{ProtoUDP, 0, 0x00, 0xb8, 0, 0, 0, 7}                  // offset 23*8=184, M=0

	tcp4 := tcpSeg(a4src, a4dst, 40000, 443, 1000, 0, FlagSYN, mss, nil)
	tests := []struct {
		name string
		pkt  []byte
		want Packet // Payload compared separately
		pay  []byte
	}{
		{"v4 tcp syn with options", ip4(ProtoTCP, a4src, a4dst, 0x4000, nil, tcp4),
			Packet{Version: 4, Protocol: ProtoTCP, Src: a4src, Dst: a4dst, SrcPort: 40000, DstPort: 443, TCPFlags: FlagSYN, Seq: 1000, TTL: 64, IPHeaderLen: 20, TransportLen: 24, TotalLen: 44}, nil},
		{"v4 tcp with ip options", ip4(ProtoTCP, a4src, a4dst, 0, []byte{1, 1, 1, 0}, tcpSeg(a4src, a4dst, 1, 2, 5, 6, FlagACK|FlagPSH|FlagFIN, nil, payload)),
			Packet{Version: 4, Protocol: ProtoTCP, Src: a4src, Dst: a4dst, SrcPort: 1, DstPort: 2, TCPFlags: FlagACK | FlagPSH | FlagFIN, Seq: 5, Ack: 6, TTL: 64, IPHeaderLen: 24, TransportLen: 20, TotalLen: 49}, payload},
		{"v4 udp", ip4(ProtoUDP, a4src, a4dst, 0, nil, udpDgram(a4src, a4dst, 5353, 53, payload)),
			Packet{Version: 4, Protocol: ProtoUDP, Src: a4src, Dst: a4dst, SrcPort: 5353, DstPort: 53, TTL: 64, IPHeaderLen: 20, TransportLen: 8, TotalLen: 33}, payload},
		{"v4 icmp echo", ip4(ProtoICMP, a4src, a4dst, 0, nil, icmpMsg(a4src, a4dst, false, 8, 0, 0xbeef0001, payload)),
			Packet{Version: 4, Protocol: ProtoICMP, Src: a4src, Dst: a4dst, SrcPort: 0xbeef, DstPort: 0xbeef, ICMPType: 8, TTL: 64, IPHeaderLen: 20, TransportLen: 8, TotalLen: 33}, payload},
		{"v4 icmp unreachable has no ports", ip4(ProtoICMP, a4src, a4dst, 0, nil, icmpMsg(a4src, a4dst, false, 3, 1, 0, payload)),
			Packet{Version: 4, Protocol: ProtoICMP, Src: a4src, Dst: a4dst, ICMPType: 3, ICMPCode: 1, TTL: 64, IPHeaderLen: 20, TransportLen: 8, TotalLen: 33}, payload},
		{"v4 first fragment", ip4(ProtoUDP, a4src, a4dst, 0x2000, nil, udpDgram(a4src, a4dst, 1, 2, payload)),
			Packet{Version: 4, Protocol: ProtoUDP, Src: a4src, Dst: a4dst, SrcPort: 1, DstPort: 2, TTL: 64, IPHeaderLen: 20, TransportLen: 8, TotalLen: 33, IsFragment: true}, payload},
		{"v4 non-first fragment", ip4(ProtoUDP, a4src, a4dst, 0x0003, nil, payload),
			Packet{Version: 4, Protocol: ProtoUDP, Src: a4src, Dst: a4dst, TTL: 64, IPHeaderLen: 20, TotalLen: 25, IsFragment: true, FragmentOffset: 24}, payload},
		{"v4 trailing bytes ignored", append(ip4(ProtoUDP, a4src, a4dst, 0, nil, udpDgram(a4src, a4dst, 1, 2, payload)), 0xde, 0xad),
			Packet{Version: 4, Protocol: ProtoUDP, Src: a4src, Dst: a4dst, SrcPort: 1, DstPort: 2, TTL: 64, IPHeaderLen: 20, TransportLen: 8, TotalLen: 33}, payload},
		{"v4 other proto", ip4(47, a4src, a4dst, 0, nil, payload),
			Packet{Version: 4, Protocol: 47, Src: a4src, Dst: a4dst, TTL: 64, IPHeaderLen: 20, TotalLen: 25}, payload},
		{"v6 tcp", ip6(ProtoTCP, a6src, a6dst, nil, tcpSeg(a6src, a6dst, 50000, 443, 7, 9, FlagACK, nil, payload)),
			Packet{Version: 6, Protocol: ProtoTCP, Src: a6src, Dst: a6dst, SrcPort: 50000, DstPort: 443, TCPFlags: FlagACK, Seq: 7, Ack: 9, TTL: 64, IPHeaderLen: 40, TransportLen: 20, TotalLen: 65}, payload},
		{"v6 hbh+destopts+udp", ip6(ipv6HopByHop, a6src, a6dst, append(append([]byte{}, hbh...), dst...), udpDgram(a6src, a6dst, 1000, 53, payload)),
			Packet{Version: 6, Protocol: ProtoUDP, Src: a6src, Dst: a6dst, SrcPort: 1000, DstPort: 53, TTL: 64, IPHeaderLen: 64, TransportLen: 8, TotalLen: 77}, payload},
		{"v6 routing+tcp", ip6(ipv6Routing, a6src, a6dst, rt, tcpSeg(a6src, a6dst, 3, 4, 0, 0, FlagSYN, nil, nil)),
			Packet{Version: 6, Protocol: ProtoTCP, Src: a6src, Dst: a6dst, SrcPort: 3, DstPort: 4, TCPFlags: FlagSYN, TTL: 64, IPHeaderLen: 48, TransportLen: 20, TotalLen: 68}, nil},
		{"v6 first fragment", ip6(ipv6Fragment, a6src, a6dst, frag0, udpDgram(a6src, a6dst, 1, 2, payload)),
			Packet{Version: 6, Protocol: ProtoUDP, Src: a6src, Dst: a6dst, SrcPort: 1, DstPort: 2, TTL: 64, IPHeaderLen: 48, TransportLen: 8, TotalLen: 61, IsFragment: true}, payload},
		{"v6 non-first fragment", ip6(ipv6Fragment, a6src, a6dst, frag1, payload),
			Packet{Version: 6, Protocol: ProtoUDP, Src: a6src, Dst: a6dst, TTL: 64, IPHeaderLen: 48, TotalLen: 53, IsFragment: true, FragmentOffset: 184}, payload},
		{"v6 icmpv6 echo", ip6(ProtoICMPv6, a6src, a6dst, nil, icmpMsg(a6src, a6dst, true, 128, 0, 0x00420001, payload)),
			Packet{Version: 6, Protocol: ProtoICMPv6, Src: a6src, Dst: a6dst, SrcPort: 0x42, DstPort: 0x42, ICMPType: 128, TTL: 64, IPHeaderLen: 40, TransportLen: 8, TotalLen: 53}, payload},
		{"v6 no next header", ip6(59, a6src, a6dst, nil, nil),
			Packet{Version: 6, Protocol: 59, Src: a6src, Dst: a6dst, TTL: 64, IPHeaderLen: 40, TotalLen: 40}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Packet
			if err := Parse(tt.pkt, &p); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !bytes.Equal(p.Payload, tt.pay) {
				t.Errorf("Payload = %q, want %q", p.Payload, tt.pay)
			}
			p.Payload = nil
			if !reflect.DeepEqual(p, tt.want) {
				t.Errorf("Parse =\n %+v\nwant\n %+v", p, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	good4 := ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 1, 2, 0, 0, FlagSYN, nil, nil))
	badIHL := bytes.Clone(good4)
	badIHL[0] = 0x44
	badTotal := bytes.Clone(good4)
	binary.BigEndian.PutUint16(badTotal[2:], 10)
	longTotal := bytes.Clone(good4)
	binary.BigEndian.PutUint16(longTotal[2:], 100)
	badDoff := bytes.Clone(good4)
	badDoff[20+12] = 0x40
	bigDoff := bytes.Clone(good4)
	bigDoff[20+12] = 0xf0
	v5 := bytes.Clone(good4)
	v5[0] = 0x55

	var loop []byte // 9 destination-option headers chained
	for range 9 {
		loop = append(loop, ipv6DestOpts, 0, 1, 4, 0, 0, 0, 0)
	}
	tests := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"version 5", v5, ErrVersion},
		{"v4 short", good4[:19], ErrTruncated},
		{"v4 ihl < 5", badIHL, ErrHeader},
		{"v4 total < ihl", badTotal, ErrHeader},
		{"v4 total > len", longTotal, ErrTruncated},
		{"tcp doff < 5", badDoff, ErrHeader},
		{"tcp doff > len", bigDoff, ErrTruncated},
		{"v4 tcp truncated", ip4(ProtoTCP, a4src, a4dst, 0, nil, make([]byte, 10)), ErrTruncated},
		{"v4 udp truncated", ip4(ProtoUDP, a4src, a4dst, 0, nil, make([]byte, 7)), ErrTruncated},
		{"v4 icmp truncated", ip4(ProtoICMP, a4src, a4dst, 0, nil, make([]byte, 4)), ErrTruncated},
		{"v6 short", append([]byte{0x60}, make([]byte, 38)...), ErrTruncated},
		{"v6 empty payload is valid", ip6(59, a6src, a6dst, nil, nil), nil},
		{"v6 udp without header", ip6(ProtoUDP, a6src, a6dst, nil, nil), ErrTruncated},
		{"v6 ext truncated", ip6(ipv6HopByHop, a6src, a6dst, []byte{ProtoUDP, 0, 0, 0}, nil), ErrTruncated},
		{"v6 ext length beyond packet", ip6(ipv6HopByHop, a6src, a6dst, []byte{ProtoUDP, 5, 0, 0, 0, 0, 0, 0}, nil), ErrTruncated},
		{"v6 frag truncated", ip6(ipv6Fragment, a6src, a6dst, []byte{ProtoUDP, 0, 0, 0}, nil), ErrTruncated},
		{"v6 too many ext", ip6(ipv6DestOpts, a6src, a6dst, loop, nil), ErrHeader},
	}
	v6long := ip6(ProtoUDP, a6src, a6dst, nil, udpDgram(a6src, a6dst, 1, 2, nil))
	binary.BigEndian.PutUint16(v6long[4:], 100)
	tests = append(tests, struct {
		name string
		pkt  []byte
		want error
	}{"v6 payload length > len", v6long, ErrTruncated})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Packet
			if err := Parse(tt.pkt, &p); !errors.Is(err, tt.want) {
				t.Fatalf("Parse err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseNoAllocs(t *testing.T) {
	pkts := [][]byte{
		ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 1, 2, 0, 0, FlagSYN, nil, nil)),
		ip6(ipv6HopByHop, a6src, a6dst, []byte{ProtoUDP, 0, 1, 4, 0, 0, 0, 0}, udpDgram(a6src, a6dst, 1, 2, nil)),
	}
	var p Packet
	for _, b := range pkts {
		if n := testing.AllocsPerRun(100, func() { _ = Parse(b, &p) }); n != 0 {
			t.Errorf("Parse allocs = %v", n)
		}
	}
}

func TestFlowKey(t *testing.T) {
	var out, in Packet
	if err := Parse(ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 40000, 443, 0, 0, FlagSYN, nil, nil)), &out); err != nil {
		t.Fatal(err)
	}
	if err := Parse(ip4(ProtoTCP, a4dst, a4src, 0, nil, tcpSeg(a4dst, a4src, 443, 40000, 0, 1, FlagSYN|FlagACK, nil, nil)), &in); err != nil {
		t.Fatal(err)
	}
	k := out.FlowKey()
	if k != (FlowKey{Proto: ProtoTCP, Src: a4src, Dst: a4dst, SrcPort: 40000, DstPort: 443}) {
		t.Fatalf("FlowKey = %+v", k)
	}
	if in.FlowKey() != k.Reverse() || k.Reverse().Reverse() != k {
		t.Fatal("Reverse mismatch")
	}
	m := map[FlowKey]int{k: 1}
	if m[in.FlowKey().Reverse()] != 1 {
		t.Fatal("FlowKey not usable as map key")
	}
	// ICMP echo reply matches request.
	var req, rep Packet
	_ = Parse(ip6(ProtoICMPv6, a6src, a6dst, nil, icmpMsg(a6src, a6dst, true, 128, 0, 0x00070001, nil)), &req)
	_ = Parse(ip6(ProtoICMPv6, a6dst, a6src, nil, icmpMsg(a6dst, a6src, true, 129, 0, 0x00070001, nil)), &rep)
	if rep.FlowKey() != req.FlowKey().Reverse() {
		t.Fatalf("echo reply key %+v != reverse of %+v", rep.FlowKey(), req.FlowKey())
	}
	if !req.HasPorts() {
		t.Error("echo request HasPorts = false")
	}
}

func TestBuildTCPReset(t *testing.T) {
	big := bytes.Repeat([]byte{'x'}, 100)
	tests := []struct {
		name    string
		pkt     []byte
		nilOrig bool
		wantSeq uint32
		wantAck uint32
		wantLen int
	}{
		{"v4 syn", ip4(ProtoTCP, a4src, a4dst, 0x4000, nil, tcpSeg(a4src, a4dst, 40000, 443, 0xfffffff0, 0, FlagSYN, []byte{2, 4, 5, 0xb4}, nil)), false, 0, 0xfffffff1, 40},
		{"v4 data+fin with ack", ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 40000, 443, 1000, 5555, FlagACK|FlagPSH|FlagFIN, nil, big)), false, 5555, 1101, 40},
		{"v4 seq wraps", ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 1, 2, 0xffffffff, 1, FlagACK, nil, big)), true, 1, 99, 40},
		{"v6 syn", ip6(ProtoTCP, a6src, a6dst, nil, tcpSeg(a6src, a6dst, 50000, 80, 42, 0, FlagSYN, nil, nil)), true, 0, 43, 60},
		{"v6 data with ext header", ip6(ipv6HopByHop, a6src, a6dst, []byte{ProtoTCP, 0, 1, 4, 0, 0, 0, 0}, tcpSeg(a6src, a6dst, 50000, 80, 10, 20, FlagACK, nil, big)), false, 20, 110, 60},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var orig Packet
			if err := Parse(tt.pkt, &orig); err != nil {
				t.Fatal(err)
			}
			op := &orig
			if tt.nilOrig {
				op = nil
			}
			out := make([]byte, MaxTCPResetLen)
			n, err := BuildTCPReset(op, tt.pkt, out)
			if err != nil {
				t.Fatalf("BuildTCPReset: %v", err)
			}
			if n != tt.wantLen {
				t.Fatalf("len = %d, want %d", n, tt.wantLen)
			}
			verifyChecksums(t, out[:n])
			var r Packet
			if err := Parse(out[:n], &r); err != nil {
				t.Fatal(err)
			}
			want := Packet{Version: orig.Version, Protocol: ProtoTCP, Src: orig.Dst, Dst: orig.Src, SrcPort: orig.DstPort, DstPort: orig.SrcPort,
				TCPFlags: FlagRST | FlagACK, Seq: tt.wantSeq, Ack: tt.wantAck, TTL: 64, IPHeaderLen: n - 20, TransportLen: 20, TotalLen: n}
			r.Payload = nil
			if !reflect.DeepEqual(r, want) {
				t.Fatalf("reset =\n %+v\nwant\n %+v", r, want)
			}
			if r.FlowKey() != orig.FlowKey().Reverse() {
				t.Fatal("reset is not on the reverse flow")
			}
		})
	}

	syn := ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 1, 2, 0, 0, FlagSYN, nil, nil))
	rst := ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 1, 2, 0, 0, FlagRST, nil, nil))
	udp := ip4(ProtoUDP, a4src, a4dst, 0, nil, udpDgram(a4src, a4dst, 1, 2, nil))
	frag := ip4(ProtoTCP, a4src, a4dst, 0x0001, nil, make([]byte, 20))
	errTests := []struct {
		name string
		pkt  []byte
		out  int
		want error
	}{
		{"rst", rst, 60, ErrIsRST},
		{"udp", udp, 60, ErrNotTCP},
		{"non-first fragment", frag, 60, ErrNotTCP},
		{"short out", syn, 39, ErrShortBuffer},
		{"garbage", []byte{0x45}, 60, ErrTruncated},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BuildTCPReset(nil, tt.pkt, make([]byte, tt.out)); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestBuildICMPUnreachable(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 200)
	hbh := []byte{ProtoUDP, 0, 1, 4, 0, 0, 0, 0}
	tests := []struct {
		name      string
		pkt       []byte
		wantQuote int
	}{
		{"v4 udp", ip4(ProtoUDP, a4src, a4dst, 0, nil, udpDgram(a4src, a4dst, 5000, 53, payload)), 28},
		{"v4 with options", ip4(ProtoTCP, a4src, a4dst, 0, []byte{1, 1, 1, 0}, tcpSeg(a4src, a4dst, 1, 2, 0, 0, FlagSYN, nil, nil)), 32},
		{"v4 short orig", ip4(ProtoUDP, a4src, a4dst, 0, nil, udpDgram(a4src, a4dst, 5000, 53, nil)), 28},
		{"v4 icmp echo", ip4(ProtoICMP, a4src, a4dst, 0, nil, icmpMsg(a4src, a4dst, false, 8, 0, 1, payload)), 28},
		{"v4 first fragment", ip4(ProtoUDP, a4src, a4dst, 0x2000, nil, udpDgram(a4src, a4dst, 5000, 53, payload)), 28},
		{"v6 udp", ip6(ProtoUDP, a6src, a6dst, nil, udpDgram(a6src, a6dst, 5000, 443, payload)), 48},
		{"v6 with ext", ip6(ipv6HopByHop, a6src, a6dst, hbh, udpDgram(a6src, a6dst, 5000, 443, payload)), 56},
		{"v6 tcp", ip6(ProtoTCP, a6src, a6dst, nil, tcpSeg(a6src, a6dst, 1, 2, 0, 0, FlagSYN, nil, nil)), 48},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var orig Packet
			if err := Parse(tt.pkt, &orig); err != nil {
				t.Fatal(err)
			}
			out := make([]byte, MaxICMPUnreachableLen)
			n, err := BuildICMPUnreachable(tt.pkt, out)
			if err != nil {
				t.Fatalf("BuildICMPUnreachable: %v", err)
			}
			ipLen, typ, code, proto := 20, uint8(3), uint8(13), ProtoICMP
			if orig.Version == 6 {
				ipLen, typ, code, proto = 40, 1, 1, ProtoICMPv6
			}
			if n != ipLen+8+tt.wantQuote {
				t.Fatalf("len = %d, want %d", n, ipLen+8+tt.wantQuote)
			}
			verifyChecksums(t, out[:n])
			var r Packet
			if err := Parse(out[:n], &r); err != nil {
				t.Fatal(err)
			}
			if r.Version != orig.Version || r.Protocol != proto || r.Src != orig.Dst || r.Dst != orig.Src ||
				r.ICMPType != typ || r.ICMPCode != code || r.HasPorts() {
				t.Fatalf("unexpected error packet %+v", r)
			}
			if rest := binary.BigEndian.Uint32(out[ipLen+4:]); rest != 0 {
				t.Errorf("unused field = %#x", rest)
			}
			if !bytes.Equal(r.Payload, tt.pkt[:tt.wantQuote]) {
				t.Errorf("quote mismatch:\n %x\n %x", r.Payload, tt.pkt[:tt.wantQuote])
			}
		})
	}

	// v6 errors are capped at 1280 bytes.
	huge := ip6(ProtoUDP, a6src, a6dst, nil, udpDgram(a6src, a6dst, 1, 2, nil))
	ext := make([]byte, 0, 2048)
	ext = append(ext, ProtoUDP, 255) // hop-by-hop of (255+1)*8 = 2048 bytes
	ext = append(ext, make([]byte, 2046)...)
	huge = ip6(ipv6HopByHop, a6src, a6dst, ext, udpDgram(a6src, a6dst, 1, 2, nil))
	out := make([]byte, MaxICMPUnreachableLen)
	n, err := BuildICMPUnreachable(huge, out)
	if err != nil || n != 1280 {
		t.Fatalf("huge v6: n=%d err=%v", n, err)
	}
	verifyChecksums(t, out[:n])

	mcast := netip.MustParseAddr("224.0.0.251")
	errTests := []struct {
		name string
		pkt  []byte
		out  int
		want error
	}{
		{"icmp error", ip4(ProtoICMP, a4src, a4dst, 0, nil, icmpMsg(a4src, a4dst, false, 3, 3, 0, nil)), 200, ErrNoICMP},
		{"icmpv6 error", ip6(ProtoICMPv6, a6src, a6dst, nil, icmpMsg(a6src, a6dst, true, 1, 4, 0, nil)), 200, ErrNoICMP},
		{"non-first fragment", ip4(ProtoUDP, a4src, a4dst, 0x0010, nil, payload), 300, ErrNoICMP},
		{"multicast dst", ip4(ProtoUDP, a4src, mcast, 0, nil, udpDgram(a4src, mcast, 5353, 5353, nil)), 200, ErrNoICMP},
		{"broadcast", ip4(ProtoUDP, a4src, netip.MustParseAddr("255.255.255.255"), 0, nil, make([]byte, 8)), 200, ErrNoICMP},
		{"v6 multicast", ip6(ProtoUDP, a6src, netip.MustParseAddr("ff02::fb"), nil, make([]byte, 8)), 200, ErrNoICMP},
		{"unspecified src", ip6(ProtoUDP, netip.IPv6Unspecified(), a6dst, nil, make([]byte, 8)), 200, ErrNoICMP},
		{"short out", ip4(ProtoUDP, a4src, a4dst, 0, nil, udpDgram(a4src, a4dst, 1, 2, nil)), 55, ErrShortBuffer},
		{"garbage", []byte{0x60, 0}, 200, ErrTruncated},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BuildICMPUnreachable(tt.pkt, make([]byte, tt.out)); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(ip4(ProtoTCP, a4src, a4dst, 0, nil, tcpSeg(a4src, a4dst, 1, 2, 3, 4, FlagSYN, []byte{2, 4, 5, 0xb4}, []byte("x"))))
	f.Add(ip4(ProtoUDP, a4src, a4dst, 0x2000, []byte{1, 1, 1, 0}, udpDgram(a4src, a4dst, 1, 2, nil)))
	f.Add(ip6(ipv6HopByHop, a6src, a6dst, []byte{ipv6Fragment, 0, 1, 4, 0, 0, 0, 0, ProtoTCP, 0, 0, 0, 0, 0, 0, 1}, tcpSeg(a6src, a6dst, 1, 2, 3, 4, FlagACK, nil, nil)))
	f.Add(ip6(ProtoICMPv6, a6src, a6dst, nil, icmpMsg(a6src, a6dst, true, 128, 0, 1, nil)))
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Packet
		if err := Parse(b, &p); err != nil {
			return
		}
		if p.TotalLen > len(b) || p.IPHeaderLen > p.TotalLen || p.IPHeaderLen+p.TransportLen+len(p.Payload) != p.TotalLen {
			t.Fatalf("inconsistent lengths: %+v (len %d)", p, len(b))
		}
		if p.Version == 4 && !(p.Src.Is4() && p.Dst.Is4()) || p.Version == 6 && !(p.Src.Is6() && p.Dst.Is6()) {
			t.Fatalf("address family mismatch: %+v", p)
		}
		out := make([]byte, MaxICMPUnreachableLen)
		if n, err := BuildTCPReset(&p, b, out); err == nil {
			verifyChecksums(t, out[:n])
		}
		if n, err := BuildICMPUnreachable(b, out); err == nil {
			verifyChecksums(t, out[:n])
		}
	})
}

func BenchmarkParse(b *testing.B) {
	pkt := ip6(ipv6HopByHop, a6src, a6dst, []byte{ProtoTCP, 0, 1, 4, 0, 0, 0, 0}, tcpSeg(a6src, a6dst, 1, 2, 3, 4, FlagACK, nil, make([]byte, 1200)))
	var p Packet
	b.ReportAllocs()
	for b.Loop() {
		_ = Parse(pkt, &p)
	}
}
