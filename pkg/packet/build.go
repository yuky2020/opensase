package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Builder errors.
var (
	ErrShortBuffer = errors.New("packet: output buffer too small")
	ErrNotTCP      = errors.New("packet: not a TCP segment with a header")
	ErrIsRST       = errors.New("packet: never answer an RST with an RST")
	ErrNoICMP      = errors.New("packet: no ICMP error allowed for this packet")
)

// defaultTTL is the TTL / hop limit of generated packets.
const defaultTTL = 64

// Maximum sizes of generated packets, useful to size out buffers.
const (
	MaxTCPResetLen = ipv6Header + tcpMinHeader // 60
	// MaxICMPUnreachableLen bounds BuildICMPUnreachable output: IPv6 errors are capped at the
	// IPv6 minimum MTU; IPv4 errors are at most 20+8+60+8 bytes.
	MaxICMPUnreachableLen = 1280
)

// BuildTCPReset writes into out an RST+ACK segment addressed back to the sender of the
// original TCP segment and returns its length. orig is the parsed form of origBytes; if orig
// is nil, origBytes is parsed. The reset uses seq = orig.Ack when the original carried ACK
// (else 0) and ack = orig.Seq + payload length + SYN + FIN, so the app's stack accepts it in
// both SYN_SENT and ESTABLISHED.
func BuildTCPReset(orig *Packet, origBytes []byte, out []byte) (int, error) {
	var parsed Packet
	if orig == nil {
		if err := Parse(origBytes, &parsed); err != nil {
			return 0, err
		}
		orig = &parsed
	}
	if orig.Protocol != ProtoTCP || orig.TransportLen < tcpMinHeader || orig.FragmentOffset > 0 {
		return 0, ErrNotTCP
	}
	if orig.RST() {
		return 0, ErrIsRST
	}
	if !addrsMatchVersion(orig) {
		return 0, ErrHeader
	}
	ipLen := ipv4MinHeader
	if orig.Version == 6 {
		ipLen = ipv6Header
	}
	n := ipLen + tcpMinHeader
	if len(out) < n {
		return 0, ErrShortBuffer
	}
	pkt := out[:n]
	clear(pkt)
	writeIPHeader(pkt, orig, ProtoTCP, tcpMinHeader)

	var seq uint32
	if orig.ACK() {
		seq = orig.Ack
	}
	ack := orig.Seq + uint32(len(orig.Payload))
	if orig.SYN() {
		ack++
	}
	if orig.FIN() {
		ack++
	}
	tcp := pkt[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], orig.DstPort)
	binary.BigEndian.PutUint16(tcp[2:4], orig.SrcPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (tcpMinHeader / 4) << 4
	tcp[13] = FlagRST | FlagACK
	// window 0, checksum filled below, urgent pointer 0
	sum := pseudoHeaderSum(pkt, orig.Version, ProtoTCP, tcpMinHeader)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(tcp, sum))
	return n, nil
}

// BuildICMPUnreachable writes into out an "administratively prohibited" error for the
// packet in origBytes (ICMPv4 type 3 code 13, or ICMPv6 type 1 code 1) and returns its
// length. The error is addressed back to the original sender and quotes the original IP
// header (incl. options / extension headers) plus 8 bytes. It refuses, with ErrNoICMP, to
// answer ICMP errors, non-first fragments and multicast/broadcast packets (RFC 1122, RFC 4443).
func BuildICMPUnreachable(origBytes []byte, out []byte) (int, error) {
	var orig Packet
	if err := Parse(origBytes, &orig); err != nil {
		return 0, err
	}
	if orig.FragmentOffset > 0 {
		return 0, ErrNoICMP
	}
	if (orig.Protocol == ProtoICMP && orig.Version == 4 || orig.Protocol == ProtoICMPv6 && orig.Version == 6) &&
		orig.TransportLen > 0 && isICMPError(orig.Version, orig.ICMPType) {
		return 0, ErrNoICMP
	}
	if orig.Dst.IsMulticast() || orig.Src.IsMulticast() || orig.Src.IsUnspecified() ||
		(orig.Version == 4 && (orig.Dst == broadcast4 || orig.Src == broadcast4)) {
		return 0, ErrNoICMP
	}

	quote := min(orig.IPHeaderLen+8, orig.TotalLen)
	ipLen, proto := ipv4MinHeader, ProtoICMP
	if orig.Version == 6 {
		ipLen, proto = ipv6Header, ProtoICMPv6
		// RFC 4443: the error must not exceed the IPv6 minimum MTU.
		quote = min(quote, MaxICMPUnreachableLen-ipv6Header-icmpHeader)
	}
	icmpLen := icmpHeader + quote
	n := ipLen + icmpLen
	if len(out) < n {
		return 0, ErrShortBuffer
	}
	pkt := out[:n]
	clear(pkt[:ipLen+icmpHeader])
	writeIPHeader(pkt, &orig, proto, icmpLen)
	icmp := pkt[ipLen:]
	var sum uint32
	if orig.Version == 4 {
		icmp[0], icmp[1] = 3, 13
	} else {
		icmp[0], icmp[1] = 1, 1
		sum = pseudoHeaderSum(pkt, 6, ProtoICMPv6, icmpLen)
	}
	copy(icmp[icmpHeader:], origBytes[:quote])
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp, sum))
	return n, nil
}

var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

func addrsMatchVersion(p *Packet) bool {
	if p.Version == 4 {
		return p.Src.Is4() && p.Dst.Is4()
	}
	return p.Version == 6 && p.Src.Is6() && p.Dst.Is6()
}

// writeIPHeader writes an IPv4 or IPv6 header into pkt with the original source and
// destination swapped. payloadLen is the length of everything after the IP header.
func writeIPHeader(pkt []byte, orig *Packet, proto uint8, payloadLen int) {
	if orig.Version == 4 {
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(ipv4MinHeader+payloadLen))
		binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
		pkt[8] = defaultTTL
		pkt[9] = proto
		src, dst := orig.Dst.As4(), orig.Src.As4()
		copy(pkt[12:16], src[:])
		copy(pkt[16:20], dst[:])
		binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ipv4MinHeader], 0))
		return
	}
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = proto
	pkt[7] = defaultTTL
	src, dst := orig.Dst.As16(), orig.Src.As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
}

// pseudoHeaderSum returns the unfolded one's-complement sum of the TCP/UDP/ICMPv6
// pseudo-header for the IP header at the start of pkt.
func pseudoHeaderSum(pkt []byte, version, proto uint8, length int) uint32 {
	var sum uint32
	if version == 4 {
		sum = sumBytes(pkt[12:20], 0)
	} else {
		sum = sumBytes(pkt[8:40], 0)
	}
	return sum + uint32(proto) + uint32(length>>16) + uint32(length&0xffff)
}

// sumBytes adds b as big-endian 16-bit words to sum (odd trailing byte padded with zero).
func sumBytes(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		if sum >= 0x80000000 {
			sum = sum&0xffff + sum>>16
		}
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

// checksum returns the Internet checksum (RFC 1071) of b with an initial partial sum.
func checksum(b []byte, initial uint32) uint16 {
	sum := sumBytes(b, initial)
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
