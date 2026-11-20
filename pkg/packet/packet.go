// Package packet parses raw IP packets as read from a TUN device (no link layer) and builds
// the feedback packets the firewall sends back to apps when it blocks a flow. Parsing does
// not allocate.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// IP protocol numbers.
const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// IPv6 extension header numbers that Parse walks.
const (
	ipv6HopByHop = 0
	ipv6Routing  = 43
	ipv6Fragment = 44
	ipv6DestOpts = 60
)

// TCP flag bits as in the TCP header.
const (
	FlagFIN uint8 = 0x01
	FlagSYN uint8 = 0x02
	FlagRST uint8 = 0x04
	FlagPSH uint8 = 0x08
	FlagACK uint8 = 0x10
)

const (
	ipv4MinHeader = 20
	ipv6Header    = 40
	tcpMinHeader  = 20
	udpHeader     = 8
	icmpHeader    = 8
	maxExtHeaders = 8
)

// Parse errors.
var (
	ErrTruncated = errors.New("packet: truncated")
	ErrVersion   = errors.New("packet: unknown IP version")
	ErrHeader    = errors.New("packet: malformed header")
)

// Packet is a parsed IP packet. Payload aliases the input buffer.
type Packet struct {
	Version  uint8 // 4 or 6
	Protocol uint8 // upper-layer protocol (after IPv6 extension headers)
	Src, Dst netip.Addr
	// SrcPort and DstPort are the TCP/UDP ports. For ICMP/ICMPv6 echo request and reply both
	// hold the echo identifier, so a reply's FlowKey is the Reverse of the request's.
	// Zero when unknown (non-first fragment, other protocols).
	SrcPort, DstPort uint16
	TCPFlags         uint8  // FlagFIN|FlagSYN|...; TCP only
	Seq, Ack         uint32 // TCP only
	ICMPType         uint8  // ICMP/ICMPv6 only
	ICMPCode         uint8
	TTL              uint8 // IPv4 TTL or IPv6 hop limit
	IPHeaderLen      int   // IPv4 header incl. options, or IPv6 header incl. extension headers
	TransportLen     int   // transport header length; 0 when not parsed
	TotalLen         int   // IP total length (bytes of b that belong to the packet)
	// IsFragment is set for any fragment. FragmentOffset is in bytes; for a non-first
	// fragment (FragmentOffset > 0) the transport header is absent and ports are unknown.
	IsFragment     bool
	FragmentOffset int
	Payload        []byte // transport payload, or the bytes after the IP headers if not parsed
}

// SYN reports whether the TCP SYN flag is set.
func (p *Packet) SYN() bool { return p.TCPFlags&FlagSYN != 0 }

// ACK reports whether the TCP ACK flag is set.
func (p *Packet) ACK() bool { return p.TCPFlags&FlagACK != 0 }

// FIN reports whether the TCP FIN flag is set.
func (p *Packet) FIN() bool { return p.TCPFlags&FlagFIN != 0 }

// RST reports whether the TCP RST flag is set.
func (p *Packet) RST() bool { return p.TCPFlags&FlagRST != 0 }

// HasPorts reports whether SrcPort/DstPort are meaningful.
func (p *Packet) HasPorts() bool {
	return p.TransportLen > 0 && (p.Protocol == ProtoTCP || p.Protocol == ProtoUDP || isEcho(p.Version, p.ICMPType))
}

// Parse decodes b into p. b must hold exactly one IP packet starting at the IP header;
// trailing bytes beyond the IP total length are ignored. p is fully overwritten.
func Parse(b []byte, p *Packet) error {
	*p = Packet{}
	if len(b) < 1 {
		return ErrTruncated
	}
	var next uint8
	var rest []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < ipv4MinHeader {
			return ErrTruncated
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < ipv4MinHeader || total < ihl {
			return ErrHeader
		}
		if len(b) < total {
			return ErrTruncated
		}
		b = b[:total]
		frag := binary.BigEndian.Uint16(b[6:8])
		p.Version = 4
		p.TTL = b[8]
		next = b[9]
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.FragmentOffset = int(frag&0x1fff) * 8
		p.IsFragment = frag&0x2000 != 0 || p.FragmentOffset != 0
		p.IPHeaderLen = ihl
		p.TotalLen = total
		rest = b[ihl:]
	case 6:
		if len(b) < ipv6Header {
			return ErrTruncated
		}
		total := ipv6Header + int(binary.BigEndian.Uint16(b[4:6]))
		if len(b) < total {
			return ErrTruncated
		}
		b = b[:total]
		p.Version = 6
		p.TTL = b[7]
		next = b[6]
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		p.TotalLen = total
		off := ipv6Header
	ext:
		for range maxExtHeaders {
			switch next {
			case ipv6HopByHop, ipv6Routing, ipv6DestOpts:
				if len(b) < off+8 {
					return ErrTruncated
				}
				n := (int(b[off+1]) + 1) * 8
				if len(b) < off+n {
					return ErrTruncated
				}
				next = b[off]
				off += n
			case ipv6Fragment:
				if len(b) < off+8 {
					return ErrTruncated
				}
				fo := binary.BigEndian.Uint16(b[off+2 : off+4])
				p.IsFragment = true
				p.FragmentOffset = int(fo>>3) * 8
				next = b[off]
				off += 8
			default:
				break ext
			}
		}
		switch next {
		case ipv6HopByHop, ipv6Routing, ipv6DestOpts, ipv6Fragment:
			return ErrHeader // too many extension headers
		}
		p.IPHeaderLen = off
		rest = b[off:]
	default:
		return ErrVersion
	}
	p.Protocol = next
	p.Payload = rest
	if p.FragmentOffset > 0 {
		return nil // non-first fragment: no transport header
	}
	switch next {
	case ProtoTCP:
		if len(rest) < tcpMinHeader {
			return ErrTruncated
		}
		doff := int(rest[12]>>4) * 4
		if doff < tcpMinHeader {
			return ErrHeader
		}
		if len(rest) < doff {
			return ErrTruncated
		}
		p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
		p.DstPort = binary.BigEndian.Uint16(rest[2:4])
		p.Seq = binary.BigEndian.Uint32(rest[4:8])
		p.Ack = binary.BigEndian.Uint32(rest[8:12])
		p.TCPFlags = rest[13]
		p.TransportLen = doff
		p.Payload = rest[doff:]
	case ProtoUDP:
		if len(rest) < udpHeader {
			return ErrTruncated
		}
		p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
		p.DstPort = binary.BigEndian.Uint16(rest[2:4])
		p.TransportLen = udpHeader
		p.Payload = rest[udpHeader:]
	case ProtoICMP, ProtoICMPv6:
		if (next == ProtoICMP) != (p.Version == 4) {
			return nil // ICMP over the wrong IP version: leave unparsed
		}
		if len(rest) < icmpHeader {
			return ErrTruncated
		}
		p.ICMPType = rest[0]
		p.ICMPCode = rest[1]
		if isEcho(p.Version, p.ICMPType) {
			id := binary.BigEndian.Uint16(rest[4:6])
			p.SrcPort, p.DstPort = id, id
		}
		p.TransportLen = icmpHeader
		p.Payload = rest[icmpHeader:]
	}
	return nil
}

func isEcho(version, typ uint8) bool {
	if version == 4 {
		return typ == 8 || typ == 0
	}
	return typ == 128 || typ == 129
}

// isICMPError reports whether an ICMP message of this type is an error message.
func isICMPError(version, typ uint8) bool {
	if version == 4 {
		switch typ {
		case 3, 4, 5, 11, 12:
			return true
		}
		return false
	}
	return typ < 128
}

// FlowKey identifies a flow by protocol, addresses and ports. It is comparable and can be
// used as a map key.
type FlowKey struct {
	Proto            uint8
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
}

// FlowKey returns the key of p's flow.
func (p *Packet) FlowKey() FlowKey {
	return FlowKey{Proto: p.Protocol, Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort}
}

// Reverse returns the key of the opposite direction of the flow.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{Proto: k.Proto, Src: k.Dst, Dst: k.Src, SrcPort: k.DstPort, DstPort: k.SrcPort}
}
