package dnsfilter

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	udpHeaderLen  = 8
	protoUDP      = 17
)

// buildUDPPacket returns a complete IPv4 or IPv6 packet carrying payload from src to dst,
// with valid IP (v4) and UDP checksums.
func buildUDPPacket(src, dst netip.AddrPort, payload []byte) ([]byte, error) {
	sa, da := src.Addr().Unmap(), dst.Addr().Unmap()
	if sa.Is4() != da.Is4() {
		return nil, errors.New("dnsfilter: address family mismatch")
	}
	udpLen := udpHeaderLen + len(payload)
	if udpLen > 0xffff {
		return nil, errors.New("dnsfilter: payload too large")
	}
	var pkt []byte
	var udp []byte
	if sa.Is4() {
		total := ipv4HeaderLen + udpLen
		if total > 0xffff {
			return nil, errors.New("dnsfilter: payload too large")
		}
		pkt = make([]byte, total)
		ip := pkt[:ipv4HeaderLen]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(total))
		ip[6] = 0x40 // DF
		ip[8] = 64   // TTL
		ip[9] = protoUDP
		s4, d4 := sa.As4(), da.As4()
		copy(ip[12:16], s4[:])
		copy(ip[16:20], d4[:])
		binary.BigEndian.PutUint16(ip[10:], ^foldChecksum(sum(ip, 0)))
		udp = pkt[ipv4HeaderLen:]
	} else {
		pkt = make([]byte, ipv6HeaderLen+udpLen)
		ip := pkt[:ipv6HeaderLen]
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(udpLen))
		ip[6] = protoUDP
		ip[7] = 64 // hop limit
		s16, d16 := sa.As16(), da.As16()
		copy(ip[8:24], s16[:])
		copy(ip[24:40], d16[:])
		udp = pkt[ipv6HeaderLen:]
	}
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[udpHeaderLen:], payload)

	// Pseudo-header checksum.
	var acc uint32
	sb, db := sa.AsSlice(), da.AsSlice()
	acc = sum(sb, acc)
	acc = sum(db, acc)
	acc += protoUDP
	acc += uint32(udpLen)
	acc = sum(udp, acc)
	cs := ^foldChecksum(acc)
	if cs == 0 {
		cs = 0xffff // RFC 768: transmitted as all ones
	}
	binary.BigEndian.PutUint16(udp[6:], cs)
	return pkt, nil
}

// sum adds b to the one's-complement accumulator acc (16-bit big-endian words).
func sum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

func foldChecksum(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return uint16(acc)
}
