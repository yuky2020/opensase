// Command geneve-probe sends a GENEVE-encapsulated DNS query to a Workload Gateway and
// checks the re-encapsulated answer (issue #21, e2e harness).
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/yuky2020/opensase/pkg/geneve"
	"github.com/yuky2020/opensase/pkg/packet"
)

var defaultOption = geneve.Option{
	Class: 0x0103,
	Type:  0x01,
	Data:  []byte{0xde, 0xad, 0xbe, 0xef},
}

func main() {
	gateway := flag.String("gateway", "10.30.0.2:6081", "gateway host:port")
	srcStr := flag.String("src", "10.30.0.99", "inner source IPv4")
	dstStr := flag.String("dst", "100.64.0.1", "inner destination IPv4")
	name := flag.String("name", "example.com", "DNS query name")
	vni := flag.Uint("vni", 4242, "GENEVE VNI")
	timeout := flag.Duration("timeout", 10*time.Second, "probe timeout")
	flag.Parse()

	srcIP, err := netip.ParseAddr(*srcStr)
	if err != nil || !srcIP.Is4() {
		fmt.Fprintf(os.Stderr, "geneve-probe: invalid -src IPv4 %q: %v\n", *srcStr, err)
		os.Exit(1)
	}
	dstIP, err := netip.ParseAddr(*dstStr)
	if err != nil || !dstIP.Is4() {
		fmt.Fprintf(os.Stderr, "geneve-probe: invalid -dst IPv4 %q: %v\n", *dstStr, err)
		os.Exit(1)
	}
	if *vni > 0xFFFFFF {
		fmt.Fprintf(os.Stderr, "geneve-probe: invalid -vni %d (exceeds 24 bits)\n", *vni)
		os.Exit(1)
	}

	answers, err := runProbe(*gateway, srcIP, dstIP, *name, uint32(*vni), *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "geneve-probe: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("geneve-probe: ok %d answers\n", answers)
}

func runProbe(gateway string, srcIP, dstIP netip.Addr, name string, vni uint32, timeout time.Duration) (int, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return 0, fmt.Errorf("generate DNS ID: %w", err)
	}
	dnsID := binary.BigEndian.Uint16(idBytes[:])

	dnsPayload, err := buildDNSQuery(name, dnsID)
	if err != nil {
		return 0, fmt.Errorf("build DNS query: %w", err)
	}

	var portBytes [2]byte
	if _, err := rand.Read(portBytes[:]); err != nil {
		return 0, fmt.Errorf("generate src port: %w", err)
	}
	srcPort := uint16(1024 + binary.BigEndian.Uint16(portBytes[:])%60000)

	innerPkt, err := buildIPv4UDPPacket(srcIP, dstIP, srcPort, 53, dnsPayload)
	if err != nil {
		return 0, fmt.Errorf("build inner IPv4/UDP packet: %w", err)
	}

	encap, err := buildGenevePacket(vni, defaultOption, innerPkt)
	if err != nil {
		return 0, fmt.Errorf("build GENEVE packet: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", gateway)
	if err != nil {
		return 0, fmt.Errorf("resolve gateway %s: %w", gateway, err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, fmt.Errorf("listen UDP: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.WriteToUDP(encap, udpAddr); err != nil {
		return 0, fmt.Errorf("send GENEVE packet: %w", err)
	}

	buf := make([]byte, 65535)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return 0, fmt.Errorf("read reply: %w", err)
	}

	return checkReply(buf[:n], vni, defaultOption, dstIP, srcIP)
}

func buildDNSQuery(name string, id uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, errors.New("empty domain name")
	}
	labels := strings.Split(name, ".")
	var qname []byte
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return nil, fmt.Errorf("invalid label %q in domain name", l)
		}
		qname = append(qname, byte(len(l)))
		qname = append(qname, l...)
	}
	qname = append(qname, 0)

	msg := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD = 1
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT = 1
	copy(msg[12:], qname)
	off := 12 + len(qname)
	binary.BigEndian.PutUint16(msg[off:off+2], 1)   // QTYPE = 1 (A)
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1) // QCLASS = 1 (IN)
	return msg, nil
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildIPv4UDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	if !srcIP.Is4() || !dstIP.Is4() {
		return nil, errors.New("IPv4 addresses required")
	}
	totalLen := 20 + 8 + len(payload)
	if totalLen > 65535 {
		return nil, errors.New("packet exceeds maximum IPv4 length")
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64                                  // TTL
	pkt[9] = 17                                  // Protocol: UDP
	src4 := srcIP.As4()
	dst4 := dstIP.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	udp[6] = 0
	udp[7] = 0 // Checksum optional in IPv4 UDP
	copy(udp[8:], payload)

	return pkt, nil
}

func buildGenevePacket(vni uint32, opt geneve.Option, inner []byte) ([]byte, error) {
	gh := geneve.Header{
		VNI:      vni,
		Protocol: geneve.ProtoIPv4,
		Options:  []geneve.Option{opt},
	}
	return gh.AppendTo(nil, inner)
}

func checkReply(reply []byte, wantVNI uint32, wantOption geneve.Option, wantSrc, wantDst netip.Addr) (int, error) {
	gh, inner, err := geneve.Parse(reply)
	if err != nil {
		return 0, fmt.Errorf("GENEVE parse error: %w", err)
	}
	if gh.VNI != wantVNI {
		return 0, fmt.Errorf("GENEVE VNI mismatch: got %d, want %d", gh.VNI, wantVNI)
	}
	if gh.Protocol != geneve.ProtoIPv4 {
		return 0, fmt.Errorf("GENEVE protocol mismatch: got 0x%04x, want 0x0800", gh.Protocol)
	}
	if len(gh.Options) != 1 {
		return 0, fmt.Errorf("GENEVE options count: got %d, want 1", len(gh.Options))
	}
	opt := gh.Options[0]
	if opt.Class != wantOption.Class || opt.Type != wantOption.Type || !bytes.Equal(opt.Data, wantOption.Data) {
		return 0, fmt.Errorf("GENEVE option mismatch: got class=0x%04x type=0x%02x data=%x, want class=0x%04x type=0x%02x data=%x",
			opt.Class, opt.Type, opt.Data, wantOption.Class, wantOption.Type, wantOption.Data)
	}

	var pkt packet.Packet
	if err := packet.Parse(inner, &pkt); err != nil {
		return 0, fmt.Errorf("inner IPv4 parse error: %w", err)
	}
	if pkt.Version != 4 {
		return 0, fmt.Errorf("inner IP version: got %d, want 4", pkt.Version)
	}
	if pkt.Src != wantSrc {
		return 0, fmt.Errorf("inner IPv4 src: got %s, want %s", pkt.Src, wantSrc)
	}
	if pkt.Dst != wantDst {
		return 0, fmt.Errorf("inner IPv4 dst: got %s, want %s", pkt.Dst, wantDst)
	}
	if pkt.Protocol != packet.ProtoUDP {
		return 0, fmt.Errorf("inner protocol: got %d, want UDP (17)", pkt.Protocol)
	}
	if pkt.SrcPort != 53 {
		return 0, fmt.Errorf("inner UDP src port: got %d, want 53", pkt.SrcPort)
	}

	dnsPayload := pkt.Payload
	if len(dnsPayload) < 12 {
		return 0, fmt.Errorf("DNS response too short: %d bytes", len(dnsPayload))
	}
	flags := binary.BigEndian.Uint16(dnsPayload[2:4])
	if flags&0x8000 == 0 {
		return 0, errors.New("DNS message is not a response (QR bit not set)")
	}
	ancount := int(binary.BigEndian.Uint16(dnsPayload[6:8]))
	if ancount < 1 {
		return 0, fmt.Errorf("DNS response has no answers (ANCOUNT=%d)", ancount)
	}

	return ancount, nil
}
