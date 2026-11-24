package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/yuky2020/opensase/pkg/geneve"
)

func TestBuildDNSQuery(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		id         uint16
		wantErr    bool
		wantLabels []string
	}{
		{
			name:       "standard domain",
			domain:     "example.com",
			id:         0x1234,
			wantErr:    false,
			wantLabels: []string{"example", "com"},
		},
		{
			name:       "trailing dot",
			domain:     "example.com.",
			id:         0xabcd,
			wantErr:    false,
			wantLabels: []string{"example", "com"},
		},
		{
			name:       "multi-level domain",
			domain:     "sub.domain.example.com",
			id:         0x5678,
			wantErr:    false,
			wantLabels: []string{"sub", "domain", "example", "com"},
		},
		{
			name:    "empty name",
			domain:  "",
			id:      0x1111,
			wantErr: true,
		},
		{
			name:    "only dot",
			domain:  ".",
			id:      0x2222,
			wantErr: true,
		},
		{
			name:    "label too long",
			domain:  strings.Repeat("a", 64) + ".com",
			id:      0x3333,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := buildDNSQuery(tt.domain, tt.id)
			if (err != nil) != tt.wantErr {
				t.Fatalf("buildDNSQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(query) < 12+4 {
				t.Fatalf("query too short: %d bytes", len(query))
			}
			if gotID := binary.BigEndian.Uint16(query[0:2]); gotID != tt.id {
				t.Errorf("ID = 0x%04x, want 0x%04x", gotID, tt.id)
			}
			if gotFlags := binary.BigEndian.Uint16(query[2:4]); gotFlags != 0x0100 {
				t.Errorf("Flags = 0x%04x, want 0x0100", gotFlags)
			}
			if gotQDCount := binary.BigEndian.Uint16(query[4:6]); gotQDCount != 1 {
				t.Errorf("QDCOUNT = %d, want 1", gotQDCount)
			}

			// Validate QNAME labels
			off := 12
			for _, wantLabel := range tt.wantLabels {
				labelLen := int(query[off])
				if labelLen != len(wantLabel) {
					t.Fatalf("at offset %d: label len = %d, want %d (%s)", off, labelLen, len(wantLabel), wantLabel)
				}
				off++
				gotLabel := string(query[off : off+labelLen])
				if gotLabel != wantLabel {
					t.Errorf("label = %q, want %q", gotLabel, wantLabel)
				}
				off += labelLen
			}
			if query[off] != 0 {
				t.Errorf("QNAME terminator = %d, want 0", query[off])
			}
			off++

			qtype := binary.BigEndian.Uint16(query[off : off+2])
			if qtype != 1 {
				t.Errorf("QTYPE = %d, want 1 (A)", qtype)
			}
			qclass := binary.BigEndian.Uint16(query[off+2 : off+4])
			if qclass != 1 {
				t.Errorf("QCLASS = %d, want 1 (IN)", qclass)
			}
		})
	}
}

// buildHandmadePacket constructs a test packet simulating a gateway reply.
func buildHandmadePacket(vni uint32, opt geneve.Option, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, qr bool, ancount uint16) []byte {
	dnsPayload := make([]byte, 12)
	binary.BigEndian.PutUint16(dnsPayload[0:2], 0x1234)
	flags := uint16(0x0100) // RD
	if qr {
		flags |= 0x8000 // Response
	}
	binary.BigEndian.PutUint16(dnsPayload[2:4], flags)
	binary.BigEndian.PutUint16(dnsPayload[4:6], 1)       // QDCOUNT
	binary.BigEndian.PutUint16(dnsPayload[6:8], ancount) // ANCOUNT

	// Question: \x07example\x03com\x00 \x00\x01 \x00\x01
	qname := []byte("\x07example\x03com\x00\x00\x01\x00\x01")
	dnsPayload = append(dnsPayload, qname...)

	// Answers
	for i := uint16(0); i < ancount; i++ {
		// Answer: pointer to qname (0xc00c), type A (0x0001), class IN (0x0001), TTL (60s), rdlength 4, IP 93.184.215.14
		ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 215, 14}
		dnsPayload = append(dnsPayload, ans...)
	}

	inner, _ := buildIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, dnsPayload)
	pkt, _ := buildGenevePacket(vni, opt, inner)
	return pkt
}

func TestCheckReply(t *testing.T) {
	dstIP := netip.MustParseAddr("100.64.0.1")
	srcIP := netip.MustParseAddr("10.30.0.99")
	wantOpt := geneve.Option{Class: 0x0103, Type: 0x01, Data: []byte{0xde, 0xad, 0xbe, 0xef}}

	tests := []struct {
		name        string
		packet      []byte
		wantAnswers int
		wantErrSub  string
	}{
		{
			name:        "valid 1 answer",
			packet:      buildHandmadePacket(4242, wantOpt, dstIP, srcIP, 53, 54321, true, 1),
			wantAnswers: 1,
		},
		{
			name:        "valid 3 answers",
			packet:      buildHandmadePacket(4242, wantOpt, dstIP, srcIP, 53, 54321, true, 3),
			wantAnswers: 3,
		},
		{
			name:       "vni mismatch",
			packet:     buildHandmadePacket(9999, wantOpt, dstIP, srcIP, 53, 54321, true, 1),
			wantErrSub: "VNI mismatch",
		},
		{
			name: "option class mismatch",
			packet: buildHandmadePacket(4242, geneve.Option{
				Class: 0x0104,
				Type:  0x01,
				Data:  []byte{0xde, 0xad, 0xbe, 0xef},
			}, dstIP, srcIP, 53, 54321, true, 1),
			wantErrSub: "option mismatch",
		},
		{
			name: "option type mismatch",
			packet: buildHandmadePacket(4242, geneve.Option{
				Class: 0x0103,
				Type:  0x02,
				Data:  []byte{0xde, 0xad, 0xbe, 0xef},
			}, dstIP, srcIP, 53, 54321, true, 1),
			wantErrSub: "option mismatch",
		},
		{
			name: "option data mismatch",
			packet: buildHandmadePacket(4242, geneve.Option{
				Class: 0x0103,
				Type:  0x01,
				Data:  []byte{0x12, 0x34, 0x56, 0x78},
			}, dstIP, srcIP, 53, 54321, true, 1),
			wantErrSub: "option mismatch",
		},
		{
			name:       "inner src IP mismatch",
			packet:     buildHandmadePacket(4242, wantOpt, netip.MustParseAddr("100.64.0.2"), srcIP, 53, 54321, true, 1),
			wantErrSub: "inner IPv4 src",
		},
		{
			name:       "inner dst IP mismatch",
			packet:     buildHandmadePacket(4242, wantOpt, dstIP, netip.MustParseAddr("10.30.0.100"), 53, 54321, true, 1),
			wantErrSub: "inner IPv4 dst",
		},
		{
			name:       "inner UDP port not 53",
			packet:     buildHandmadePacket(4242, wantOpt, dstIP, srcIP, 54, 54321, true, 1),
			wantErrSub: "inner UDP src port",
		},
		{
			name:       "dns not a response",
			packet:     buildHandmadePacket(4242, wantOpt, dstIP, srcIP, 53, 54321, false, 1),
			wantErrSub: "QR bit not set",
		},
		{
			name:       "dns 0 answers",
			packet:     buildHandmadePacket(4242, wantOpt, dstIP, srcIP, 53, 54321, true, 0),
			wantErrSub: "no answers",
		},
		{
			name:       "truncated packet",
			packet:     []byte{0x00, 0x00, 0x08, 0x00},
			wantErrSub: "GENEVE parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answers, err := checkReply(tt.packet, 4242, wantOpt, dstIP, srcIP)
			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("checkReply() expected error containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("checkReply() error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkReply() unexpected error: %v", err)
			}
			if answers != tt.wantAnswers {
				t.Fatalf("checkReply() answers = %d, want %d", answers, tt.wantAnswers)
			}
		})
	}
}
