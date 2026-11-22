// Package geneve implements parsing and serialisation of the Generic Network
// Virtualization Encapsulation (GENEVE) protocol header according to RFC 8926.
package geneve

import (
	"encoding/binary"
	"errors"
)

// Port is the standard GENEVE UDP port (RFC 8926).
const Port = 6081

// Protocol types (Ethertypes) encapsulated by GENEVE.
const (
	ProtoIPv4 uint16 = 0x0800
	ProtoIPv6 uint16 = 0x86DD
)

// Header layout bounds per RFC 8926.
const (
	maxOptionDataLen = 124
	maxHeaderLen     = 260
	baseHeaderLen    = 8
)

// Parse and serialisation errors.
var (
	ErrShortInput          = errors.New("geneve: short input")
	ErrVersion             = errors.New("geneve: unsupported version")
	ErrHeaderTooLong       = errors.New("geneve: total header exceeds 260 bytes")
	ErrOptionsOverrun      = errors.New("geneve: options overrun")
	ErrOptionDataOverrun   = errors.New("geneve: option data overrun")
	ErrInvalidOptionLength = errors.New("geneve: invalid option length")
	ErrInvalidVNI          = errors.New("geneve: VNI exceeds 24 bits")
	ErrCriticalBit         = errors.New("geneve: critical option without critical flag in header")
)

// Option represents a variable-length TLV option in a GENEVE header.
// Data length must be a multiple of 4, at most 124 bytes.
type Option struct {
	Class uint16
	Type  uint8
	Data  []byte
}

// Header represents a GENEVE header.
type Header struct {
	VNI      uint32 // 24-bit Virtual Network Identifier
	Protocol uint16 // Ethertype of the inner payload
	Options  []Option
	OAM      bool
	Critical bool
}

// Parse parses a GENEVE packet from b. It validates version 0, ensures the option
// length fits in b and every option fits inside the options area, ignores the VNI's
// reserved byte, and returns the inner payload slice without copying.
//
// Refuses: short input, version != 0, options overrunning, option data overrunning,
// total header over 260 bytes. Never panics on any input.
func Parse(b []byte) (Header, []byte, error) {
	if len(b) < baseHeaderLen {
		return Header{}, nil, ErrShortInput
	}
	ver := b[0] >> 6
	if ver != 0 {
		return Header{}, nil, ErrVersion
	}
	optLenWords := int(b[0] & 0x3F)
	optLenBytes := optLenWords * 4
	totalHdr := baseHeaderLen + optLenBytes
	if totalHdr > maxHeaderLen {
		return Header{}, nil, ErrHeaderTooLong
	}
	if len(b) < totalHdr {
		return Header{}, nil, ErrShortInput
	}

	h := Header{
		OAM:      b[1]&0x80 != 0,
		Critical: b[1]&0x40 != 0,
		Protocol: binary.BigEndian.Uint16(b[2:4]),
		VNI:      uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]),
	}

	optArea := b[baseHeaderLen:totalHdr]
	off := 0
	hasCrit := false
	for off < len(optArea) {
		if len(optArea)-off < 4 {
			return Header{}, nil, ErrOptionsOverrun
		}
		class := binary.BigEndian.Uint16(optArea[off : off+2])
		typ := optArea[off+2]
		optDataLen := int(optArea[off+3]&0x1F) * 4
		if len(optArea)-off < 4+optDataLen {
			return Header{}, nil, ErrOptionDataOverrun
		}
		if typ&0x80 != 0 {
			hasCrit = true
		}
		h.Options = append(h.Options, Option{
			Class: class,
			Type:  typ,
			Data:  optArea[off+4 : off+4+optDataLen],
		})
		off += 4 + optDataLen
	}

	if hasCrit && !h.Critical {
		return Header{}, nil, ErrCriticalBit
	}

	return h, b[totalHdr:], nil
}

// AppendTo serialises the Header and options, setting the critical bit if any option has
// the critical bit 0x80 in Type, followed by payload into dst. It errors on invalid option lengths.
func (h Header) AppendTo(dst []byte, payload []byte) ([]byte, error) {
	if h.VNI > 0xFFFFFF {
		return nil, ErrInvalidVNI
	}
	totalOptLen := 0
	hasCrit := false
	for _, opt := range h.Options {
		if len(opt.Data)%4 != 0 || len(opt.Data) > maxOptionDataLen {
			return nil, ErrInvalidOptionLength
		}
		if opt.Type&0x80 != 0 {
			hasCrit = true
		}
		totalOptLen += 4 + len(opt.Data)
	}
	if baseHeaderLen+totalOptLen > maxHeaderLen {
		return nil, ErrHeaderTooLong
	}

	totalHdr := baseHeaderLen + totalOptLen
	hdr := make([]byte, totalHdr)

	// Byte 0: Ver (0), Opt Len in 4-byte words
	hdr[0] = uint8(totalOptLen/4) & 0x3F

	// Byte 1: OAM, Critical, Reserved (0)
	if h.OAM {
		hdr[1] |= 0x80
	}
	if h.Critical || hasCrit {
		hdr[1] |= 0x40
	}

	// Bytes 2-3: Protocol
	binary.BigEndian.PutUint16(hdr[2:4], h.Protocol)

	// Bytes 4-6: VNI (24 bits)
	hdr[4] = byte(h.VNI >> 16)
	hdr[5] = byte(h.VNI >> 8)
	hdr[6] = byte(h.VNI)

	// Byte 7: Reserved (0)

	// Variable length options
	off := baseHeaderLen
	for _, opt := range h.Options {
		binary.BigEndian.PutUint16(hdr[off:off+2], opt.Class)
		hdr[off+2] = opt.Type
		hdr[off+3] = uint8(len(opt.Data) / 4) // Reserved bits 5-7 are 0
		copy(hdr[off+4:], opt.Data)
		off += 4 + len(opt.Data)
	}

	dst = append(dst, hdr...)
	dst = append(dst, payload...)
	return dst, nil
}
