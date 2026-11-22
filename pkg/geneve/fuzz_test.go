package geneve

import (
	"bytes"
	"testing"
)

func FuzzParse(f *testing.F) {
	// Seed corpus with valid and edge-case inputs.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte{0x00, 0x80, 0x08, 0x00, 0x12, 0x34, 0x56, 0x00, 't', 'e', 's', 't'})

	// 1 option (non-critical)
	f.Add([]byte{
		0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x42, 0x00,
		0x01, 0x00, 0x01, 0x00,
	})

	// 1 option with 4 bytes data
	f.Add([]byte{
		0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x42, 0x00,
		0x01, 0x00, 0x01, 0x01,
		0xaa, 0xbb, 0xcc, 0xdd,
		'p', 'a', 'y', 'l', 'o', 'a', 'd',
	})

	// 1 critical option with Critical bit set
	f.Add([]byte{
		0x01, 0x40, 0x08, 0x00, 0x00, 0x00, 0x42, 0x00,
		0x01, 0x00, 0x80, 0x00,
	})

	// 3 options
	f.Add([]byte{
		0x04, 0x40, 0x08, 0x00, 0x00, 0x00, 0x42, 0x00,
		0x01, 0x00, 0x81, 0x00, // 4 bytes
		0x02, 0x00, 0x02, 0x01, // 4 bytes + 4 bytes data = 8 bytes
		0x11, 0x22, 0x33, 0x44,
		0x03, 0x00, 0x03, 0x00, // 4 bytes
	})

	f.Fuzz(func(t *testing.T, b []byte) {
		h, payload, err := Parse(b)
		if err != nil {
			return
		}

		optLenWords := int(b[0] & 0x3F)
		hdrLen := baseHeaderLen + optLenWords*4

		if !bytes.Equal(payload, b[hdrLen:]) {
			t.Fatalf("payload mismatch: got %x, want %x", payload, b[hdrLen:])
		}

		out, err := h.AppendTo(nil, payload)
		if err != nil {
			t.Fatalf("AppendTo failed on accepted Parse input: %v", err)
		}
		if len(out) != len(b) {
			t.Fatalf("reconstructed length %d != original length %d", len(out), len(b))
		}

		// Byte 0: Ver (bits 6-7) and Opt Len (bits 0-5)
		if out[0] != b[0] {
			t.Fatalf("byte 0 mismatch: got 0x%02x, want 0x%02x", out[0], b[0])
		}

		// Byte 1: OAM (bit 7) and Critical (bit 6) must match; bits 0-5 are reserved.
		if (out[1] & 0xC0) != (b[1] & 0xC0) {
			t.Fatalf("byte 1 flags mismatch: got 0x%02x, want 0x%02x", out[1]&0xC0, b[1]&0xC0)
		}

		// Bytes 2-3: Protocol
		if !bytes.Equal(out[2:4], b[2:4]) {
			t.Fatalf("protocol mismatch: got %x, want %x", out[2:4], b[2:4])
		}

		// Bytes 4-6: VNI (24 bits)
		if !bytes.Equal(out[4:7], b[4:7]) {
			t.Fatalf("VNI mismatch: got %x, want %x", out[4:7], b[4:7])
		}

		// Byte 7 is reserved: ignored on receipt, zeroed on transmit.

		// Variable length options
		off := baseHeaderLen
		for i, opt := range h.Options {
			// Class (2 bytes)
			if !bytes.Equal(out[off:off+2], b[off:off+2]) {
				t.Fatalf("option %d class mismatch", i)
			}
			// Type (1 byte)
			if out[off+2] != b[off+2] {
				t.Fatalf("option %d type mismatch", i)
			}
			// Length in 4-byte words (bits 0-4 of byte 3). Bits 5-7 are reserved.
			if (out[off+3] & 0x1F) != (b[off+3] & 0x1F) {
				t.Fatalf("option %d length mismatch", i)
			}
			// Option data
			optDataLen := len(opt.Data)
			if !bytes.Equal(out[off+4:off+4+optDataLen], b[off+4:off+4+optDataLen]) {
				t.Fatalf("option %d data mismatch", i)
			}
			off += 4 + optDataLen
		}
	})
}
