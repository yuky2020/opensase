package geneve

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		payload []byte
	}{
		{
			name: "0 options, standard IPv4",
			header: Header{
				VNI:      100,
				Protocol: ProtoIPv4,
				OAM:      false,
				Critical: false,
			},
			payload: []byte("inner ipv4 packet test payload"),
		},
		{
			name: "1 option without critical flag",
			header: Header{
				VNI:      200000,
				Protocol: ProtoIPv4,
				OAM:      true,
				Critical: false,
				Options: []Option{
					{
						Class: 0x0102,
						Type:  0x03,
						Data:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
					},
				},
			},
			payload: []byte("payload with 1 option"),
		},
		{
			name: "3 options including critical option",
			header: Header{
				VNI:      0xFEDCBA,
				Protocol: ProtoIPv6,
				OAM:      false,
				Critical: true,
				Options: []Option{
					{
						Class: 0x0100,
						Type:  0x81, // critical
						Data:  []byte{0x10, 0x20, 0x30, 0x40},
					},
					{
						Class: 0x0200,
						Type:  0x02,
						Data:  []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22},
					},
					{
						Class: 0x0300,
						Type:  0x03,
						Data:  []byte{},
					},
				},
			},
			payload: []byte("payload with 3 options"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tc.header.AppendTo(nil, tc.payload)
			if err != nil {
				t.Fatalf("AppendTo failed: %v", err)
			}
			parsed, payload, err := Parse(wire)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if parsed.VNI != tc.header.VNI {
				t.Errorf("VNI = %d, want %d", parsed.VNI, tc.header.VNI)
			}
			if parsed.Protocol != tc.header.Protocol {
				t.Errorf("Protocol = 0x%04x, want 0x%04x", parsed.Protocol, tc.header.Protocol)
			}
			if parsed.OAM != tc.header.OAM {
				t.Errorf("OAM = %v, want %v", parsed.OAM, tc.header.OAM)
			}
			if parsed.Critical != tc.header.Critical {
				t.Errorf("Critical = %v, want %v", parsed.Critical, tc.header.Critical)
			}
			if len(parsed.Options) != len(tc.header.Options) {
				t.Fatalf("Options count = %d, want %d", len(parsed.Options), len(tc.header.Options))
			}
			for i := range parsed.Options {
				if parsed.Options[i].Class != tc.header.Options[i].Class {
					t.Errorf("Option[%d].Class = 0x%04x, want 0x%04x", i, parsed.Options[i].Class, tc.header.Options[i].Class)
				}
				if parsed.Options[i].Type != tc.header.Options[i].Type {
					t.Errorf("Option[%d].Type = 0x%02x, want 0x%02x", i, parsed.Options[i].Type, tc.header.Options[i].Type)
				}
				if !slices.Equal(parsed.Options[i].Data, tc.header.Options[i].Data) {
					t.Errorf("Option[%d].Data = %x, want %x", i, parsed.Options[i].Data, tc.header.Options[i].Data)
				}
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Errorf("payload = %q, want %q", payload, tc.payload)
			}
		})
	}
}

func TestKnownByteVector(t *testing.T) {
	// Hand-built GENEVE packet:
	// Byte 0: Ver=0 (0x00), OptLen=2 words (8 bytes) -> 0x02
	// Byte 1: OAM=1 (0x80), Critical=1 (0x40), Rsvd=0 -> 0xC0
	// Bytes 2-3: Protocol = ProtoIPv4 (0x0800)
	// Bytes 4-6: VNI = 0x123456
	// Byte 7: Reserved = 0xFF (should be ignored by Parse)
	// Option 1 (8 bytes):
	//   Bytes 8-9: Class = 0x0102
	//   Byte 10: Type = 0x83 (critical bit set)
	//   Byte 11: Length = 1 word (4 bytes) -> 0x01
	//   Bytes 12-15: Data = 0xaa, 0xbb, 0xcc, 0xdd
	// Payload (12 bytes): "hello geneve"
	wire := []byte{
		0x02, 0xC0, 0x08, 0x00,
		0x12, 0x34, 0x56, 0xFF, // Byte 7 is 0xFF to verify reserved byte is ignored
		0x01, 0x02, 0x83, 0x01,
		0xaa, 0xbb, 0xcc, 0xdd,
		'h', 'e', 'l', 'l', 'o', ' ', 'g', 'e', 'n', 'e', 'v', 'e',
	}

	h, payload, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if h.VNI != 0x123456 {
		t.Errorf("VNI = 0x%x, want 0x123456", h.VNI)
	}
	if h.Protocol != ProtoIPv4 {
		t.Errorf("Protocol = 0x%04x, want 0x0800", h.Protocol)
	}
	if !h.OAM {
		t.Errorf("OAM = false, want true")
	}
	if !h.Critical {
		t.Errorf("Critical = false, want true")
	}
	if len(h.Options) != 1 {
		t.Fatalf("len(Options) = %d, want 1", len(h.Options))
	}
	opt := h.Options[0]
	if opt.Class != 0x0102 || opt.Type != 0x83 || !slices.Equal(opt.Data, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Errorf("unexpected option: %+v", opt)
	}
	if string(payload) != "hello geneve" {
		t.Errorf("payload = %q, want %q", payload, "hello geneve")
	}

	// Re-serialise and ensure wire format matches (with byte 7 normalized to 0).
	reconstructed, err := h.AppendTo(nil, payload)
	if err != nil {
		t.Fatalf("AppendTo failed: %v", err)
	}
	expectedWire := make([]byte, len(wire))
	copy(expectedWire, wire)
	expectedWire[7] = 0x00 // serialised reserved byte is 0
	if !bytes.Equal(reconstructed, expectedWire) {
		t.Errorf("reconstructed = %x, want %x", reconstructed, expectedWire)
	}
}

func TestParseRefusals(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{
			name:    "short input: empty",
			input:   []byte{},
			wantErr: ErrShortInput,
		},
		{
			name:    "short input: less than 8 bytes",
			input:   []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01},
			wantErr: ErrShortInput,
		},
		{
			name:    "short input: declared option length exceeds buffer",
			input:   []byte{0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02}, // needs 8 + 4 = 12 bytes
			wantErr: ErrShortInput,
		},
		{
			name:    "version != 0: version 1",
			input:   []byte{0x40, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantErr: ErrVersion,
		},
		{
			name:    "version != 0: version 2",
			input:   []byte{0x80, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantErr: ErrVersion,
		},
		{
			name:    "version != 0: version 3",
			input:   []byte{0xC0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantErr: ErrVersion,
		},
		{
			name: "options overrunning: options area truncated within option header",
			// OptLen = 2 words (8 bytes). First option is 4 bytes. 2 bytes remain (< 4 byte header).
			input: []byte{
				0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
				0x01, 0x02, 0x03, 0x00, // option 1: len 0
				0x01, 0x02, // only 2 bytes left of the 8 declared bytes
			},
			wantErr: ErrShortInput, // the declared header is longer than the input
		},
		{
			name: "option data overrunning: option data extends beyond options area",
			// OptLen = 2 words (8 bytes). Option declares length 2 words (8 bytes data) -> needs 12 bytes.
			input: []byte{
				0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
				0x01, 0x02, 0x03, 0x02, // Length = 2 words (8 bytes data)
				0x11, 0x22, 0x33, 0x44, // only 4 bytes of data provided in options area
			},
			wantErr: ErrOptionDataOverrun,
		},
		{
			name: "critical option without critical flag in header",
			// Header has Critical = 0 (byte 1 = 0x00), but option has Type = 0x80 (critical bit set).
			input: []byte{
				0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
				0x01, 0x02, 0x80, 0x00,
			},
			wantErr: ErrCriticalBit,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(tc.input)
			if err == nil {
				t.Fatalf("Parse succeeded, want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Parse err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAppendToRefusals(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		wantErr error
	}{
		{
			name: "VNI exceeds 24 bits",
			header: Header{
				VNI:      0x1000000,
				Protocol: ProtoIPv4,
			},
			wantErr: ErrInvalidVNI,
		},
		{
			name: "option data not multiple of 4",
			header: Header{
				VNI:      1,
				Protocol: ProtoIPv4,
				Options: []Option{
					{Class: 1, Type: 1, Data: []byte{1, 2, 3}},
				},
			},
			wantErr: ErrInvalidOptionLength,
		},
		{
			name: "option data exceeds 124 bytes",
			header: Header{
				VNI:      1,
				Protocol: ProtoIPv4,
				Options: []Option{
					{Class: 1, Type: 1, Data: make([]byte, 128)},
				},
			},
			wantErr: ErrInvalidOptionLength,
		},
		{
			name: "total header over 260 bytes",
			// 3 options of 100 bytes data each: 3 * (4 + 100) = 312 bytes options + 8 bytes header = 320 > 260.
			header: Header{
				VNI:      1,
				Protocol: ProtoIPv4,
				Options: []Option{
					{Class: 1, Type: 1, Data: make([]byte, 100)},
					{Class: 2, Type: 2, Data: make([]byte, 100)},
					{Class: 3, Type: 3, Data: make([]byte, 100)},
				},
			},
			wantErr: ErrHeaderTooLong,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.header.AppendTo(nil, []byte("payload"))
			if err == nil {
				t.Fatalf("AppendTo succeeded, want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("AppendTo err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
