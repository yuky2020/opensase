package dlp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// Legacy Office documents (ADR-0024): .doc, .xls and .ppt are Compound File Binary (OLE2)
// containers. Their text sits in streams as 8-bit or UTF-16LE runs, so instead of
// interpreting each format the extractor reads every stream and keeps the runs of printable
// text in both encodings. That finds identifiers in Word, Excel and PowerPoint documents
// without a per-format parser.

var oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// OLE2 constants.
const (
	oleFreeSect   = 0xFFFFFFFF
	oleEndChain   = 0xFFFFFFFE
	oleMaxRegSect = 0xFFFFFFFA
	oleMaxSectors = 1 << 20
	oleMaxStreams = 4096
	minTextRun    = 4
)

var errOLE = errors.New("dlp: damaged OLE2 container")

type ole struct {
	b        []byte
	sectSize int
	fat      []uint32
}

func (o *ole) sector(n uint32) ([]byte, bool) {
	off := (int(n) + 1) * o.sectSize
	if n > oleMaxRegSect || off < 0 || off+o.sectSize > len(o.b) {
		return nil, false
	}
	return o.b[off : off+o.sectSize], true
}

// chain follows the FAT from start and concatenates up to limit bytes.
func (o *ole) chain(fat []uint32, start uint32, limit int, read func(uint32) ([]byte, bool)) ([]byte, error) {
	var out []byte
	seen := make(map[uint32]bool)
	for s := start; s != oleEndChain; {
		if s >= uint32(len(fat)) || seen[s] {
			return out, errOLE // out of range, or a loop
		}
		seen[s] = true
		sec, ok := read(s)
		if !ok {
			return out, errOLE
		}
		out = append(out, sec...)
		if len(out) >= limit {
			return out[:limit], nil
		}
		s = fat[s]
	}
	return out, nil
}

// oleStreams returns the contents of the streams of an OLE2 file, within budget bytes.
func oleStreams(b []byte, budget int) ([][]byte, bool, error) {
	if len(b) < 512 || !bytes.Equal(b[:8], oleMagic) {
		return nil, false, errOLE
	}
	le := binary.LittleEndian
	shift := le.Uint16(b[30:])
	miniShift := le.Uint16(b[32:])
	if shift != 9 && shift != 12 || miniShift != 6 {
		return nil, false, errOLE
	}
	o := &ole{b: b, sectSize: 1 << shift}
	numFAT := le.Uint32(b[44:])
	dirStart := le.Uint32(b[48:])
	cutoff := int(le.Uint32(b[56:]))
	miniFATStart := le.Uint32(b[60:])
	numMiniFAT := le.Uint32(b[64:])
	difatStart := le.Uint32(b[68:])
	numDIFAT := le.Uint32(b[72:])
	if numFAT > oleMaxSectors/128 || numMiniFAT > oleMaxSectors || numDIFAT > oleMaxSectors {
		return nil, false, errOLE
	}
	// The DIFAT: 109 entries in the header, then a chain of DIFAT sectors.
	var fatSects []uint32
	for i := 0; i < 109; i++ {
		if s := le.Uint32(b[76+4*i:]); s <= oleMaxRegSect {
			fatSects = append(fatSects, s)
		}
	}
	for s, n := difatStart, uint32(0); s <= oleMaxRegSect && n < numDIFAT; n++ {
		sec, ok := o.sector(s)
		if !ok {
			return nil, false, errOLE
		}
		per := o.sectSize/4 - 1
		for i := 0; i < per; i++ {
			if v := le.Uint32(sec[4*i:]); v <= oleMaxRegSect {
				fatSects = append(fatSects, v)
			}
		}
		s = le.Uint32(sec[4*per:])
	}
	if uint32(len(fatSects)) > numFAT {
		fatSects = fatSects[:numFAT]
	}
	for _, s := range fatSects {
		sec, ok := o.sector(s)
		if !ok {
			return nil, false, errOLE
		}
		for i := 0; i < o.sectSize/4; i++ {
			o.fat = append(o.fat, le.Uint32(sec[4*i:]))
		}
		if len(o.fat) > oleMaxSectors {
			return nil, false, errOLE
		}
	}
	dir, err := o.chain(o.fat, dirStart, oleMaxStreams*128, o.sector)
	if err != nil && len(dir) == 0 {
		return nil, false, err
	}
	complete := err == nil
	// Root entry (first directory entry): start and size of the mini stream.
	if len(dir) < 128 {
		return nil, false, errOLE
	}
	rootStart := le.Uint32(dir[116:])
	rootSize := int(le.Uint64(dir[120:]) & 0x7FFFFFFF)
	ministream, err := o.chain(o.fat, rootStart, min(rootSize, budget), o.sector)
	if err != nil {
		complete = false
	}
	var miniFAT []uint32
	if numMiniFAT > 0 {
		mf, err := o.chain(o.fat, miniFATStart, int(numMiniFAT)*o.sectSize, o.sector)
		if err != nil {
			complete = false
		}
		for i := 0; i+4 <= len(mf); i += 4 {
			miniFAT = append(miniFAT, le.Uint32(mf[i:]))
		}
	}
	miniSector := func(n uint32) ([]byte, bool) {
		off := int(n) * 64
		if off < 0 || off+64 > len(ministream) {
			return nil, false
		}
		return ministream[off : off+64], true
	}
	var out [][]byte
	for off := 0; off+128 <= len(dir); off += 128 {
		e := dir[off : off+128]
		if e[66] != 2 { // stream objects only
			continue
		}
		start := le.Uint32(e[116:])
		size := int(le.Uint64(e[120:]) & 0x7FFFFFFF)
		if size == 0 {
			continue
		}
		if size > budget {
			complete = false
			size = budget
		}
		var data []byte
		var err error
		if size < cutoff {
			data, err = o.chain(miniFAT, start, size, miniSector)
		} else {
			data, err = o.chain(o.fat, start, size, o.sector)
		}
		if err != nil {
			complete = false
		}
		budget -= len(data)
		out = append(out, data)
		if budget <= 0 {
			complete = false
			break
		}
	}
	return out, complete, nil
}

// textRuns keeps the runs of printable text of b, read as 8-bit text and as UTF-16LE (both
// alignments), separated by spaces.
func textRuns(b []byte) []byte {
	var out bytes.Buffer
	// 8-bit runs.
	start := -1
	for i := 0; i <= len(b); i++ {
		if i < len(b) && isTextByte(b[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minTextRun {
			out.Write(b[start:i])
			out.WriteByte(' ')
		}
		start = -1
	}
	// UTF-16LE runs, at both byte alignments.
	for align := 0; align < 2; align++ {
		var run []uint16
		flush := func() {
			if len(run) >= minTextRun {
				out.WriteString(string(utf16.Decode(run)))
				out.WriteByte(' ')
			}
			run = run[:0]
		}
		for i := align; i+1 < len(b); i += 2 {
			c := uint16(b[i]) | uint16(b[i+1])<<8
			if c >= 0x20 && c != 0x7F && (c < 0xD800 || c > 0xDFFF) && c != 0xFFFE && c != 0xFFFF {
				run = append(run, c)
				continue
			}
			flush()
		}
		flush()
	}
	return out.Bytes()
}

func isTextByte(c byte) bool { return c >= 0x20 && c < 0x7F || c == '\t' }

// rtfText strips RTF control words and groups, keeping the text.
func rtfText(b []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(b); i++ {
		switch c := b[i]; c {
		case '\\':
			if i+1 >= len(b) {
				break
			}
			n := b[i+1]
			switch {
			case n == '\\' || n == '{' || n == '}':
				out.WriteByte(n)
				i++
			case n == '\'' && i+3 < len(b): // \'hh
				var v byte
				for _, h := range b[i+2 : i+4] {
					v <<= 4
					switch {
					case h >= '0' && h <= '9':
						v |= h - '0'
					case h >= 'a' && h <= 'f':
						v |= h - 'a' + 10
					case h >= 'A' && h <= 'F':
						v |= h - 'A' + 10
					}
				}
				out.WriteByte(v)
				i += 3
			default:
				// A control word: letters, an optional number, an optional space.
				j := i + 1
				for j < len(b) && (b[j] >= 'a' && b[j] <= 'z' || b[j] >= 'A' && b[j] <= 'Z') {
					j++
				}
				word := string(b[i+1 : j])
				for j < len(b) && (b[j] == '-' || b[j] >= '0' && b[j] <= '9') {
					j++
				}
				if j < len(b) && b[j] == ' ' {
					j++
				}
				if word == "par" || word == "line" || word == "tab" || word == "cell" {
					out.WriteByte(' ')
				}
				i = j - 1
			}
		case '{', '}', '\r', '\n':
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}
