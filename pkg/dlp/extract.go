package dlp

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"path"
	"regexp"
	"strings"
)

// Text extraction (ADR-0021). Detectors run on text, but uploads and downloads are often
// containers: ZIP archives, Office Open XML documents (which are ZIP files of XML), PDF files
// with compressed streams, gzip. Extract turns content into the text blobs to scan, within
// fixed bounds so that a small hostile file cannot make the Edge expand gigabytes.

// Extraction bounds.
const (
	MaxExtract      = 32 << 20 // total bytes produced from one input
	maxDepth        = 3        // containers inside containers
	maxZipEntries   = 1000
	maxPDFStreams   = 2000
	maxPDFStreamOut = 4 << 20
)

// Extraction is the text to scan and whether all of the content could be read.
type Extraction struct {
	Blobs    [][]byte
	Complete bool // false: a bound was hit, or a container was damaged or encrypted
}

// Extract returns the blobs to scan for b: b itself, or for a container (ZIP, gzip, PDF) the
// content extracted from it, so that nothing is counted twice.
func Extract(b []byte) Extraction {
	x := &extractor{budget: MaxExtract, ex: Extraction{Complete: true}}
	x.add(b, 0)
	return x.ex
}

// Decode undoes a Content-Encoding (gzip, x-gzip, deflate) within MaxExtract. ok is false
// for an unsupported encoding (br, zstd) or damaged or oversized data.
func Decode(encoding string, b []byte) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return b, true
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false
		}
		return readBounded(r, MaxExtract)
	case "deflate":
		// HTTP "deflate" is zlib-wrapped; some servers send raw deflate.
		if r, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			if out, ok := readBounded(r, MaxExtract); ok {
				return out, true
			}
		}
		return readBounded(flate.NewReader(bytes.NewReader(b)), MaxExtract)
	}
	return nil, false
}

func readBounded(r io.Reader, limit int) ([]byte, bool) {
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil || len(out) > limit {
		return nil, false
	}
	return out, true
}

type extractor struct {
	budget int
	ex     Extraction
}

// take reserves n bytes of the output budget.
func (x *extractor) take(n int) bool {
	if n > x.budget {
		x.ex.Complete = false
		return false
	}
	x.budget -= n
	return true
}

func (x *extractor) add(b []byte, depth int) {
	if !isContainer(b) && !looksXML(b) {
		x.ex.Blobs = append(x.ex.Blobs, b)
	}
	if depth >= maxDepth {
		if isContainer(b) {
			x.ex.Complete = false
			x.ex.Blobs = append(x.ex.Blobs, b) // scanned as it is
		}
		return
	}
	switch {
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		x.zip(b, depth)
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			x.ex.Complete = false
			return
		}
		out, ok := readBounded(r, x.budget)
		if !ok || !x.take(len(out)) {
			x.ex.Complete = false
			return
		}
		x.add(out, depth+1)
	case bytes.HasPrefix(b, []byte("%PDF-")):
		x.pdf(b)
	case looksXML(b):
		if t := xmlText(b); x.take(len(t)) {
			x.ex.Blobs = append(x.ex.Blobs, t)
		}
	}
}

func isContainer(b []byte) bool {
	return bytes.HasPrefix(b, []byte("PK\x03\x04")) || bytes.HasPrefix(b, []byte{0x1f, 0x8b}) || bytes.HasPrefix(b, []byte("%PDF-"))
}

func (x *extractor) zip(b []byte, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		x.ex.Complete = false
		return
	}
	if len(zr.File) > maxZipEntries {
		x.ex.Complete = false
	}
	for i, f := range zr.File {
		if i >= maxZipEntries {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Flags&0x1 != 0 { // encrypted entry
			x.ex.Complete = false
			continue
		}
		if f.UncompressedSize64 > uint64(x.budget) {
			x.ex.Complete = false
			continue
		}
		rc, err := f.Open()
		if err != nil {
			x.ex.Complete = false
			continue
		}
		// The declared size can lie: the read is bounded by the budget too.
		out, ok := readBounded(rc, x.budget)
		_ = rc.Close()
		if !ok || !x.take(len(out)) {
			x.ex.Complete = false
			continue
		}
		if strings.EqualFold(path.Ext(f.Name), ".xml") || strings.EqualFold(path.Ext(f.Name), ".rels") {
			// Office Open XML parts: only their text is worth scanning.
			if t := xmlText(out); len(t) > 0 {
				x.ex.Blobs = append(x.ex.Blobs, t)
			}
			continue
		}
		x.add(out, depth+1)
	}
}

func looksXML(b []byte) bool {
	t := bytes.TrimLeft(b, " \t\r\n\xef\xbb\xbf")
	return bytes.HasPrefix(t, []byte("<?xml"))
}

var (
	tagRe   = regexp.MustCompile(`<[^>]*>`)
	spaceRe = regexp.MustCompile(`\s+`)
)

// xmlText replaces tags with spaces (so that adjacent cells do not glue together), decodes
// the common entities and collapses whitespace.
func xmlText(b []byte) []byte {
	t := tagRe.ReplaceAll(b, []byte(" "))
	t = bytes.NewBufferString(strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(string(t))).Bytes()
	return bytes.TrimSpace(spaceRe.ReplaceAll(t, []byte(" ")))
}

var streamRe = regexp.MustCompile(`stream\r?\n`)

// pdf inflates the FlateDecode streams and extracts the literal strings of text operators.
// It is best effort: fonts with custom encodings (CID fonts) show glyph IDs, not text.
func (x *extractor) pdf(b []byte) {
	var text bytes.Buffer
	rest := b
	for n := 0; n < maxPDFStreams; n++ {
		loc := streamRe.FindIndex(rest)
		if loc == nil {
			break
		}
		body := rest[loc[1]:]
		end := bytes.Index(body, []byte("endstream"))
		if end < 0 {
			break
		}
		text.Write(pdfStrings(rest[:loc[0]])) // objects between streams
		text.WriteByte(' ')
		data := body[:end]
		rest = body[end+len("endstream"):]
		out := data // an unfiltered stream
		if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			inflated, err := io.ReadAll(io.LimitReader(r, maxPDFStreamOut+1))
			switch {
			case len(inflated) > maxPDFStreamOut:
				x.ex.Complete = false
				continue
			case err == nil || len(inflated) > 0:
				out = inflated
			}
		}
		s := pdfStrings(out)
		if !x.take(len(s)) {
			return
		}
		text.Write(s)
		text.WriteByte(' ')
	}
	text.Write(pdfStrings(rest))
	if text.Len() > 0 {
		x.ex.Blobs = append(x.ex.Blobs, text.Bytes())
	}
}

// pdfStrings returns the literal strings "( … )" of a content stream. Strings inside one TJ
// array are joined without a separator (a positioned word), others with a space.
func pdfStrings(b []byte) []byte {
	var out bytes.Buffer
	inArray := false
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '[':
			inArray = true
		case ']':
			inArray = false
			out.WriteByte(' ')
		case '(':
			j, s := pdfLiteral(b, i+1)
			out.Write(s)
			if !inArray {
				out.WriteByte(' ')
			}
			i = j
		}
	}
	return out.Bytes()
}

// pdfLiteral reads a literal string starting after its "(" and returns the index of the
// closing ")" and the decoded bytes.
func pdfLiteral(b []byte, i int) (int, []byte) {
	var s []byte
	depth := 1
	for ; i < len(b); i++ {
		c := b[i]
		switch c {
		case '\\':
			if i+1 >= len(b) {
				return i, s
			}
			i++
			switch e := b[i]; e {
			case 'n':
				s = append(s, '\n')
			case 'r':
				s = append(s, '\r')
			case 't':
				s = append(s, '\t')
			case '(', ')', '\\':
				s = append(s, e)
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for k := 0; k < 2 && i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '7'; k++ {
						i++
						v = v*8 + int(b[i]-'0')
					}
					s = append(s, byte(v))
				}
			}
		case '(':
			depth++
			s = append(s, c)
		case ')':
			depth--
			if depth == 0 {
				return i, s
			}
			s = append(s, c)
		default:
			s = append(s, c)
		}
	}
	return i, s
}
