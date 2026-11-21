package dlp

import (
	"bytes"
	"compress/zlib"
	"image"
	"image/png"
	"io"
	"regexp"
	"strconv"
	"unicode/utf16"
)

// PDF text and images (ADR-0021, ADR-0026). The extractor indexes the objects of the file,
// including those packed in object streams, decodes FlateDecode streams (with PNG
// predictors), maps the text of fonts that have a ToUnicode CMap (CID fonts, issue #13), and
// hands image XObjects to OCR (issue #12). Everything is bounded: a hostile PDF can only make
// the extraction incomplete.

const (
	maxPDFObjects   = 100_000
	maxCMapEntries  = 1 << 16
	maxImagePixels  = 25_000_000
	maxPDFImageSide = 20_000
)

var (
	objRe       = regexp.MustCompile(`(\d{1,10})\s+(\d{1,5})\s+obj\b`)
	refRe       = regexp.MustCompile(`(\d{1,10})\s+\d{1,5}\s+R\b`)
	streamKwRe  = regexp.MustCompile(`stream\r?\n`)
	fontDictRe  = regexp.MustCompile(`/Font\s*(<<(?:[^<>]|<<[^<>]*>>)*>>|\d+\s+\d+\s+R)`)
	fontEntryRe = regexp.MustCompile(`/([^\s/<>\[\]()]+)\s+(\d{1,10})\s+\d{1,5}\s+R`)
)

type pdfObj struct {
	dict      []byte
	stream    []byte // raw (still encoded)
	hasStream bool
}

type pdfFile struct {
	objs     map[int]*pdfObj
	complete bool
}

func parsePDFObjects(b []byte) *pdfFile {
	f := &pdfFile{objs: map[int]*pdfObj{}, complete: true}
	locs := objRe.FindAllSubmatchIndex(b, maxPDFObjects+1)
	if len(locs) > maxPDFObjects {
		f.complete = false
		locs = locs[:maxPDFObjects]
	}
	for i, m := range locs {
		num, _ := strconv.Atoi(string(b[m[2]:m[3]]))
		end := len(b)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		body := b[m[1]:end]
		if e := bytes.LastIndex(body, []byte("endobj")); e >= 0 {
			body = body[:e]
		}
		o := &pdfObj{dict: body}
		if s := streamKwRe.FindIndex(body); s != nil {
			o.dict = body[:s[0]]
			data := body[s[1]:]
			if e := bytes.LastIndex(data, []byte("endstream")); e >= 0 {
				data = data[:e]
			}
			o.stream, o.hasStream = bytes.TrimRight(data, "\r\n"), true
		}
		f.objs[num] = o
	}
	// Objects packed in object streams (PDF 1.5+): "N First", then N pairs of numbers.
	for _, o := range f.objs {
		if !o.hasStream || !bytes.Contains(o.dict, []byte("/ObjStm")) {
			continue
		}
		data, ok := f.decode(o)
		if !ok {
			f.complete = false
			continue
		}
		n, first := dictInt(o.dict, "/N"), dictInt(o.dict, "/First")
		if n <= 0 || first <= 0 || first > len(data) || n > maxPDFObjects {
			f.complete = false
			continue
		}
		nums := bytes.Fields(data[:first])
		for k := 0; k+1 < len(nums) && k/2 < n; k += 2 {
			num, err1 := strconv.Atoi(string(nums[k]))
			off, err2 := strconv.Atoi(string(nums[k+1]))
			if err1 != nil || err2 != nil || first+off > len(data) || off < 0 {
				f.complete = false
				break
			}
			end := len(data)
			if k+3 < len(nums) {
				if next, err := strconv.Atoi(string(nums[k+3])); err == nil && first+next <= len(data) && next >= off {
					end = first + next
				}
			}
			if _, dup := f.objs[num]; !dup && len(f.objs) < maxPDFObjects {
				f.objs[num] = &pdfObj{dict: data[first+off : end]}
			}
		}
	}
	return f
}

var intRe = regexp.MustCompile(`^\s*(-?\d{1,10})`)

// dictInt reads the integer value of key in a dictionary, or 0.
func dictInt(dict []byte, key string) int {
	i := bytes.Index(dict, []byte(key))
	if i < 0 {
		return 0
	}
	rest := dict[i+len(key):]
	if len(rest) > 0 && (rest[0] >= 'A' && rest[0] <= 'Z' || rest[0] >= 'a' && rest[0] <= 'z') {
		return dictInt(rest, key) // a longer key with the same prefix
	}
	m := intRe.FindSubmatch(rest)
	if m == nil {
		return 0
	}
	v, _ := strconv.Atoi(string(m[1]))
	return v
}

// decode returns the decoded stream of o: FlateDecode (with PNG predictors) or unfiltered.
// Other filters are not decoded (ok false), except that DCTDecode data is returned as is
// by image handling.
func (f *pdfFile) decode(o *pdfObj) ([]byte, bool) {
	switch {
	case bytes.Contains(o.dict, []byte("/FlateDecode")) || bytes.Contains(o.dict, []byte("/Fl ")):
		r, err := zlib.NewReader(bytes.NewReader(o.stream))
		if err != nil {
			return nil, false
		}
		out, err := io.ReadAll(io.LimitReader(r, maxPDFStreamOut+1))
		if len(out) > maxPDFStreamOut || (err != nil && len(out) == 0) {
			return nil, false
		}
		if p := dictInt(o.dict, "/Predictor"); p >= 10 {
			cols := max(dictInt(o.dict, "/Columns"), 1)
			colors := max(dictInt(o.dict, "/Colors"), 1)
			bpc := max(dictInt(o.dict, "/BitsPerComponent"), 8)
			if out, err = unpredictPNG(out, colors, bpc, cols); err != nil {
				return nil, false
			}
		}
		return out, true
	case bytes.Contains(o.dict, []byte("/Filter")):
		return nil, false
	default:
		return o.stream, true
	}
}

// unpredictPNG undoes PNG row predictors (PDF /Predictor >= 10).
func unpredictPNG(b []byte, colors, bpc, cols int) ([]byte, error) {
	bpp := max(colors*bpc/8, 1)
	row := (colors*bpc*cols + 7) / 8
	if row <= 0 || row > 1<<20 {
		return nil, errOLE
	}
	var out []byte
	prev := make([]byte, row)
	for len(b) > row {
		ft, line := b[0], b[1:row+1]
		b = b[row+1:]
		cur := make([]byte, row)
		for i := range line {
			var left, up, ul byte
			if i >= bpp {
				left, ul = cur[i-bpp], prev[i-bpp]
			}
			up = prev[i]
			switch ft {
			case 0:
				cur[i] = line[i]
			case 1:
				cur[i] = line[i] + left
			case 2:
				cur[i] = line[i] + up
			case 3:
				cur[i] = line[i] + byte((int(left)+int(up))/2)
			case 4:
				cur[i] = line[i] + paeth(left, up, ul)
			default:
				return nil, errOLE
			}
		}
		out = append(out, cur...)
		prev = cur
		if len(out) > maxPDFStreamOut {
			return nil, errOLE
		}
	}
	return out, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	}
	return c
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// --- fonts and CMaps ---

// cmap maps character codes of one code length to text.
type cmap struct {
	codeLen int
	m       map[uint32]string
}

func (f *pdfFile) fonts() map[string]*cmap {
	out := map[string]*cmap{}
	for _, o := range f.objs {
		for _, m := range fontDictRe.FindAllSubmatch(o.dict, -1) {
			dict := m[1]
			if r := refRe.FindSubmatch(dict); r != nil && !bytes.HasPrefix(dict, []byte("<<")) {
				num, _ := strconv.Atoi(string(r[1]))
				if ro := f.objs[num]; ro != nil {
					dict = ro.dict
				}
			}
			for _, e := range fontEntryRe.FindAllSubmatch(dict, -1) {
				name := string(e[1])
				if _, seen := out[name]; seen {
					continue
				}
				num, _ := strconv.Atoi(string(e[2]))
				if cm := f.toUnicode(num); cm != nil {
					out[name] = cm
				}
			}
		}
	}
	return out
}

func (f *pdfFile) toUnicode(fontObj int) *cmap {
	fo := f.objs[fontObj]
	if fo == nil {
		return nil
	}
	i := bytes.Index(fo.dict, []byte("/ToUnicode"))
	if i < 0 {
		return nil
	}
	r := refRe.FindSubmatch(fo.dict[i:])
	if r == nil {
		return nil
	}
	num, _ := strconv.Atoi(string(r[1]))
	co := f.objs[num]
	if co == nil || !co.hasStream {
		return nil
	}
	data, ok := f.decode(co)
	if !ok {
		return nil
	}
	return parseCMap(data)
}

var (
	codespaceRe = regexp.MustCompile(`begincodespacerange\s*<([0-9A-Fa-f]+)>`)
	bfcharRe    = regexp.MustCompile(`(?s)beginbfchar(.*?)endbfchar`)
	bfrangeRe   = regexp.MustCompile(`(?s)beginbfrange(.*?)endbfrange`)
	hexTokRe    = regexp.MustCompile(`<([0-9A-Fa-f]*)>|\[|\]`)
)

func hexBytes(s []byte) []byte {
	if len(s)%2 == 1 {
		s = append(append([]byte(nil), s...), '0')
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, _ := strconv.ParseUint(string(s[2*i:2*i+2]), 16, 8)
		out[i] = byte(v)
	}
	return out
}

func beUint(b []byte) uint32 {
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return v
}

// utf16BE decodes a ToUnicode destination.
func utf16BE(b []byte) string {
	if len(b)%2 == 1 {
		return string(b)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return string(utf16.Decode(u))
}

func parseCMap(data []byte) *cmap {
	cm := &cmap{codeLen: 2, m: map[uint32]string{}}
	if m := codespaceRe.FindSubmatch(data); m != nil {
		cm.codeLen = max(1, min(4, (len(m[1])+1)/2))
	}
	for _, blk := range bfcharRe.FindAllSubmatch(data, -1) {
		toks := hexTokRe.FindAllSubmatch(blk[1], -1)
		for i := 0; i+1 < len(toks) && len(cm.m) < maxCMapEntries; i += 2 {
			cm.m[beUint(hexBytes(toks[i][1]))] = utf16BE(hexBytes(toks[i+1][1]))
		}
	}
	for _, blk := range bfrangeRe.FindAllSubmatch(data, -1) {
		toks := hexTokRe.FindAllSubmatch(blk[1], -1)
		for i := 0; i+2 < len(toks) && len(cm.m) < maxCMapEntries; {
			lo, hi := beUint(hexBytes(toks[i][1])), beUint(hexBytes(toks[i+1][1]))
			if hi < lo || hi-lo > maxCMapEntries {
				return cm
			}
			if string(toks[i+2][0]) == "[" { // an array of destinations
				j := i + 3
				for c := lo; j < len(toks) && string(toks[j][0]) != "]"; j++ {
					if c <= hi && len(cm.m) < maxCMapEntries {
						cm.m[c] = utf16BE(hexBytes(toks[j][1]))
					}
					c++
				}
				i = j + 1
				continue
			}
			dst := hexBytes(toks[i+2][1])
			for c := lo; c <= hi && len(cm.m) < maxCMapEntries; c++ {
				d := append([]byte(nil), dst...)
				if len(d) > 0 {
					d[len(d)-1] += byte(c - lo)
				}
				cm.m[c] = utf16BE(d)
			}
			i += 3
		}
	}
	return cm
}

func (cm *cmap) text(b []byte) string {
	var out []byte
	for i := 0; i+cm.codeLen <= len(b); i += cm.codeLen {
		if s, ok := cm.m[beUint(b[i:i+cm.codeLen])]; ok {
			out = append(out, s...)
		}
	}
	return string(out)
}

// --- content streams ---

// contentText interprets the text operators of a content stream: Tf selects a font, and
// Tj, TJ, ' and " show strings, decoded with the font's CMap when it has one.
func contentText(b []byte, fonts map[string]*cmap) []byte {
	var out bytes.Buffer
	var font *cmap
	var lastName string
	var strs [][]byte // strings since the last operator
	inArray := false
	show := func(sep bool) {
		for _, s := range strs {
			if font != nil {
				out.WriteString(font.text(s))
			} else {
				out.Write(s)
			}
		}
		if sep || len(strs) > 0 {
			out.WriteByte(' ')
		}
		strs = strs[:0]
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '%':
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
		case c == '/':
			j := i + 1
			for j < len(b) && !isPDFDelim(b[j]) {
				j++
			}
			lastName = string(b[i+1 : j])
			i = j - 1
		case c == '(':
			j, s := pdfLiteral(b, i+1)
			strs = append(strs, s)
			i = j
		case c == '<' && i+1 < len(b) && b[i+1] == '<':
			i++
		case c == '<':
			j := bytes.IndexByte(b[i:], '>')
			if j < 0 {
				return out.Bytes()
			}
			hex := bytes.Map(func(r rune) rune {
				if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
					return r
				}
				return -1
			}, b[i+1:i+j])
			strs = append(strs, hexBytes(hex))
			i += j
		case c == '[':
			inArray = true
		case c == ']':
			inArray = false
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '\'' || c == '"':
			j := i
			for j < len(b) && (b[j] >= 'A' && b[j] <= 'Z' || b[j] >= 'a' && b[j] <= 'z' || b[j] == '*' || b[j] == '\'' || b[j] == '"') {
				j++
			}
			switch string(b[i:j]) {
			case "Tf":
				font = fonts[lastName]
				strs = strs[:0]
			case "Tj", "TJ", "'", "\"":
				show(true)
			case "BT", "ET", "Td", "TD", "T*", "Tm":
				if !inArray {
					strs = strs[:0]
				}
			default:
				strs = strs[:0]
			}
			i = j - 1
		}
	}
	return out.Bytes()
}

func isPDFDelim(c byte) bool {
	return c <= ' ' || bytes.IndexByte([]byte("()<>[]{}/%"), c) >= 0
}

// --- images ---

// pdfImage returns an image XObject as data OCR can read: JPEG as stored, or 8-bit gray or
// RGB pixels re-encoded as PNG. ok is false for formats it cannot hand over.
func (f *pdfFile) pdfImage(o *pdfObj) ([]byte, bool) {
	if bytes.Contains(o.dict, []byte("/DCTDecode")) || bytes.Contains(o.dict, []byte("/DCT ")) {
		return o.stream, true
	}
	w, h, bpc := dictInt(o.dict, "/Width"), dictInt(o.dict, "/Height"), dictInt(o.dict, "/BitsPerComponent")
	if w <= 0 || h <= 0 || w > maxPDFImageSide || h > maxPDFImageSide || w*h > maxImagePixels || bpc != 8 {
		return nil, false
	}
	data, ok := f.decode(o)
	if !ok {
		return nil, false
	}
	var img image.Image
	switch {
	case bytes.Contains(o.dict, []byte("/DeviceGray")) && len(data) >= w*h:
		g := image.NewGray(image.Rect(0, 0, w, h))
		copy(g.Pix, data[:w*h])
		img = g
	case bytes.Contains(o.dict, []byte("/DeviceRGB")) && len(data) >= 3*w*h:
		rgba := image.NewRGBA(image.Rect(0, 0, w, h))
		for p := 0; p < w*h; p++ {
			copy(rgba.Pix[4*p:4*p+3], data[3*p:3*p+3])
			rgba.Pix[4*p+3] = 0xFF
		}
		img = rgba
	default:
		return nil, false
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// pdfDoc extracts the text of a PDF and sends its images to OCR.
func (x *extractor) pdfDoc(b []byte) bool {
	f := parsePDFObjects(b)
	if len(f.objs) == 0 {
		return false // not parseable as objects: the stream scan handles it
	}
	if !f.complete {
		x.ex.Complete = false
	}
	fonts := f.fonts()
	var text bytes.Buffer
	for _, o := range f.objs {
		isImage := bytes.Contains(o.dict, []byte("/Subtype")) && bytes.Contains(o.dict, []byte("/Image"))
		switch {
		case isImage && o.hasStream:
			if x.opt.OCR == nil {
				continue
			}
			img, ok := f.pdfImage(o)
			if !ok {
				x.ex.Complete = false
				continue
			}
			x.ocr(img)
		case o.hasStream:
			if bytes.Contains(o.dict, []byte("/ObjStm")) || bytes.Contains(o.dict, []byte("/XRef")) {
				continue
			}
			data, ok := f.decode(o)
			if !ok {
				continue // fonts, other filters: no text of their own
			}
			text.Write(contentText(data, fonts))
		default:
			// Strings in object dictionaries (form fields, annotations, metadata).
			text.Write(pdfStrings(o.dict))
		}
		if text.Len() > x.budget {
			x.ex.Complete = false
			break
		}
	}
	if t := text.Bytes(); len(t) > 0 && x.take(len(t)) {
		x.ex.Blobs = append(x.ex.Blobs, t)
	}
	return true
}
