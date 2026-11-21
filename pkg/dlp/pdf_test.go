package dlp

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"strings"
	"testing"
)

func zflate(s []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write(s)
	_ = w.Close()
	return b.Bytes()
}

// cidHex encodes text with the test CID font: digits are codes 0x0010-0x0019, space 0x0003.
func cidHex(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			fmt.Fprintf(&b, "%04X", 0x10+int(r-'0'))
		case r == ' ':
			b.WriteString("0003")
		}
	}
	return b.String()
}

const testCMap = `/CIDInit /ProcSet findresource begin 12 dict begin begincmap
1 begincodespacerange <0000> <FFFF> endcodespacerange
1 beginbfchar <0003> <0020> endbfchar
1 beginbfrange <0010> <0019> <0030> endbfrange
endcmap CMapName currentdict /CMap defineresource pop end end`

type pdfBuilder struct{ b bytes.Buffer }

func (p *pdfBuilder) obj(num int, dict string, stream []byte) {
	fmt.Fprintf(&p.b, "%d 0 obj\n%s", num, dict)
	if stream != nil {
		fmt.Fprintf(&p.b, "\nstream\n%s\nendstream", stream)
	}
	p.b.WriteString("\nendobj\n")
}

func newPDF() *pdfBuilder {
	p := &pdfBuilder{}
	p.b.WriteString("%PDF-1.7\n")
	return p
}

func cidPDF(objStm bool) []byte {
	p := newPDF()
	page := "<< /Type /Page /Resources << /Font << /F1 2 0 R >> >> /Contents 4 0 R >>"
	font := "<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding /Identity-H /ToUnicode 3 0 R >>"
	if objStm {
		// Objects 1 and 2 packed in object stream 5 (compressed, as modern writers do).
		body := page + "\n" + font
		header := fmt.Sprintf("1 0 2 %d ", len(page)+1)
		data := []byte(header + body)
		p.obj(5, fmt.Sprintf("<< /Type /ObjStm /N 2 /First %d /Filter /FlateDecode /Length %d >>", len(header), len(zflate(data))), zflate(data))
	} else {
		p.obj(1, page, nil)
		p.obj(2, font, nil)
	}
	cm := zflate([]byte(testCMap))
	p.obj(3, fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(cm)), cm)
	content := zflate([]byte("BT /F1 12 Tf 72 720 Td <" + cidHex("4111 1111 1111 1111") + "> Tj ET"))
	p.obj(4, fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(content)), content)
	p.b.WriteString("%%EOF\n")
	return p.b.Bytes()
}

func countCardsIn(t *testing.T, ex Extraction) int {
	t.Helper()
	m, _ := Compile([]string{CreditCard}, nil)
	n := 0
	for _, b := range ex.Blobs {
		n += m.Counts(b)[CreditCard]
	}
	return n
}

// TestPDFCIDFonts covers issue #13: text drawn with a Type0 font is mapped through its
// ToUnicode CMap, also when the font dictionary sits in a compressed object stream.
func TestPDFCIDFonts(t *testing.T) {
	for _, objStm := range []bool{false, true} {
		ex := Extract(cidPDF(objStm))
		if n := countCardsIn(t, ex); n != 1 {
			t.Errorf("objStm=%v: %d cards", objStm, n)
		}
	}
	// The glyph codes alone (without the CMap) do not read as the number.
	raw := []byte("%PDF-1.7\n4 0 obj\n<< /Length 9 >>\nstream\nBT /F1 12 Tf <" + cidHex("4111 1111 1111 1111") + "> Tj ET\nendstream\nendobj\n")
	if n := countCardsIn(t, Extract(raw)); n != 0 {
		t.Errorf("unmapped CID codes counted as text: %d", n)
	}
}

// TestPDFImages covers issue #12: image XObjects go to OCR, JPEG as stored and Flate pixels
// as PNG; without OCR they carry no text; OCR errors make the extraction incomplete.
func TestPDFImages(t *testing.T) {
	var jp bytes.Buffer
	_ = jpeg.Encode(&jp, image.NewGray(image.Rect(0, 0, 8, 8)), nil)
	p := newPDF()
	p.obj(1, fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode /Length %d >>", jp.Len()), jp.Bytes())
	pix := zflate(bytes.Repeat([]byte{0xFF}, 4*2))
	p.obj(2, fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width 4 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>", len(pix)), pix)
	doc := p.b.Bytes()

	var kinds []string
	ocr := func(img []byte) ([]byte, error) {
		switch {
		case bytes.HasPrefix(img, []byte{0xFF, 0xD8}):
			kinds = append(kinds, "jpeg")
		case bytes.HasPrefix(img, []byte{0x89, 'P', 'N', 'G'}):
			kinds = append(kinds, "png")
		default:
			kinds = append(kinds, "other")
		}
		return []byte("scan: 4111 1111 1111 1111"), nil
	}
	ex := ExtractWith(doc, Options{OCR: ocr})
	if n := countCardsIn(t, ex); n != 2 || !ex.Complete || strings.Join(kinds, ",") == "" {
		t.Fatalf("cards %d complete %v kinds %v", n, ex.Complete, kinds)
	}
	if !strings.Contains(strings.Join(kinds, ","), "jpeg") || !strings.Contains(strings.Join(kinds, ","), "png") {
		t.Fatalf("kinds %v", kinds)
	}
	if n := countCardsIn(t, Extract(doc)); n != 0 {
		t.Fatalf("images read without OCR: %d", n)
	}
	failing := func([]byte) ([]byte, error) { return nil, errors.New("down") }
	if ex := ExtractWith(doc, Options{OCR: failing}); ex.Complete {
		t.Fatal("OCR failure reported complete")
	}
	// An image too large to hand over is incomplete, not decoded.
	big := newPDF()
	big.obj(1, "<< /Subtype /Image /Width 100000 /Height 100000 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length 1 >>", []byte{0})
	if ex := ExtractWith(big.b.Bytes(), Options{OCR: ocr}); ex.Complete {
		t.Fatal("oversized image reported complete")
	}
}

func TestUnpredictPNG(t *testing.T) {
	// Two rows of 3 bytes: "Up" filter on the second row.
	in := []byte{0, 1, 2, 3, 2, 1, 1, 1}
	out, err := unpredictPNG(in, 1, 8, 3)
	if err != nil || !bytes.Equal(out, []byte{1, 2, 3, 2, 3, 4}) {
		t.Fatalf("%v %v", out, err)
	}
	if _, err := unpredictPNG([]byte{9, 1, 2, 3}, 1, 8, 3); err == nil {
		t.Fatal("bad filter type accepted")
	}
}

func FuzzPDF(f *testing.F) {
	f.Add(cidPDF(false))
	f.Add(cidPDF(true))
	f.Fuzz(func(_ *testing.T, b []byte) {
		if !bytes.HasPrefix(b, []byte("%PDF-")) {
			b = append([]byte("%PDF-"), b...)
		}
		_ = ExtractWith(b, Options{OCR: func([]byte) ([]byte, error) { return nil, nil }})
	})
}

// TestWritePDFFixtures writes card-cid.pdf and card-scan.pdf into OPENSASE_WRITE_FIXTURES:
// the test card number drawn with a CID font (font in an object stream), and as a scanned
// page (the card.png fixture as a JPEG image XObject).
func TestWritePDFFixtures(t *testing.T) {
	dir := os.Getenv("OPENSASE_WRITE_FIXTURES")
	if dir == "" {
		t.Skip("set OPENSASE_WRITE_FIXTURES to the fixtures directory")
	}
	if err := os.WriteFile(dir+"/card-cid.pdf", cidPDF(true), 0o644); err != nil { //nolint:gosec // G306: test fixture
		t.Fatal(err)
	}
	f, err := os.Open(dir + "/card.png")
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	var jp bytes.Buffer
	_ = jpeg.Encode(&jp, img, &jpeg.Options{Quality: 95})
	b := img.Bounds()
	p := newPDF()
	p.obj(1, "<< /Type /Page /Resources << /XObject << /Im1 2 0 R >> >> /Contents 3 0 R >>", nil)
	p.obj(2, fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode /Length %d >>", b.Dx(), b.Dy(), jp.Len()), jp.Bytes())
	p.obj(3, "<< /Length 31 >>", []byte(fmt.Sprintf("q %d 0 0 %d 0 0 cm /Im1 Do Q", b.Dx(), b.Dy())))
	p.b.WriteString("%%EOF\n")
	if err := os.WriteFile(dir+"/card-scan.pdf", p.b.Bytes(), 0o644); err != nil { //nolint:gosec // G306: test fixture
		t.Fatal(err)
	}
}
