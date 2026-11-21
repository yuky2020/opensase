package dlp

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(b)
	_ = w.Close()
	return out.Bytes()
}

// pdfWith builds a minimal PDF whose page content (FlateDecode) draws content.
func pdfWith(content string) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	_, _ = w.Write([]byte(content))
	_ = w.Close()
	return []byte(fmt.Sprintf("%%PDF-1.7\n4 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream\nendobj\n%%%%EOF\n", z.Len(), z.Bytes()))
}

func cards(t *testing.T, b []byte) (int, bool) {
	t.Helper()
	m, _ := Compile([]string{CreditCard}, nil)
	ex := Extract(b)
	n := 0
	for _, blob := range ex.Blobs {
		n += m.Counts(blob)[CreditCard]
	}
	return n, ex.Complete
}

func TestExtract(t *testing.T) {
	// A Word document whose card number is split across two runs.
	docx := zipOf(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte(`<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>Card 4111 11</w:t></w:r><w:r><w:t>11 1111 1111</w:t></w:r></w:p></w:body></w:document>`),
	})
	// A spreadsheet with the number in a cell next to another cell.
	xlsx := zipOf(t, map[string][]byte{
		"xl/worksheets/sheet1.xml": []byte(`<?xml version="1.0"?><worksheet><sheetData><row><c><v>1</v></c><c><v>5555555555554444</v></c></row></sheetData></worksheet>`),
	})
	nested := zipOf(t, map[string][]byte{"inner.zip": zipOf(t, map[string][]byte{"a.txt": []byte("pan 4111111111111111")})})
	for name, tc := range map[string]struct {
		in       []byte
		want     int
		complete bool
	}{
		"plain":       {[]byte("4111111111111111"), 1, true},
		"docx":        {docx, 1, true},
		"xlsx":        {xlsx, 1, true},
		"nested zip":  {nested, 1, true},
		"gzip":        {gz([]byte("x 4111111111111111 y")), 1, true},
		"zip in gzip": {gz(nested), 1, true},
		"pdf Tj":      {pdfWith("BT /F1 12 Tf (Card 4111 1111 1111 1111) Tj ET"), 1, true},
		"pdf TJ":      {pdfWith("BT [(4111)-20(1111)-20(1111)-20(1111)] TJ ET"), 1, true},
		"pdf escapes": {pdfWith(`BT (\(card\) \064111111111111111) Tj ET`), 1, true},
		"damaged zip": {[]byte("PK\x03\x04garbage"), 0, false},
	} {
		n, complete := cards(t, tc.in)
		if n != tc.want || complete != tc.complete {
			t.Errorf("%s: %d cards complete=%v, want %d %v", name, n, complete, tc.want, tc.complete)
		}
	}
}

func TestExtractBounds(t *testing.T) {
	// A zip bomb: one entry expanding past the budget.
	bomb := zipOf(t, map[string][]byte{"zeros.txt": make([]byte, MaxExtract+1)})
	if len(bomb) > 1<<20 {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	if ex := Extract(bomb); ex.Complete {
		t.Error("zip bomb reported complete")
	}
	// Containers nested deeper than maxDepth.
	deep := []byte("4111111111111111")
	for range maxDepth + 1 {
		deep = gz(deep)
	}
	if ex := Extract(deep); ex.Complete {
		t.Error("over-deep nesting reported complete")
	}
	// gzip of a gzip bomb.
	if ex := Extract(gz(make([]byte, MaxExtract+1))); ex.Complete {
		t.Error("gzip bomb reported complete")
	}
}

func TestDecode(t *testing.T) {
	if out, ok := Decode("gzip", gz([]byte("hi"))); !ok || string(out) != "hi" {
		t.Fatalf("gzip: %q %v", out, ok)
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	_, _ = w.Write([]byte("hi"))
	_ = w.Close()
	if out, ok := Decode("deflate", z.Bytes()); !ok || string(out) != "hi" {
		t.Fatalf("deflate: %q %v", out, ok)
	}
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	_, _ = bw.Write([]byte("hi"))
	_ = bw.Close()
	if out, ok := Decode("br", br.Bytes()); !ok || string(out) != "hi" {
		t.Fatalf("br: %q %v", out, ok)
	}
	zw, _ := zstd.NewWriter(nil)
	if out, ok := Decode("zstd", zw.EncodeAll([]byte("hi"), nil)); !ok || string(out) != "hi" {
		t.Fatalf("zstd: %q %v", out, ok)
	}
	// Decompression bombs stay bounded.
	bw2 := new(bytes.Buffer)
	bb := brotli.NewWriterLevel(bw2, 1)
	_, _ = bb.Write(make([]byte, MaxExtract+1))
	_ = bb.Close()
	if _, ok := Decode("br", bw2.Bytes()); ok {
		t.Fatal("brotli bomb decoded")
	}
	if _, ok := Decode("zstd", zw.EncodeAll(make([]byte, MaxExtract+1), nil)); ok {
		t.Fatal("zstd bomb decoded")
	}
	if _, ok := Decode("compress", []byte("x")); ok {
		t.Fatal("unknown encoding decoded")
	}
	if _, ok := Decode("gzip", gz(make([]byte, MaxExtract+1))); ok {
		t.Fatal("oversized gzip decoded")
	}
}

func FuzzExtract(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add(pdfWith("BT (x) Tj ET"))
	f.Add(gz([]byte("hello")))
	f.Fuzz(func(_ *testing.T, b []byte) { _ = Extract(b) })
}
