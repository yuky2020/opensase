package dlp

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

// oleFile builds a minimal version-3 Compound File with one regular stream (big, >= 4096
// bytes, in normal sectors) and one small stream (in the mini stream).
func oleFile(t *testing.T, big, small []byte) []byte {
	t.Helper()
	const ss = 512
	le := binary.LittleEndian
	if len(big) < 4096 || len(small) >= 4096 || len(small) > ss {
		t.Fatal("bad sizes")
	}
	bigSects := (len(big) + ss - 1) / ss
	miniSects := (len(small) + 63) / 64
	// Layout: 0 FAT, 1 directory, 2.. big stream, then mini stream container, then mini FAT.
	bigStart := uint32(2)
	miniCont := bigStart + uint32(bigSects)
	miniFATSect := miniCont + 1
	total := int(miniFATSect) + 1
	file := make([]byte, ss*(total+1))
	h := file[:ss]
	copy(h, oleMagic)
	le.PutUint16(h[24:], 0x3E)
	le.PutUint16(h[26:], 3)
	le.PutUint16(h[28:], 0xFFFE)
	le.PutUint16(h[30:], 9)
	le.PutUint16(h[32:], 6)
	le.PutUint32(h[44:], 1)           // FAT sectors
	le.PutUint32(h[48:], 1)           // directory start
	le.PutUint32(h[56:], 4096)        // mini stream cutoff
	le.PutUint32(h[60:], miniFATSect) // mini FAT start
	le.PutUint32(h[64:], 1)           // mini FAT sectors
	le.PutUint32(h[68:], oleEndChain) // no DIFAT sectors
	for i := 0; i < 109; i++ {
		le.PutUint32(h[76+4*i:], oleFreeSect)
	}
	le.PutUint32(h[76:], 0)
	sect := func(n int) []byte { return file[(n+1)*ss : (n+2)*ss] }
	fat := sect(0)
	for i := 0; i < ss/4; i++ {
		le.PutUint32(fat[4*i:], oleFreeSect)
	}
	le.PutUint32(fat[0:], 0xFFFFFFFD)  // FAT sector
	le.PutUint32(fat[4:], oleEndChain) // directory
	for i := 0; i < bigSects; i++ {
		next := uint32(oleEndChain)
		if i < bigSects-1 {
			next = bigStart + uint32(i) + 1
		}
		le.PutUint32(fat[4*(int(bigStart)+i):], next)
		copy(sect(int(bigStart)+i), big[i*ss:min(len(big), (i+1)*ss)])
	}
	le.PutUint32(fat[4*int(miniCont):], oleEndChain)
	le.PutUint32(fat[4*int(miniFATSect):], oleEndChain)
	copy(sect(int(miniCont)), small)
	mf := sect(int(miniFATSect))
	for i := 0; i < ss/4; i++ {
		le.PutUint32(mf[4*i:], oleFreeSect)
	}
	for i := 0; i < miniSects; i++ {
		next := uint32(oleEndChain)
		if i < miniSects-1 {
			next = uint32(i + 1)
		}
		le.PutUint32(mf[4*i:], next)
	}
	dir := sect(1)
	entry := func(i int, name string, typ byte, start uint32, size int) {
		e := dir[i*128 : (i+1)*128]
		u := utf16.Encode([]rune(name))
		for j, c := range u {
			le.PutUint16(e[2*j:], c)
		}
		le.PutUint16(e[64:], uint16(2*(len(u)+1)))
		e[66] = typ
		le.PutUint32(e[68:], 0xFFFFFFFF)
		le.PutUint32(e[72:], 0xFFFFFFFF)
		le.PutUint32(e[76:], 0xFFFFFFFF)
		le.PutUint32(e[116:], start)
		le.PutUint64(e[120:], uint64(size))
	}
	entry(0, "Root Entry", 5, miniCont, miniSects*64)
	entry(1, "WordDocument", 2, bigStart, len(big))
	entry(2, "SummaryInformation", 2, 0, len(small))
	return file
}

func utf16le(s string) []byte {
	var b bytes.Buffer
	for _, c := range utf16.Encode([]rune(s)) {
		_ = binary.Write(&b, binary.LittleEndian, c)
	}
	return b.Bytes()
}

func TestOLE2(t *testing.T) {
	// The regular stream holds a card number as UTF-16LE (as Word does), padded past 4096
	// bytes; the mini stream holds an IBAN as 8-bit text.
	big := append(utf16le("Pagamento con carta 4111 1111 1111 1111, grazie."), bytes.Repeat([]byte{0}, 5000)...)
	small := []byte("\x00\x01IBAN IT60X0542811101000000123456\x00")
	doc := oleFile(t, big, small)
	m, _ := Compile([]string{CreditCard, IBAN}, nil)
	ex := Extract(doc)
	if !ex.Complete {
		t.Fatal("incomplete")
	}
	got := map[string]int{}
	for _, b := range ex.Blobs {
		for k, v := range m.Counts(b) {
			got[k] += v
		}
	}
	if got[CreditCard] != 1 || got[IBAN] != 1 {
		t.Fatalf("counts %v", got)
	}

	// Damaged containers are reported incomplete, never panic.
	for name, bad := range map[string][]byte{
		"truncated":  doc[:700],
		"fat loop":   func() []byte { d := bytes.Clone(doc); binary.LittleEndian.PutUint32(d[512+4*3:], 2); return d }(),
		"bad shift":  func() []byte { d := bytes.Clone(doc); d[30] = 30; return d }(),
		"huge FAT":   func() []byte { d := bytes.Clone(doc); binary.LittleEndian.PutUint32(d[44:], 1<<30); return d }(),
		"dir beyond": func() []byte { d := bytes.Clone(doc); binary.LittleEndian.PutUint32(d[48:], 1<<20); return d }(),
	} {
		if ex := Extract(bad); ex.Complete {
			t.Errorf("%s: reported complete", name)
		}
	}
}

func TestRTFAndUTF16(t *testing.T) {
	rtf := []byte(`{\rtf1\ansi{\fonttbl\f0 Arial;}\f0\fs24 Carta: 4111\'201111 1111 1111\par Fine}`)
	bom := append([]byte{0xFF, 0xFE}, utf16le("card 5555555555554444")...)
	m, _ := Compile([]string{CreditCard}, nil)
	for name, in := range map[string][]byte{"rtf": rtf, "utf16 bom": bom} {
		n := 0
		for _, b := range Extract(in).Blobs {
			n += m.Counts(b)[CreditCard]
		}
		if n != 1 {
			t.Errorf("%s: %d cards", name, n)
		}
	}
}

func FuzzOLE2(f *testing.F) {
	f.Add(append(bytes.Clone(oleMagic), make([]byte, 600)...))
	f.Fuzz(func(_ *testing.T, b []byte) {
		if len(b) >= 8 {
			copy(b, oleMagic)
		}
		_ = Extract(b)
	})
}

// TestWriteLegacyFixture writes test/security/fixtures/card.doc when OPENSASE_WRITE_FIXTURES
// is set: a Compound File holding the public test card number as UTF-16LE.
func TestWriteLegacyFixture(t *testing.T) {
	dir := os.Getenv("OPENSASE_WRITE_FIXTURES")
	if dir == "" {
		t.Skip("set OPENSASE_WRITE_FIXTURES to the fixtures directory")
	}
	big := append(utf16le("Test card 4111 1111 1111 1111 (public test number)"), bytes.Repeat([]byte{0}, 5000)...)
	if err := os.WriteFile(dir+"/card.doc", oleFile(t, big, []byte("summary")), 0o644); err != nil { //nolint:gosec // G306: test fixture
		t.Fatal(err)
	}
}
