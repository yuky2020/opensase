package categories

import (
	"bytes"
	"testing"
)

func FuzzDecode(f *testing.F) {
	db, _ := ParseUT1(bytes.NewReader(ut1Archive(f)))
	if db != nil {
		var w bytes.Buffer
		if err := db.Encode(&w, []string{"gambling", "adult"}); err == nil {
			f.Add(w.Bytes())
		}
	}
	f.Add([]byte{})
	f.Add([]byte("OSCAT2"))
	f.Add([]byte("NOPE"))
	f.Add([]byte("OSCAT2\x01a\x00\x00\x00\x00\x00\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		res, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		if res == nil {
			t.Fatal("Decode returned nil DB with nil error")
		}
		for _, name := range res.Names() {
			if !ValidName(name) {
				t.Fatalf("invalid category name %q in DB", name)
			}
			c, ok := res.Get(name)
			if !ok || c == nil {
				t.Fatalf("category %q found in Names() but not in Get()", name)
			}
		}
	})
}

func FuzzParseUT1(f *testing.F) {
	f.Add(ut1Archive(f))
	f.Add([]byte{})
	f.Add([]byte("not a gzip archive"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		res, err := ParseUT1(bytes.NewReader(data))
		if err != nil {
			return
		}
		if res == nil {
			t.Fatal("ParseUT1 returned nil DB with nil error")
		}
		for _, name := range res.Names() {
			if !ValidName(name) {
				t.Fatalf("invalid category name %q in DB", name)
			}
			c, ok := res.Get(name)
			if !ok || c == nil {
				t.Fatalf("category %q found in Names() but not in Get()", name)
			}
		}
	})
}
