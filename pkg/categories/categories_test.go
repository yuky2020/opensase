package categories

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// ut1Archive builds a small archive with the layout of blacklists.tar.gz.
func ut1Archive(t testing.TB) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	file := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	file("blacklists/gambling/domains", "casino.example\n# comment\n"+strings.Repeat("x", 70000)+"\nBETS.example.\n\nbad entry!\n*.poker.example")
	file("blacklists/gambling/urls", "casino.example/x\nhttp://Free-Games.example/Poker/\ncdn.example/promo?id=7\nnopath.example\n")
	file("blacklists/adult/domains", "adult.example\n")
	file("blacklists/liste_blanche/domains", "school.example\n")
	_ = tw.WriteHeader(&tar.Header{Name: "blacklists/porn", Typeflag: tar.TypeSymlink, Linkname: "adult"})
	file("blacklists/global_usage", "NAME:\tgambling\nDEFAULT_TYPE: black\nNAME EN: Gambling\nDESC EN: Online casinos.\n\nNAME:\tliste_blanche\nDEFAULT_TYPE: white\nNAME EN: White list\n")
	_ = tw.Close()
	_ = gz.Close()
	return b.Bytes()
}

func TestParseAndLookup(t *testing.T) {
	db, err := ParseUT1(bytes.NewReader(ut1Archive(t)))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Names(); !slices.Equal(got, []string{"adult", "gambling", "liste_blanche"}) {
		t.Fatalf("names %v", got)
	}
	g, _ := db.Get("gambling")
	if g.Len() != 3 || g.Title != "Gambling" || g.Description != "Online casinos." || g.Type != "black" {
		t.Fatalf("gambling %+v len %d", g, g.Len())
	}
	if w, _ := db.Get("liste_blanche"); w.Type != "white" {
		t.Fatal("white type not read")
	}
	if a, _ := db.Get("adult"); !slices.Equal(a.Aliases, []string{"porn"}) {
		t.Fatalf("aliases %v", a.Aliases)
	}
	if n, ok := db.Lookup("adult.example", []string{"porn"}); !ok || n != "porn" {
		t.Fatalf("alias lookup %q %v", n, ok)
	}
	for host, want := range map[string]string{
		"casino.example":       "gambling",
		"www.Casino.Example.":  "gambling",
		"bets.example":         "gambling",
		"a.b.poker.example":    "gambling",
		"adult.example":        "adult",
		"notcasino.example":    "",
		"example":              "",
		"casino.example.other": "",
	} {
		got, ok := db.Lookup(host, []string{"gambling", "adult"})
		if got != want || ok != (want != "") {
			t.Errorf("Lookup(%q) = %q %v, want %q", host, got, ok, want)
		}
	}
	if _, ok := db.Lookup("adult.example", []string{"gambling"}); ok {
		t.Error("category not asked for matched")
	}
}

func TestLookupURL(t *testing.T) {
	db, _ := ParseUT1(bytes.NewReader(ut1Archive(t)))
	if g, _ := db.Get("gambling"); g.URLs() != 3 {
		t.Fatalf("url entries %d", g.URLs())
	}
	for _, tc := range []struct {
		host, path, query string
		want              bool
	}{
		{"free-games.example", "/poker", "", true},
		{"www.free-games.example", "/Poker/table/1", "", true},
		{"free-games.example", "/poker2", "", false},
		{"free-games.example", "/", "", false},
		{"casino.example", "/x/y", "a=1", true},
		{"cdn.example", "/promo", "id=7", true},
		{"cdn.example", "/promo", "id=8", false},
		{"cdn.example", "/promo", "", false},
		{"nopath.example", "/anything", "", false},
	} {
		_, got := db.LookupURL(tc.host, tc.path, tc.query, []string{"gambling"})
		if got != tc.want {
			t.Errorf("LookupURL(%s %s ?%s) = %v", tc.host, tc.path, tc.query, got)
		}
	}
}

func TestWireRoundTrip(t *testing.T) {
	db, _ := ParseUT1(bytes.NewReader(ut1Archive(t)))
	var w bytes.Buffer
	if err := db.Encode(&w, []string{"gambling", "nope"}); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(w.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := got.Lookup("www.casino.example", []string{"gambling"}); !ok || n != "gambling" {
		t.Fatal("decoded lookup failed")
	}
	if _, ok := got.LookupURL("free-games.example", "/poker/x", "", []string{"gambling"}); !ok {
		t.Fatal("decoded URL lookup failed")
	}
	if _, ok := got.Get("adult"); ok {
		t.Fatal("category not requested was encoded")
	}
	for name, bad := range map[string][]byte{
		"header":   []byte("NOPE"),
		"name":     append([]byte("OSCAT2\x03A!b"), 0, 0, 0, 0),
		"unsorted": append([]byte("OSCAT2\x01a\x00\x00\x00\x00\x02\x00\x00\x00"), append(bytes.Repeat([]byte{9}, 8), bytes.Repeat([]byte{1}, 8)...)...),
		"short":    []byte("OSCAT2\x01a\x05\x00\x00\x00"),
	} {
		if _, err := Decode(bytes.NewReader(bad)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// TestRealUT1 parses a downloaded blacklists.tar.gz (OPENSASE_UT1=path) and reports its size.
func TestRealUT1(t *testing.T) {
	p := os.Getenv("OPENSASE_UT1")
	if p == "" {
		t.Skip("set OPENSASE_UT1 to a blacklists.tar.gz")
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start := time.Now()
	db, err := ParseUT1(f)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range db.Names() {
		c, _ := db.Get(n)
		total += c.Len()
	}
	a, _ := db.Get("adult")
	t.Logf("%d categories, %d domains (adult %d), parsed in %s", len(db.Names()), total, a.Len(), time.Since(start))
	if n, ok := db.Lookup("www.0-casino.info", []string{"gambling"}); !ok {
		t.Errorf("gambling entry not found: %q", n)
	}
}
