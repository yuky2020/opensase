package dlp

import (
	"strings"
	"testing"
)

func TestTokensAndNormalize(t *testing.T) {
	if got := strings.Join(Tokens("Mario ROSSI, mario.rossi@acme.example; ID: AB-1234."), "|"); got != "mario|rossi|mario.rossi@acme.example|id|ab-1234" {
		t.Fatalf("tokens %q", got)
	}
	if NormalizeValue("  Mario   Rossi ") != "mario rossi" || NormalizeValue("a b c d e") != "" || NormalizeValue("--") != "" {
		t.Fatal("normalize")
	}
}

func TestExactDataMatch(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	d := &Dataset{Kind: KindValues, Key: key, Hashes: ValueHashes(key, []string{"Mario Rossi", "ACCT-99887766", "luigi.verdi@acme.example"})}
	text := []byte(`Customer list: MARIO ROSSI (acct-99887766), luigi.verdi@acme.example; Anna Bianchi.`)
	if n := d.Count(text); n != 3 {
		t.Fatalf("matches %d", n)
	}
	if n := d.Count([]byte("Mario went to Rossi street")); n != 0 {
		t.Fatalf("partial words matched: %d", n)
	}
	// Another key does not match the same values.
	other := &Dataset{Kind: KindValues, Key: []byte("another key of thirty-two bytes!"), Hashes: d.Hashes}
	if other.Count(text) != 0 {
		t.Fatal("matched under another key")
	}
}

func TestDocumentFingerprint(t *testing.T) {
	key := []byte("k")
	doc := "The merger with Example Industries closes on 15 March at a price of 42 euro per share, subject to the approval of the board and of the competition authority."
	d := &Dataset{Kind: KindDocument, Key: key, Hashes: ShingleHashes(key, doc)}
	// A copied, reformatted sentence matches many shingles; unrelated text none.
	pasted := "fyi: the MERGER with example industries closes on 15 march, at a price of 42 euro per share!"
	if n := d.Count([]byte(pasted)); n < 5 {
		t.Fatalf("pasted excerpt: %d shingles", n)
	}
	if n := d.Count([]byte("The weather in March is mild and the board meets on Tuesdays.")); n != 0 {
		t.Fatalf("unrelated: %d", n)
	}
}

func FuzzTokens(f *testing.F) {
	f.Add("Mario Rossi, mario@x.example")
	f.Fuzz(func(_ *testing.T, s string) {
		d := &Dataset{Kind: KindValues, Key: []byte("k"), Hashes: ValueHashes([]byte("k"), []string{s})}
		_ = d.Count([]byte(s))
		_ = ShingleHashes([]byte("k"), s)
	})
}
