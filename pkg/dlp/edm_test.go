package dlp

import (
	"slices"
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

func TestRecords(t *testing.T) {
	key := []byte("a key of thirty-two bytes long!!")
	d := &Dataset{Kind: KindRecords, Key: key, Hashes: RecordHashes(key, [][]string{
		{"Mario Rossi", "ACCT-99887766", "Roma"},
		{"Luigi Verdi", "ACCT-11223344", "Roma"},
		{"only-one-field"},
	})}
	cases := []struct {
		name string
		text string
		want int
	}{
		{"two fields of one record", "pay Mario Rossi on ACCT-99887766 today", 1},
		{"three fields of one record", "mario rossi, acct-99887766, roma", 3},
		{"fields of different records", "Mario Rossi and ACCT-11223344", 0},
		{"a shared value alone", "meeting in Roma", 0},
		{"a common field of two records", "Roma: Mario Rossi, Luigi Verdi", 2},
		{"single-field records add nothing", "only-one-field", 0},
		{"no match", "nothing to see here", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := d.Count([]byte(c.text)); got != c.want {
				t.Fatalf("Count(%q) = %d, want %d", c.text, got, c.want)
			}
		})
	}
	// A different key matches nothing: hashes are useless without the dataset key.
	other := &Dataset{Kind: KindRecords, Key: []byte("another key of thirty-two bytes!"), Hashes: d.Hashes}
	if got := other.Count([]byte("Mario Rossi ACCT-99887766")); got != 0 {
		t.Fatalf("other key matched %d", got)
	}
	// Field and pair hashes are domain separated from values datasets.
	if slices.Contains(d.Hashes, KeyedHash(key, "mario rossi")) {
		t.Fatal("record field hash equals the values hash")
	}
}
