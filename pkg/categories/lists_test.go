package categories

import (
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	in := `# a hosts file
0.0.0.0 localhost
127.0.0.1 malware.example # comment
0.0.0.0 Phish.Example.
plain.example
||adblock.example^
||path.example/x^
! adblock comment
not a domain line at all
`
	c, err := ParseList("t-acme-bad", "Bad", strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 4 {
		t.Fatalf("entries %d", c.Len())
	}
	db := (*DB)(nil).With(c)
	for _, h := range []string{"malware.example", "sub.phish.example", "plain.example", "adblock.example"} {
		if _, ok := db.Lookup(h, []string{"t-acme-bad"}); !ok {
			t.Errorf("%s not matched", h)
		}
	}
	if _, ok := db.Lookup("localhost", []string{"t-acme-bad"}); ok {
		t.Error("localhost matched")
	}
	if _, err := ParseList("Bad Name", "", strings.NewReader("a.example")); err == nil {
		t.Error("invalid name accepted")
	}
	if _, err := ParseList("empty", "", strings.NewReader("# nothing\n")); err == nil {
		t.Error("empty list accepted")
	}
}
