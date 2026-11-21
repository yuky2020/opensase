package dlp

import (
	"maps"
	"testing"
)

func TestDetectors(t *testing.T) {
	m, err := Compile(Detectors(), []string{`project\s+falcon`})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		in   string
		want map[string]int
	}{
		{"visa", "card 4111111111111111 exp", map[string]int{CreditCard: 1}},
		{"grouped", "4111 1111 1111 1111 and 5555-5555-5555-4444", map[string]int{CreditCard: 2}},
		{"amex in json", `{"pan":"378282246310005"}`, map[string]int{CreditCard: 1}},
		{"adjacent", "4111111111111111,5555555555554444", map[string]int{CreditCard: 2}},
		{"bad luhn", "4111111111111112", map[string]int{}},
		{"same digit", "4444444444444444", map[string]int{}},
		{"unknown prefix", "9111111111111119", map[string]int{}},
		{"longer number", "41111111111111110000000", map[string]int{}},
		{"order id", "order 1234567890123", map[string]int{}},
		{"iban", "pay IT60X0542811101000000123456 now", map[string]int{IBAN: 1}},
		{"iban spaced", "GB82 WEST 1234 5698 7654 32", map[string]int{IBAN: 1}},
		{"iban lower", "it60x0542811101000000123456", map[string]int{IBAN: 1}},
		{"iban bad check", "IT61X0542811101000000123456", map[string]int{}},
		{"iban bad length", "IT60X054281110100000012345", map[string]int{}},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMII...", map[string]int{PrivateKey: 1}},
		{"openssh key", "-----BEGIN OPENSSH PRIVATE KEY-----", map[string]int{PrivateKey: 1}},
		{"public key", "-----BEGIN PUBLIC KEY-----", map[string]int{}},
		{"tax code", "cf: RSSMRA85T10A562S.", map[string]int{ITTaxCode: 1}},
		{"tax code bad check", "RSSMRA85T10A562T", map[string]int{}},
		{"tax code glued", "XRSSMRA85T10A562S", map[string]int{}},
		{"emails", "a@b.example, c.d+e@mail.example.org", map[string]int{Email: 2}},
		{"pattern", "the PROJECT   Falcon plan", map[string]int{"pattern": 1}},
		{"nothing", "hello world 2026-11-21", map[string]int{}},
	} {
		if got := m.Counts([]byte(tc.in)); !maps.Equal(got, tc.want) {
			t.Errorf("%s: %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestCompile(t *testing.T) {
	for name, tc := range map[string]struct{ det, pat []string }{
		"unknown":  {[]string{"ssn"}, nil},
		"empty":    {nil, nil},
		"bad re":   {nil, []string{"a("}},
		"empty re": {nil, []string{"a*"}},
		"long re":  {nil, []string{string(make([]byte, MaxPatternLen+1))}},
	} {
		if _, err := Compile(tc.det, tc.pat); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

func FuzzCounts(f *testing.F) {
	m, _ := Compile(Detectors(), []string{"secret"})
	for _, s := range []string{"4111 1111 1111 1111", "IT60X0542811101000000123456", "RSSMRA85T10A562S", "-----BEGIN PRIVATE KEY-----", "a@b.co"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(_ *testing.T, b []byte) { _ = m.Counts(b) })
}
