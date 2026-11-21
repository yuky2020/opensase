// Package dlp finds sensitive data in request bodies (ADR-0019): built-in detectors with
// checksum validation, to keep false positives low, plus tenant-defined patterns.
//
// A Matcher never returns the data it found, only how many matches each detector had, so
// that callers cannot leak it into logs or flow records.
package dlp

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Built-in detector names.
const (
	CreditCard = "credit-card" // 13-19 digits, Luhn-valid, known issuer prefix
	IBAN       = "iban"        // ISO 13616, mod-97 and per-country length
	PrivateKey = "private-key" // PEM private key block
	ITTaxCode  = "it-tax-code" // Italian codice fiscale with its check character
	Email      = "email"       // e-mail addresses (meant for bulk thresholds)
)

// Detectors lists the built-in detectors.
func Detectors() []string { return []string{CreditCard, IBAN, PrivateKey, ITTaxCode, Email} }

// Limits on tenant-defined patterns.
const (
	MaxPatterns   = 20
	MaxPatternLen = 256
)

// Matcher counts matches of a set of detectors and patterns.
type Matcher struct {
	builtin  []string
	patterns []*regexp.Regexp
}

// Compile builds a Matcher. patterns are RE2 regular expressions (linear time), matched
// case-insensitively.
func Compile(detectors, patterns []string) (*Matcher, error) {
	m := &Matcher{}
	for _, d := range detectors {
		if !slices.Contains(Detectors(), d) {
			return nil, fmt.Errorf("unknown detector %q", d)
		}
		if !slices.Contains(m.builtin, d) {
			m.builtin = append(m.builtin, d)
		}
	}
	if len(patterns) > MaxPatterns {
		return nil, fmt.Errorf("more than %d patterns", MaxPatterns)
	}
	for _, p := range patterns {
		if p == "" || len(p) > MaxPatternLen {
			return nil, fmt.Errorf("pattern must be 1..%d characters", MaxPatternLen)
		}
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("pattern %q matches the empty string", p)
		}
		m.patterns = append(m.patterns, re)
	}
	if len(m.builtin) == 0 && len(m.patterns) == 0 {
		return nil, errors.New("no detector or pattern")
	}
	return m, nil
}

// Counts returns the number of matches per detector ("pattern" for tenant patterns) in b.
// Only detectors with at least one match appear.
func (m *Matcher) Counts(b []byte) map[string]int {
	out := map[string]int{}
	for _, d := range m.builtin {
		var n int
		switch d {
		case CreditCard:
			n = countCards(b)
		case IBAN:
			n = countIBANs(b)
		case PrivateKey:
			n = countPrivateKeys(b)
		case ITTaxCode:
			n = countTaxCodes(b)
		case Email:
			n = len(emailRe.FindAllIndex(b, -1))
		}
		if n > 0 {
			out[d] = n
		}
	}
	n := 0
	for _, re := range m.patterns {
		n += len(re.FindAllIndex(b, -1))
	}
	if n > 0 {
		out["pattern"] = n
	}
	return out
}

// --- credit cards ---

// countCards finds runs of digits grouped by single spaces or dashes and not glued to other
// digits. Within a run, consecutive groups totalling 13-19 digits are candidates, so two
// numbers separated by a single space are both found. Candidates must be Luhn-valid with a
// known issuer prefix.
func countCards(b []byte) int {
	n := 0
	var groups [][]byte
	for i := 0; i < len(b); {
		if !isDigit(b[i]) || (i > 0 && isDigit(b[i-1])) {
			i++
			continue
		}
		groups = groups[:0]
		j := i
		for j < len(b) {
			k := j
			for k < len(b) && isDigit(b[k]) {
				k++
			}
			groups = append(groups, b[j:k])
			if k+1 < len(b) && (b[k] == ' ' || b[k] == '-') && isDigit(b[k+1]) && len(groups) < 64 {
				j = k + 1
				continue
			}
			j = k
			break
		}
		n += cardsInGroups(groups)
		i = j
	}
	return n
}

func cardsInGroups(groups [][]byte) int {
	n := 0
	digits := make([]byte, 0, 19)
	for i := 0; i < len(groups); {
		found := false
		digits = digits[:0]
		for j := i; j < len(groups) && len(digits)+len(groups[j]) <= 19; j++ {
			digits = append(digits, groups[j]...)
			if l := len(digits); l >= 13 && cardPrefix(digits) && luhn(digits) && !sameDigit(digits) {
				n++
				i, found = j+1, true
				break
			}
		}
		if !found {
			i++
		}
	}
	return n
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool { return isDigit(c) || (c|0x20 >= 'a' && c|0x20 <= 'z') }

// bounded reports whether b[s:e] is not glued to letters or digits.
func bounded(b []byte, s, e int) bool {
	return (s == 0 || !isAlnum(b[s-1])) && (e == len(b) || !isAlnum(b[e]))
}

// cardPrefix accepts the major issuer ranges with their lengths.
func cardPrefix(d []byte) bool {
	s := string(d)
	l := len(d)
	switch {
	case s[0] == '4': // Visa
		return l == 13 || l == 16 || l == 19
	case l == 16 && (s[:2] >= "51" && s[:2] <= "55" || s[:4] >= "2221" && s[:4] <= "2720"): // Mastercard
		return true
	case l == 15 && (s[:2] == "34" || s[:2] == "37"): // American Express
		return true
	case l >= 16 && (strings.HasPrefix(s, "6011") || strings.HasPrefix(s, "65")): // Discover
		return true
	case l >= 16 && s[:4] >= "3528" && s[:4] <= "3589": // JCB
		return true
	case l == 14 && (s[:2] == "36" || s[:2] == "38" || s[:3] >= "300" && s[:3] <= "305"): // Diners
		return true
	}
	return false
}

func luhn(d []byte) bool {
	sum := 0
	for i := range d {
		v := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

func sameDigit(d []byte) bool {
	for _, c := range d {
		if c != d[0] {
			return false
		}
	}
	return true
}

// --- IBAN ---

// ibanRe matches an IBAN written without spaces or in the printed form (groups of four).
var ibanRe = regexp.MustCompile(`(?i)[a-z]{2}[0-9]{2}(?:[a-z0-9]{11,30}|(?: [a-z0-9]{4}){2,7}(?: [a-z0-9]{1,4})?)`)

// ibanLen is the IBAN length of common countries; others must be 15..34.
var ibanLen = map[string]int{
	"AT": 20, "BE": 16, "CH": 21, "CZ": 24, "DE": 22, "DK": 18, "ES": 24, "FI": 18, "FR": 27,
	"GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IT": 27, "LU": 20, "NL": 18, "NO": 15,
	"PL": 28, "PT": 25, "RO": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
}

func countIBANs(b []byte) int {
	n := 0
	for _, m := range ibanRe.FindAllIndex(b, -1) {
		if !bounded(b, m[0], m[1]) {
			continue
		}
		s := strings.ToUpper(strings.ReplaceAll(string(b[m[0]:m[1]]), " ", ""))
		if want, ok := ibanLen[s[:2]]; ok {
			if len(s) != want {
				continue
			}
		} else if len(s) < 15 || len(s) > 34 {
			continue
		}
		if ibanValid(s) {
			n++
		}
	}
	return n
}

// ibanValid checks the ISO 7064 mod-97 checksum of an upper-case IBAN without spaces.
func ibanValid(s string) bool {
	r := s[4:] + s[:4]
	mod := 0
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c >= '0' && c <= '9':
			mod = (mod*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			mod = (mod*100 + v) % 97
		default:
			return false
		}
	}
	return mod == 1
}

// --- private keys ---

var pemKeyRe = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)

func countPrivateKeys(b []byte) int {
	if !bytes.Contains(b, []byte("PRIVATE KEY-----")) {
		return 0
	}
	return len(pemKeyRe.FindAllIndex(b, -1))
}

// --- Italian tax code ---

var taxRe = regexp.MustCompile(`(?i)[a-z]{6}[0-9lmnpqrstuv]{2}[abcdehlmprst][0-9lmnpqrstuv]{2}[a-z][0-9lmnpqrstuv]{3}[a-z]`)

// Odd-position values of the codice fiscale check algorithm, for 0-9 and A-Z.
var taxOdd = [36]int{1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23}

func countTaxCodes(b []byte) int {
	n := 0
	for _, m := range taxRe.FindAllIndex(b, -1) {
		if bounded(b, m[0], m[1]) && taxCheck(strings.ToUpper(string(b[m[0]:m[1]]))) {
			n++
		}
	}
	return n
}

func taxCheck(s string) bool {
	sum := 0
	for i := 0; i < 15; i++ {
		c := s[i]
		var idx int
		switch {
		case c >= '0' && c <= '9':
			idx = int(c - '0')
		default:
			idx = int(c-'A') + 10
		}
		if i%2 == 0 { // odd position (1-based)
			sum += taxOdd[idx]
		} else if c >= '0' && c <= '9' {
			sum += int(c - '0')
		} else {
			sum += int(c - 'A')
		}
	}
	return s[15] == byte('A'+sum%26)
}

// --- e-mail ---

var emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}`)
