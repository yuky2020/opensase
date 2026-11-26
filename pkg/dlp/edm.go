package dlp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
	"unicode"
)

// Exact data match and document fingerprints (ADR-0029, issue #15).
//
// A tenant registers datasets:
//   - "values": records to protect (customer names, account IDs, e-mail addresses). Each value
//     is normalized into 1 to MaxValueTokens tokens;
//   - "document": protected documents, cut into shingles of ShingleTokens consecutive tokens.
//
// Only keyed hashes (HMAC-SHA-256 with a random per-dataset key, truncated to 64 bits) are
// stored and distributed; the values and documents themselves are discarded by the Control
// Plane. The Edge hashes the candidates of scanned text with the same key and counts members.

// Dataset kinds.
const (
	KindValues   = "values"
	KindDocument = "document"
	// KindRecords protects rows of structured data (for example a customer table): a match is
	// two or more fields of the same row in one text, so a common value alone (a first name,
	// a city) does not count (issue #75).
	KindRecords = "records"
)

// Candidate bounds.
const (
	MaxValueTokens = 4
	ShingleTokens  = 8
	// MaxRecordFields bounds the fields of one record; MaxRecordMatches bounds the distinct
	// field values of one text that are paired when counting records.
	MaxRecordFields  = 16
	MaxRecordMatches = 512
)

// Tokens normalizes text into lowercase tokens: letters and digits, keeping the inner
// punctuation of identifiers and addresses (". _ - @ +") and dropping it at the ends.
func Tokens(text string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		t := strings.Trim(b.String(), "._-@+")
		if t != "" {
			out = append(out, t)
		}
		b.Reset()
	}
	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
		case strings.ContainsRune("._-@+", r) && b.Len() > 0:
			b.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

// NormalizeValue is the canonical form of a dataset value, or "" if it has no tokens or
// more than MaxValueTokens.
func NormalizeValue(v string) string {
	t := Tokens(v)
	if len(t) == 0 || len(t) > MaxValueTokens {
		return ""
	}
	return strings.Join(t, " ")
}

// KeyedHash is the 64-bit truncated HMAC-SHA-256 of s under key.
func KeyedHash(key []byte, s string) uint64 {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(s))
	return binary.BigEndian.Uint64(m.Sum(nil))
}

// ValueHashes returns the sorted, unique hashes of the values (empty values are skipped).
func ValueHashes(key []byte, values []string) []uint64 {
	var out []uint64
	for _, v := range values {
		if n := NormalizeValue(v); n != "" {
			out = append(out, KeyedHash(key, n))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Record hashes are domain separated so that field and pair hashes can share one sorted
// list (and the existing wire format) without colliding.
func fieldHash(key []byte, v string) uint64 { return KeyedHash(key, "f\x00"+v) }

func pairHash(key []byte, a, b string) uint64 {
	if b < a {
		a, b = b, a
	}
	return KeyedHash(key, "p\x00"+a+"\x00"+b)
}

// RecordHashes returns the sorted, unique hashes of records: one per normalized field and
// one per unordered pair of distinct fields of the same record. Empty fields are skipped,
// fields beyond MaxRecordFields are ignored, and records with fewer than two usable fields
// add nothing.
func RecordHashes(key []byte, records [][]string) []uint64 {
	var out []uint64
	for _, rec := range records {
		var fs []string
		for _, f := range rec[:min(len(rec), MaxRecordFields)] {
			if n := NormalizeValue(f); n != "" && !slices.Contains(fs, n) {
				fs = append(fs, n)
			}
		}
		if len(fs) < 2 {
			continue
		}
		for i, a := range fs {
			out = append(out, fieldHash(key, a))
			for _, b := range fs[i+1:] {
				out = append(out, pairHash(key, a, b))
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ShingleHashes returns the sorted, unique hashes of the shingles of text.
func ShingleHashes(key []byte, text string) []uint64 {
	t := Tokens(text)
	var out []uint64
	for i := 0; i+ShingleTokens <= len(t); i++ {
		out = append(out, KeyedHash(key, strings.Join(t[i:i+ShingleTokens], " ")))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Dataset is the matching form of a dataset: its kind, key and sorted hashes.
type Dataset struct {
	Name   string
	Kind   string
	Key    []byte
	Hashes []uint64 // sorted, unique
}

func (d *Dataset) has(h uint64) bool {
	_, ok := slices.BinarySearch(d.Hashes, h)
	return ok
}

// maxCandidates bounds the work on one text (about 8 MiB of words).
const maxCandidates = 4_000_000

// Count returns how many candidates of text are in the dataset: token sequences of 1 to
// MaxValueTokens for values, distinct shingles for documents.
func (d *Dataset) Count(text []byte) int {
	t := Tokens(string(text))
	n, work := 0, 0
	switch d.Kind {
	case KindValues:
		for i := range t {
			for k := 1; k <= MaxValueTokens && i+k <= len(t); k++ {
				if work++; work > maxCandidates {
					return n
				}
				if d.has(KeyedHash(d.Key, strings.Join(t[i:i+k], " "))) {
					n++
				}
			}
		}
	case KindRecords:
		return d.countRecords(t)
	case KindDocument:
		seen := map[uint64]bool{}
		for i := 0; i+ShingleTokens <= len(t); i++ {
			if work++; work > maxCandidates {
				return n
			}
			h := KeyedHash(d.Key, strings.Join(t[i:i+ShingleTokens], " "))
			if d.has(h) && !seen[h] {
				seen[h] = true
				n++
			}
		}
	}
	return n
}

// countRecords returns how many field pairs of the same record appear in the tokens: the
// distinct candidates that are fields are collected first (at most MaxRecordMatches), then
// every pair of them is looked up.
func (d *Dataset) countRecords(t []string) int {
	var fields []string
	work := 0
	for i := range t {
		for k := 1; k <= MaxValueTokens && i+k <= len(t); k++ {
			if work++; work > maxCandidates {
				break
			}
			c := strings.Join(t[i:i+k], " ")
			if d.has(fieldHash(d.Key, c)) && !slices.Contains(fields, c) {
				fields = append(fields, c)
				if len(fields) == MaxRecordMatches {
					return d.countPairs(fields)
				}
			}
		}
	}
	return d.countPairs(fields)
}

func (d *Dataset) countPairs(fields []string) int {
	n := 0
	for i, a := range fields {
		for _, b := range fields[i+1:] {
			if d.has(pairHash(d.Key, a, b)) {
				n++
			}
		}
	}
	return n
}
