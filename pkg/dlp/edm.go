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
)

// Candidate bounds.
const (
	MaxValueTokens = 4
	ShingleTokens  = 8
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
