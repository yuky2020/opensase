package categories

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// Blocklists imported from a URL (issue #63). They become extra categories, so the Control
// Plane serves them to the Edges like the category list, and policies block them by name.

// maxListBytes bounds one downloaded list.
const maxListBytes = 64 << 20

// ParseList reads a domain blocklist in hosts format ("0.0.0.0 example.com"), plain format
// (one domain per line) or the domain-only adblock form ("||example.com^"). Comments (#, !)
// and entries it cannot read are skipped.
func ParseList(name, title string, r io.Reader) (*Category, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("categories: invalid list name %q", name)
	}
	c := &Category{Name: name, Title: title, Type: "black"}
	lr := &io.LimitedReader{R: r, N: maxListBytes + 1}
	if err := readEntries(lr, normalizeListEntry, &c.hashes); err != nil {
		return nil, fmt.Errorf("categories: list %s: %w", name, err)
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("categories: list %s is larger than %d bytes", name, maxListBytes)
	}
	slices.Sort(c.hashes)
	c.hashes = slices.Compact(c.hashes)
	if len(c.hashes) == 0 {
		return nil, fmt.Errorf("categories: list %s has no domain", name)
	}
	return c, nil
}

func normalizeListEntry(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' {
		return ""
	}
	if i := strings.IndexAny(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if strings.HasPrefix(line, "||") {
		line = strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
		if strings.ContainsAny(line, "/*$^") {
			return ""
		}
		return normalizeEntry(line)
	}
	f := strings.Fields(line)
	switch len(f) {
	case 1:
		return normalizeEntry(f[0])
	case 2:
		if f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::" || f[0] == "::1" {
			if f[1] == "localhost" || f[1] == "0.0.0.0" || strings.HasPrefix(f[1], "localhost.") {
				return ""
			}
			return normalizeEntry(f[1])
		}
	}
	return ""
}

// With returns a DB with the categories of db plus extra (an extra replaces a category of the
// same name). db is not modified and may be nil.
func (db *DB) With(extra ...*Category) *DB {
	out := &DB{cats: map[string]*Category{}, alias: map[string]string{}}
	if db != nil {
		maps.Copy(out.cats, db.cats)
		maps.Copy(out.alias, db.alias)
	}
	for _, c := range extra {
		if c == nil {
			continue
		}
		out.cats[c.Name] = c
		delete(out.alias, c.Name)
	}
	return out
}
