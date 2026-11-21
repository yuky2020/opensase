// Package categories holds web categories built from a public category list (ADR-0022): the
// UT1 blacklists of Université Toulouse Capitole (CC BY-SA 4.0), the list used by SquidGuard,
// E2Guardian and most open source web filters.
//
// Domains are stored as sorted 64-bit FNV-1a hashes of their names: a category of 4.6 million
// domains takes 37 MB, and a lookup is a binary search per label suffix. An entry matches the
// name and all its subdomains, as in SquidGuard.
package categories

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Source attribution, to show wherever categories are listed.
const (
	SourceName    = "UT1 blacklists, Université Toulouse Capitole"
	SourceLicence = "CC BY-SA 4.0"
	SourceURL     = "https://dsi.ut-capitole.fr/blacklists/"
	DefaultURL    = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
)

// Parsing bounds.
const (
	maxArchive     = 1 << 30 // uncompressed tar bytes
	maxCategories  = 512
	maxPerCategory = 20_000_000
	maxLine        = 512
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidName reports whether s can be a category name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Category is one category of the list.
type Category struct {
	Name        string
	Title       string // English display name
	Description string // English description
	Type        string // "black" (meant to be blocked) or "white" (allow lists)
	Aliases     []string
	hashes      []uint64 // domains: sorted, unique
	urls        []uint64 // URL entries (host/path prefixes): sorted, unique
}

// URLs is the number of URL entries in the category.
func (c *Category) URLs() int { return len(c.urls) }

// Len is the number of domains in the category.
func (c *Category) Len() int { return len(c.hashes) }

// DB is a set of categories.
type DB struct {
	cats  map[string]*Category
	alias map[string]string // alias -> category name
}

// Names returns the category names, sorted.
func (db *DB) Names() []string {
	out := make([]string, 0, len(db.cats))
	for n := range db.cats {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get returns a category by name or alias.
func (db *DB) Get(name string) (*Category, bool) {
	if db == nil {
		return nil, false
	}
	if t, ok := db.alias[name]; ok {
		name = t
	}
	c, ok := db.cats[name]
	return c, ok
}

// Hash is the hash of a normalized (lowercase, no trailing dot) name.
func Hash(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}

func (c *Category) has(h uint64) bool {
	_, ok := slices.BinarySearch(c.hashes, h)
	return ok
}

// Lookup returns the first category of names (in that order) that host or one of its parent
// domains belongs to.
func (db *DB) Lookup(host string, names []string) (string, bool) {
	if db == nil || len(names) == 0 {
		return "", false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	var hs []uint64
	for s := host; ; {
		hs = append(hs, Hash(s))
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
		if !strings.Contains(s, ".") {
			// A bare TLD is never an entry worth matching.
			break
		}
	}
	for _, n := range names {
		c, ok := db.Get(n)
		if !ok {
			continue
		}
		for _, h := range hs {
			if c.has(h) {
				return n, true
			}
		}
	}
	return "", false
}

// readEntries hashes the normalized lines of r into dst. Lines over maxLine are skipped, not
// fatal: one bad line must not drop the rest.
func readEntries(r io.Reader, norm func(string) string, dst *[]uint64) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		long := errors.Is(err, bufio.ErrBufferFull)
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = br.ReadSlice('\n')
		}
		if !long && len(line) <= maxLine {
			if n := norm(string(line)); n != "" {
				*dst = append(*dst, Hash(n))
				if len(*dst) > maxPerCategory {
					return errors.New("too many entries")
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// normalizeURLEntry returns the normalized "host/path" of a urls-file line, or "": lower
// case, no scheme, no trailing slash. Entries without a path are domains, not URLs.
func normalizeURLEntry(line string) string {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" || line[0] == '#' {
		return ""
	}
	line = strings.TrimPrefix(strings.TrimPrefix(line, "http://"), "https://")
	line = strings.TrimRight(line, "/")
	host, path, ok := strings.Cut(line, "/")
	if !ok || path == "" || normalizeEntry(host) == "" && !isIPv4(host) {
		return ""
	}
	return strings.TrimSuffix(host, ".") + "/" + path
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

// LookupURL returns the first category of names with a URL entry that is a prefix of the
// request: host (or a parent domain) followed by the path up to a "/" boundary, the whole
// path, or the path with its query. path is the request path, query the raw query.
func (db *DB) LookupURL(host, path, query string, names []string) (string, bool) {
	if db == nil || len(names) == 0 {
		return "", false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	p := strings.ToLower(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	var prefixes []string
	for i := 1; i < len(p); i++ {
		if p[i] == '/' {
			prefixes = append(prefixes, strings.TrimRight(p[:i], "/"))
		}
	}
	if full := strings.TrimRight(p, "/"); full != "" {
		prefixes = append(prefixes, full)
		if query != "" {
			prefixes = append(prefixes, full+"?"+strings.ToLower(query), p+"?"+strings.ToLower(query))
		}
	}
	var hs []uint64
	for s := host; ; {
		for _, pre := range prefixes {
			if pre != "" && pre != "/" {
				hs = append(hs, Hash(s+pre))
			}
		}
		i := strings.IndexByte(s, '.')
		if i < 0 || isIPv4(s) {
			break
		}
		s = s[i+1:]
		if !strings.Contains(s, ".") {
			break
		}
	}
	for _, n := range names {
		c, ok := db.Get(n)
		if !ok || len(c.urls) == 0 {
			continue
		}
		for _, h := range hs {
			if _, found := slices.BinarySearch(c.urls, h); found {
				return n, true
			}
		}
	}
	return "", false
}

// normalizeEntry returns the normalized name of a domains-file line, or "".
func normalizeEntry(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || len(line) > 253 {
		return ""
	}
	line = strings.TrimSuffix(strings.ToLower(line), ".")
	line = strings.TrimPrefix(line, "*.")
	for i := 0; i < len(line); i++ {
		c := line[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return ""
		}
	}
	if !strings.Contains(line, ".") {
		return ""
	}
	return line
}

// ParseUT1 reads the UT1 blacklists.tar.gz archive: every <category>/domains file, the
// symbolic links between categories (aliases) and the global_usage catalogue.
func ParseUT1(r io.Reader) (*DB, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("categories: %w", err)
	}
	tr := tar.NewReader(io.LimitReader(gz, maxArchive))
	db := &DB{cats: map[string]*Category{}, alias: map[string]string{}}
	aliases := map[string]string{} // alias -> target
	var usage []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("categories: read archive: %w", err)
		}
		dir, file := path.Split(path.Clean(h.Name))
		cat := path.Base(dir)
		switch {
		case h.Typeflag == tar.TypeSymlink && path.Dir(path.Clean(h.Name)) == "blacklists":
			if ValidName(file) && ValidName(path.Base(h.Linkname)) {
				aliases[file] = path.Base(h.Linkname)
			}
		case h.Typeflag == tar.TypeReg && file == "global_usage":
			if usage, err = io.ReadAll(io.LimitReader(tr, 4<<20)); err != nil {
				return nil, err
			}
		case h.Typeflag == tar.TypeReg && (file == "domains" || file == "urls") && ValidName(cat):
			c := db.cats[cat]
			if c == nil {
				if len(db.cats) >= maxCategories {
					return nil, errors.New("categories: too many categories")
				}
				c = &Category{Name: cat, Type: "black"}
				db.cats[cat] = c
			}
			norm, dst := normalizeEntry, &c.hashes
			if file == "urls" {
				norm, dst = normalizeURLEntry, &c.urls
			}
			if err := readEntries(tr, norm, dst); err != nil {
				return nil, fmt.Errorf("categories: %s/%s: %w", cat, file, err)
			}
		}
	}
	for _, c := range db.cats {
		slices.Sort(c.hashes)
		c.hashes = slices.Compact(c.hashes)
		slices.Sort(c.urls)
		c.urls = slices.Compact(c.urls)
	}
	if len(db.cats) == 0 {
		return nil, errors.New("categories: no category in the archive")
	}
	applyUsage(db, usage)
	for a, target := range aliases {
		if c, ok := db.cats[target]; ok && db.cats[a] == nil {
			c.Aliases = append(c.Aliases, a)
			db.alias[a] = target
		}
	}
	for _, c := range db.cats {
		sort.Strings(c.Aliases)
	}
	return db, nil
}

// applyUsage reads the NAME / DEFAULT_TYPE / NAME EN / DESC EN records of global_usage.
func applyUsage(db *DB, usage []byte) {
	var cur *Category
	sc := bufio.NewScanner(bytes.NewReader(usage))
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "NAME":
			cur = db.cats[val]
		case "DEFAULT_TYPE":
			if cur != nil && (val == "black" || val == "white") {
				cur.Type = val
			}
		case "NAME EN":
			if cur != nil {
				cur.Title = val
			}
		case "DESC EN":
			if cur != nil {
				cur.Description = val
			}
		}
	}
}

// --- wire format (Control Plane -> Edge) ---
//
// "OSCAT2" then, per category: name length (1 byte), name, then the domain hashes and the
// URL hashes, each as a count (uint32 LE) followed by that many uint64 LE, sorted.

var magic = []byte("OSCAT2")

// Encode writes the named categories of db (unknown names are skipped).
func (db *DB) Encode(w io.Writer, names []string) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.Write(magic); err != nil {
		return err
	}
	var b [8]byte
	for _, n := range names {
		c, ok := db.Get(n)
		if !ok {
			continue
		}
		// Under the requested name, so that aliases in a policy match.
		_ = bw.WriteByte(byte(len(n)))
		_, _ = bw.WriteString(n)
		for _, list := range [][]uint64{c.hashes, c.urls} {
			binary.LittleEndian.PutUint32(b[:4], uint32(len(list))) //nolint:gosec // G115: bounded by maxPerCategory
			_, _ = bw.Write(b[:4])
			for _, h := range list {
				binary.LittleEndian.PutUint64(b[:], h)
				if _, err := bw.Write(b[:]); err != nil {
					return err
				}
			}
		}
	}
	return bw.Flush()
}

// Decode reads the wire format. Hashes must be sorted and unique.
func Decode(r io.Reader) (*DB, error) {
	br := bufio.NewReader(r)
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(br, head); err != nil || !bytes.Equal(head, magic) {
		return nil, errors.New("categories: bad header")
	}
	db := &DB{cats: map[string]*Category{}, alias: map[string]string{}}
	for {
		l, err := br.ReadByte()
		if errors.Is(err, io.EOF) {
			return db, nil
		}
		if err != nil {
			return nil, err
		}
		name := make([]byte, l)
		if _, err := io.ReadFull(br, name); err != nil || !ValidName(string(name)) {
			return nil, errors.New("categories: bad name")
		}
		if len(db.cats) >= maxCategories {
			return nil, errors.New("categories: too large")
		}
		c := &Category{Name: string(name), Type: "black"}
		for _, dst := range []*[]uint64{&c.hashes, &c.urls} {
			if err := readHashes(br, dst); err != nil {
				return nil, err
			}
		}
		db.cats[c.Name] = c
	}
}

func readHashes(br *bufio.Reader, dst *[]uint64) error {
	var b [8]byte
	if _, err := io.ReadFull(br, b[:4]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(b[:4])
	if n > maxPerCategory {
		return errors.New("categories: too large")
	}
	list := make([]uint64, n)
	for i := range list {
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return err
		}
		list[i] = binary.LittleEndian.Uint64(b[:])
		if i > 0 && list[i] <= list[i-1] {
			return errors.New("categories: hashes not sorted")
		}
	}
	*dst = list
	return nil
}
