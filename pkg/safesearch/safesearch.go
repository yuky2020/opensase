// Package safesearch forces the safe modes that search engines and video sites document
// for networks (ADR-0025): DNS answers that point their hostnames to a "safe" hostname, and
// on the inspected path the request parameters and headers that request it.
package safesearch

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// googleRe matches Google search hostnames: google.<tld>, google.co.<cc>, google.com.<cc>,
// with or without "www.".
var googleRe = regexp.MustCompile(`^(www\.)?google\.(com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})$`)

// exact maps hostnames to the safe hostname their provider documents.
var exact = map[string]string{
	// YouTube restricted mode (strict).
	"www.youtube.com":          "restrict.youtube.com",
	"m.youtube.com":            "restrict.youtube.com",
	"youtube.com":              "restrict.youtube.com",
	"youtubei.googleapis.com":  "restrict.youtube.com",
	"youtube.googleapis.com":   "restrict.youtube.com",
	"www.youtube-nocookie.com": "restrict.youtube.com",
	"music.youtube.com":        "restrict.youtube.com",
	// Bing strict mode.
	"www.bing.com": "strict.bing.com",
	"bing.com":     "strict.bing.com",
	// DuckDuckGo safe search.
	"duckduckgo.com":     "safe.duckduckgo.com",
	"www.duckduckgo.com": "safe.duckduckgo.com",
}

// Target returns the safe hostname a query for name must resolve to, if name is a covered
// search or video hostname. name may be mixed case with a trailing dot.
func Target(name string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	if t, ok := exact[n]; ok {
		return t, true
	}
	if googleRe.MatchString(n) {
		return "forcesafesearch.google.com", true
	}
	return "", false
}

// IsTarget reports whether name is one of the safe hostnames (they must resolve normally).
func IsTarget(name string) bool {
	switch strings.TrimSuffix(strings.ToLower(name), ".") {
	case "forcesafesearch.google.com", "restrict.youtube.com", "restrictmoderate.youtube.com", "strict.bing.com", "safe.duckduckgo.com":
		return true
	}
	return false
}

// Rewrite adds the safe-mode parameters and headers to a request for host on the inspected
// path. It reports whether the request was changed.
func Rewrite(host string, u *url.URL, h http.Header) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	set := func(k, v string) bool {
		q := u.Query()
		if q.Get(k) == v {
			return false
		}
		q.Set(k, v)
		u.RawQuery = q.Encode()
		return true
	}
	switch {
	case googleRe.MatchString(host):
		if strings.HasPrefix(u.Path, "/search") || u.Path == "/complete/search" {
			return set("safe", "active")
		}
	case host == "www.bing.com" || host == "bing.com":
		if strings.HasPrefix(u.Path, "/search") || strings.HasPrefix(u.Path, "/images/search") || strings.HasPrefix(u.Path, "/videos/search") {
			return set("adlt", "strict")
		}
	case host == "duckduckgo.com" || host == "www.duckduckgo.com" || host == "html.duckduckgo.com":
		return set("kp", "1")
	case strings.HasSuffix(host, "youtube.com") || host == "youtubei.googleapis.com" || host == "www.youtube-nocookie.com":
		if h.Get("YouTube-Restrict") != "Strict" {
			h.Set("YouTube-Restrict", "Strict")
			return true
		}
	}
	return false
}
