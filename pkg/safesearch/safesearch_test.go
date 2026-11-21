package safesearch

import (
	"net/http"
	"net/url"
	"testing"
)

func TestTarget(t *testing.T) {
	for name, want := range map[string]string{
		"www.google.com":             "forcesafesearch.google.com",
		"WWW.Google.IT.":             "forcesafesearch.google.com",
		"google.co.uk":               "forcesafesearch.google.com",
		"www.google.com.br":          "forcesafesearch.google.com",
		"m.youtube.com":              "restrict.youtube.com",
		"youtubei.googleapis.com":    "restrict.youtube.com",
		"www.bing.com":               "strict.bing.com",
		"duckduckgo.com":             "safe.duckduckgo.com",
		"mail.google.com":            "",
		"google.example.com":         "",
		"forcesafesearch.google.com": "",
		"notgoogle.com":              "",
	} {
		got, ok := Target(name)
		if got != want || ok != (want != "") {
			t.Errorf("Target(%q) = %q %v, want %q", name, got, ok, want)
		}
	}
	if !IsTarget("Restrict.YouTube.com.") || IsTarget("www.youtube.com") {
		t.Error("IsTarget")
	}
}

func TestRewrite(t *testing.T) {
	for _, tc := range []struct {
		host, url, want string
		changed         bool
	}{
		{"www.google.com", "https://www.google.com/search?q=x", "q=x&safe=active", true},
		{"www.google.it", "https://www.google.it/search?q=x&safe=off", "q=x&safe=active", true},
		{"www.google.com", "https://www.google.com/maps", "", false},
		{"www.bing.com", "https://www.bing.com/images/search?q=x", "adlt=strict&q=x", true},
		{"duckduckgo.com", "https://duckduckgo.com/?q=x&kp=-2", "kp=1&q=x", true},
		{"example.com", "https://example.com/search?q=x", "q=x", false},
	} {
		u, _ := url.Parse(tc.url)
		h := http.Header{}
		if got := Rewrite(tc.host, u, h); got != tc.changed || u.RawQuery != tc.want && tc.want != "" {
			t.Errorf("%s: changed %v query %q", tc.url, got, u.RawQuery)
		}
	}
	u, _ := url.Parse("https://www.youtube.com/watch?v=1")
	h := http.Header{}
	if !Rewrite("www.youtube.com", u, h) || h.Get("YouTube-Restrict") != "Strict" {
		t.Error("YouTube header")
	}
}
