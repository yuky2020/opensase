package policy

import (
	"fmt"
	"net/textproto"
	"path"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/yuky2020/opensase/pkg/dlp"
)

// Web inspection policy (ADR-0018): compiled form and request evaluation.

// Limits of a WebPolicy.
const (
	maxWebRules    = 1000
	maxWebHeaders  = 64
	maxHeaderValue = 4096
	maxDLPRules    = 64
)

// reservedHeaders are request headers a WebHeader may not set: they frame the request or
// the connection, so changing them would desynchronise the Edge and the server.
var reservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "Keep-Alive": true, "Expect": true,
	"Proxy-Connection": true, "Proxy-Authorization": true, "Proxy-Authenticate": true,
}

type compiledWeb struct {
	inspect bool
	bypass  domainSet
	rules   []compiledWebRule
	headers []compiledWebHeader
	dlp     []compiledDLP
	malware MalwarePolicy
}

type compiledDLP struct {
	check DLPCheck
	all   bool // no Domains: every host
	hosts domainSet
}

// DLPCheck is one DLP rule that applies to a host.
type DLPCheck struct {
	ID             string
	Action         Action
	MinMatches     int
	BlockUnscanned bool
	Matcher        *dlp.Matcher
}

type compiledWebRule struct {
	id       string
	hosts    domainSet
	prefixes []string // lowercase, normalized
	methods  []string // uppercase
	action   Action
}

type compiledWebHeader struct {
	hosts domainSet
	name  string // canonical
	value string
}

func compileWeb(w *WebPolicy) (*compiledWeb, error) {
	cw := &compiledWeb{inspect: w.Inspect, malware: w.Malware}
	var err error
	if cw.bypass, err = buildSet(w.Bypass, "", "web.bypass"); err != nil {
		return nil, err
	}
	if len(w.Rules) > maxWebRules {
		return nil, verr("web.rules", "more than %d rules", maxWebRules)
	}
	seen := map[string]bool{}
	for i, r := range w.Rules {
		field := fmt.Sprintf("web.rules[%d]", i)
		if r.ID == "" || len(r.ID) > 64 || strings.ContainsAny(r.ID, " \t\r\n") {
			return nil, verr(field+".id", "must be 1..64 characters without spaces")
		}
		if seen[r.ID] {
			return nil, verr(field+".id", "duplicate %q", r.ID)
		}
		seen[r.ID] = true
		if r.Action != ActionAllow && r.Action != ActionBlock {
			return nil, verr(field+".action", "must be allow or block, got %q", r.Action)
		}
		if len(r.Domains) == 0 {
			return nil, verr(field+".domains", "at least one domain required")
		}
		cr := compiledWebRule{id: r.ID, action: r.Action}
		if cr.hosts, err = buildSet(r.Domains, "", field+".domains"); err != nil {
			return nil, err
		}
		for j, p := range r.PathPrefixes {
			if !strings.HasPrefix(p, "/") {
				return nil, verr(fmt.Sprintf("%s.pathPrefixes[%d]", field, j), "must start with '/'")
			}
			cr.prefixes = append(cr.prefixes, strings.ToLower(normalizePath(p, true)))
		}
		for j, m := range r.Methods {
			if m == "" || !httpguts.ValidHeaderFieldName(m) {
				return nil, verr(fmt.Sprintf("%s.methods[%d]", field, j), "invalid method %q", m)
			}
			cr.methods = append(cr.methods, strings.ToUpper(m))
		}
		cw.rules = append(cw.rules, cr)
	}
	if len(w.Headers) > maxWebHeaders {
		return nil, verr("web.headers", "more than %d headers", maxWebHeaders)
	}
	for i, h := range w.Headers {
		field := fmt.Sprintf("web.headers[%d]", i)
		if !httpguts.ValidHeaderFieldName(h.Name) {
			return nil, verr(field+".name", "invalid header name %q", h.Name)
		}
		name := textproto.CanonicalMIMEHeaderKey(h.Name)
		if reservedHeaders[name] {
			return nil, verr(field+".name", "%s cannot be set", name)
		}
		if len(h.Value) > maxHeaderValue || !httpguts.ValidHeaderFieldValue(h.Value) {
			return nil, verr(field+".value", "invalid header value")
		}
		if len(h.Domains) == 0 {
			return nil, verr(field+".domains", "at least one domain required")
		}
		ch := compiledWebHeader{name: name, value: h.Value}
		if ch.hosts, err = buildSet(h.Domains, "", field+".domains"); err != nil {
			return nil, err
		}
		cw.headers = append(cw.headers, ch)
	}
	if len(w.DLP) > maxDLPRules {
		return nil, verr("web.dlp", "more than %d rules", maxDLPRules)
	}
	for i, r := range w.DLP {
		field := fmt.Sprintf("web.dlp[%d]", i)
		if r.ID == "" || len(r.ID) > 64 || strings.ContainsAny(r.ID, " \t\r\n") {
			return nil, verr(field+".id", "must be 1..64 characters without spaces")
		}
		if seen["dlp:"+r.ID] {
			return nil, verr(field+".id", "duplicate %q", r.ID)
		}
		seen["dlp:"+r.ID] = true
		if r.Action != ActionAllow && r.Action != ActionBlock {
			return nil, verr(field+".action", "must be allow or block, got %q", r.Action)
		}
		if r.MinMatches < 0 || r.MinMatches > 100000 {
			return nil, verr(field+".minMatches", "must be 0..100000")
		}
		m, err := dlp.Compile(r.Detectors, r.Patterns)
		if err != nil {
			return nil, verr(field, "%v", err)
		}
		cd := compiledDLP{all: len(r.Domains) == 0, check: DLPCheck{ID: r.ID, Action: r.Action, MinMatches: max(r.MinMatches, 1), BlockUnscanned: r.BlockUnscanned, Matcher: m}}
		if cd.hosts, err = buildSet(r.Domains, "", field+".domains"); err != nil {
			return nil, err
		}
		cw.dlp = append(cw.dlp, cd)
	}
	return cw, nil
}

// Malware returns the malware scanning policy (ADR-0020).
func (c *Compiled) Malware() MalwarePolicy {
	if c.web == nil {
		return MalwarePolicy{}
	}
	return c.web.malware
}

// DLPChecks returns the DLP rules that apply to requests to host, in policy order.
func (c *Compiled) DLPChecks(host string) []DLPCheck {
	if c.web == nil {
		return nil
	}
	var out []DLPCheck
	for i := range c.web.dlp {
		if d := &c.web.dlp[i]; d.all || d.hosts.has(host) {
			out = append(out, d.check)
		}
	}
	return out
}

// normalizePath resolves dot segments and collapses duplicate slashes, so "/a/../admin" and
// "//admin" match a rule for "/admin". keepSlash keeps a trailing slash (rule prefixes).
func normalizePath(p string, keepSlash bool) string {
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	c := path.Clean(p)
	if keepSlash && strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

func (s *domainSet) has(host string) bool {
	var nb nameBuf
	if !nb.load(host) {
		return false
	}
	_, ok := s.lookup(&nb)
	return ok
}

// Inspects reports whether the Edge decrypts TLS for host: inspection is on and host is not
// bypassed. A host that is not a valid name (an IP literal, no SNI) is never decrypted.
func (c *Compiled) Inspects(host string) bool {
	if c.web == nil || !c.web.inspect || validName(strings.ToLower(strings.TrimSuffix(host, "."))) != nil {
		return false
	}
	return !c.web.bypass.has(host)
}

// InspectEnabled reports whether TLS inspection is on for the device (some hosts may still be
// bypassed).
func (c *Compiled) InspectEnabled() bool { return c.web != nil && c.web.inspect }

// HasWebRules reports whether requests need to be evaluated at all (any rule, header or DLP
// rule).
func (c *Compiled) HasWebRules() bool {
	return c.web != nil && (len(c.web.rules) > 0 || len(c.web.headers) > 0 || len(c.web.dlp) > 0 ||
		c.web.malware.Uploads || c.web.malware.Downloads)
}

// WebDecide returns the action for one request and the ID of the rule that decided it ("" if
// no rule matched, which allows). urlPath is the decoded request path.
func (c *Compiled) WebDecide(host, method, urlPath string) (Action, string) {
	if c.web == nil {
		return ActionAllow, ""
	}
	p := strings.ToLower(normalizePath(urlPath, false))
	pSlash := p
	if !strings.HasSuffix(pSlash, "/") {
		pSlash += "/"
	}
	method = strings.ToUpper(method)
	for i := range c.web.rules {
		r := &c.web.rules[i]
		if !r.hosts.has(host) {
			continue
		}
		if len(r.methods) > 0 && !containsString(r.methods, method) {
			continue
		}
		if len(r.prefixes) > 0 && !matchPrefix(r.prefixes, p, pSlash) {
			continue
		}
		return r.action, r.id
	}
	return ActionAllow, ""
}

// matchPrefix reports whether p starts with one of prefixes. A prefix ending in "/" also
// matches the directory itself ("/admin/" matches "/admin").
func matchPrefix(prefixes []string, p, pSlash string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) || strings.HasPrefix(pSlash, pre) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// WebHeaders returns the headers to set on a request to host, in policy order.
func (c *Compiled) WebHeaders(host string) []WebHeader {
	if c.web == nil {
		return nil
	}
	var out []WebHeader
	for i := range c.web.headers {
		if h := &c.web.headers[i]; h.hosts.has(host) {
			out = append(out, WebHeader{Name: h.name, Value: h.value})
		}
	}
	return out
}
