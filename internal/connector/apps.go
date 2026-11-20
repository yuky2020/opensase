// Package connector implements the OpenSASE Connector (ADR-0013): it enrolls with a
// connector provisioning key, keeps one outbound TLS 1.3 PQ connection to every Edge
// broker and serves POST /v1/dial streams over it (inverted HTTP/2), dialling only the
// name:port pairs of its own ConnectorConfig.Apps.
package connector

import (
	"strings"

	"github.com/yuky2020/opensase/pkg/policy"
)

// MatchApp returns the first app whose Domains match name and whose Ports contain port.
// Domains use Match.Domains semantics: "example.com" exact, "*.example.com" the apex and every
// subdomain, case-insensitive, trailing dot ignored. Empty Ports means no access.
func MatchApp(apps []policy.PrivateApp, name string, port uint16) (policy.PrivateApp, bool) {
	name = normalize(name)
	if name == "" || port == 0 {
		return policy.PrivateApp{}, false
	}
	for _, a := range apps {
		if domainMatch(a.Domains, name) && portMatch(a.Ports, port) {
			return a, true
		}
	}
	return policy.PrivateApp{}, false
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func domainMatch(patterns []string, name string) bool {
	for _, p := range patterns {
		p = normalize(p)
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if suffix != "" && (name == suffix || strings.HasSuffix(name, "."+suffix)) {
				return true
			}
		} else if p != "" && p != "*" && name == p {
			return true
		}
	}
	return false
}

func portMatch(rs []policy.PortRange, port uint16) bool {
	for _, r := range rs {
		to := r.To
		if to == 0 {
			to = r.From
		}
		if port >= r.From && port <= to {
			return true
		}
	}
	return false
}
