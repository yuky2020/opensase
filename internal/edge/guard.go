package edge

import (
	"net/netip"
	"strings"

	"github.com/yuky2020/opensase/pkg/policy"
)

// Built-in Edge rules, applied to tunnel traffic before any tenant or user policy
// (security review #3 and #6). Their decisions use Layer "edge".
const (
	LayerEdge       = "edge"
	RuleBuiltinDeny = "builtin-deny"
	RuleDNSBypass   = "builtin-dns-bypass" //nolint:gosec // G101: rule ID, not a credential
	dnsPort         = 53
	dotPort         = 853
	httpsPort       = 443
)

// alwaysDenied are destinations a tunnel client never needs: link-local (cloud metadata at
// 169.254.169.254), loopback, "this network", multicast and broadcast, and the IPv6
// equivalents. DNS goes to the Edge resolver on its tunnel address, which is unicast and
// handled before these rules.
var alwaysDenied = mustPrefixes(
	"169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
	"fe80::/10", "::1/128", "::/128", "ff00::/8",
)

// privateRanges are denied unless Config.AllowPrivate: RFC 1918, CGNAT (the tunnel pool is
// in it), benchmarking, and IPv6 unique-local. They cover the Docker/VPC networks of the
// Edge host, the Control Plane and other internal services.
var privateRanges = mustPrefixes(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "198.18.0.0/15", "fc00::/7",
)

// dohIPs and dohDomains are well-known public DNS-over-HTTPS endpoints. HTTPS (tcp/udp 443)
// to them is blocked so clients fall back to the Edge resolver.
var dohIPs = map[netip.Addr]bool{}

var dohDomains = []string{"dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "doh.opendns.com"}

func init() {
	for _, s := range []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
		"208.67.222.222", "208.67.220.220",
		"2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
		"2620:fe::fe", "2620:fe::9",
	} {
		dohIPs[netip.MustParseAddr(s)] = true
	}
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// guard holds the built-in Edge rules. It is immutable after newGuard.
type guard struct {
	deny     []netip.Prefix
	blockDoH bool
}

// newGuard builds the deny list: alwaysDenied, privateRanges unless allowPrivate, extra
// (Config.DenyCIDRs) and the Edge's own interface addresses.
func newGuard(extra []netip.Prefix, local []netip.Addr, allowPrivate, blockDoH bool) *guard {
	g := &guard{blockDoH: blockDoH}
	g.deny = append(g.deny, alwaysDenied...)
	if !allowPrivate {
		g.deny = append(g.deny, privateRanges...)
	}
	for _, p := range extra {
		g.deny = append(g.deny, p.Masked())
	}
	for _, a := range local {
		a = a.Unmap()
		if a.IsValid() && a != EdgeIPv4 && a != EdgeIPv6 {
			g.deny = append(g.deny, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return g
}

// check returns a block decision if a built-in rule applies to an outbound tunnel flow to
// dst (already unmapped). Flows to the Edge's own tunnel address never reach it.
func (g *guard) check(dst netip.Addr, f policy.Flow) (policy.Decision, bool) {
	for _, p := range g.deny {
		if p.Contains(dst) {
			return policy.Decision{Action: policy.ActionBlock, RuleID: RuleBuiltinDeny, Layer: LayerEdge, Log: true}, true
		}
	}
	if f.Protocol == "tcp" || f.Protocol == "udp" {
		bypass := f.DstPort == dnsPort || f.DstPort == dotPort ||
			(g.blockDoH && f.DstPort == httpsPort && (dohIPs[dst] || isDoHDomain(f.Domain)))
		if bypass {
			return policy.Decision{Action: policy.ActionBlock, RuleID: RuleDNSBypass, Layer: LayerEdge, Log: true}, true
		}
	}
	return policy.Decision{}, false
}

func isDoHDomain(d string) bool {
	if d == "" {
		return false
	}
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	for _, s := range dohDomains {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}
