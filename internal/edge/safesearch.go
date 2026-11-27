package edge

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/safesearch"
)

// SafeSearch (ADR-0025). For devices whose policy turns it on, the Edge resolver answers
// covered search and video hostnames with a CNAME to the safe hostname of the provider, and
// flows to those hostnames (by TLS SNI or HTTP Host) must go to an address the Edge itself
// returned for a safe hostname: a hard-coded address or a cache filled elsewhere is reset.

const (
	safeIPLife    = 6 * time.Hour   // how long a safe address stays known
	safeWarmEvery = 5 * time.Minute // background refresh of the safe addresses
)

// safeTargets are refreshed in the background so that a restarted Edge knows them before the
// first query.
var safeTargets = []string{"forcesafesearch.google.com", "restrict.youtube.com", "strict.bing.com", "safe.duckduckgo.com"}

// safeIPs holds the addresses of the safe hostnames.
type safeIPs struct {
	mu sync.Mutex
	m  map[netip.Addr]time.Time
}

func newSafeIPs() *safeIPs { return &safeIPs{m: map[netip.Addr]time.Time{}} }

func (s *safeIPs) add(ip netip.Addr, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ip.Unmap()] = now.Add(safeIPLife)
	for a, exp := range s.m {
		if now.After(exp) {
			delete(s.m, a)
		}
	}
}

func (s *safeIPs) has(ip netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[ip.Unmap()]
	return ok && now.Before(exp)
}

// safeSearchDecision blocks a flow to a covered hostname whose address the Edge did not hand
// out for a safe hostname.
func (e *Edge) safeSearchDecision(c *policy.Compiled, host string, dst netip.Addr) (policy.Decision, bool) {
	if !c.SafeSearch() {
		return policy.Decision{}, false
	}
	if _, covered := safesearch.Target(host); !covered || e.safe.has(dst, time.Now()) {
		return policy.Decision{}, false
	}
	return policy.Decision{Action: policy.ActionBlock, RuleID: "safesearch:bypass", Layer: LayerWeb, Log: true}, true
}

// safeAnswer answers a covered name with a CNAME to target and target's own records. HTTPS
// and SVCB queries get only the CNAME: their address hints would point elsewhere.
func (rs *resolver) safeAnswer(ctx context.Context, w dns.ResponseWriter, req *dns.Msg, deviceID, name, target string, q dns.Question) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: dns.Fqdn(target)})
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		tq := new(dns.Msg)
		tq.SetQuestion(dns.Fqdn(target), q.Qtype)
		tq.RecursionDesired = true
		resp, _, err := rs.udp.ExchangeContext(ctx, tq, rs.upstream)
		if err != nil || resp == nil {
			fail := new(dns.Msg)
			fail.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(fail)
			return
		}
		now := time.Now()
		for _, rr := range resp.Answer {
			var ip netip.Addr
			switch v := rr.(type) {
			case *dns.A:
				ip, _ = netip.AddrFromSlice(v.A.To4())
			case *dns.AAAA:
				ip, _ = netip.AddrFromSlice(v.AAAA)
				ip = ip.Unmap()
			case *dns.CNAME:
				m.Answer = append(m.Answer, rr)
				continue
			default:
				continue
			}
			if ip.IsValid() {
				rs.e.safe.add(ip, now)
				rs.e.snoop.add(deviceID, ip, name, time.Duration(rr.Header().Ttl)*time.Second, now)
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	_ = w.WriteMsg(m)
}

// safeSearchLoop keeps the safe addresses fresh while any device has SafeSearch on.
func (e *Edge) safeSearchLoop(ctx context.Context) {
	c := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	t := time.NewTicker(safeWarmEvery)
	defer t.Stop()
	for {
		if e.anySafeSearch() {
			now := time.Now()
			for _, target := range safeTargets {
				for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn(target), qt)
					resp, _, err := c.ExchangeContext(ctx, m, e.cfg.Upstream)
					if err != nil || resp == nil {
						continue
					}
					for _, rr := range resp.Answer {
						switch v := rr.(type) {
						case *dns.A:
							if ip, ok := netip.AddrFromSlice(v.A.To4()); ok {
								e.safe.add(ip, now)
							}
						case *dns.AAAA:
							if ip, ok := netip.AddrFromSlice(v.AAAA); ok {
								e.safe.add(ip.Unmap(), now)
							}
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Edge) anySafeSearch() bool {
	e.reg.mu.Lock()
	defer e.reg.mu.Unlock()
	for _, d := range e.reg.devices {
		if c := d.compiled.Load(); c != nil && c.SafeSearch() {
			return true
		}
	}
	return false
}
