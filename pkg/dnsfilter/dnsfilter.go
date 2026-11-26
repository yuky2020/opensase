// Package dnsfilter is the Client DNS interceptor (ADR-0012). It decides DNS
// queries against the Policy Snapshot, synthesises block responses as ready-to-inject IP
// packets, and snoops DNS responses coming back through the tunnel to learn which domain
// an IP address belongs to (used to fill policy.Flow.Domain for domain rules).
package dnsfilter

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/policy"
)

// Defaults for Config.
const (
	DefaultMaxEntries = 8192
	DefaultMinTTL     = 30 * time.Second
	DefaultMaxTTL     = 24 * time.Hour
	blockAnswerTTL    = 60 // seconds, TTL of synthesised 0.0.0.0 / :: answers

	// DefaultMaxPending bounds the outstanding-query table used to match responses.
	DefaultMaxPending = 4096
	// DefaultQueryTimeout is how long a forwarded query waits for its response.
	DefaultQueryTimeout = 10 * time.Second

	maxDNSTimes = 256
)

// ErrNotQuery is returned for DNS messages that are not a single-question standard query.
var ErrNotQuery = errors.New("dnsfilter: not a standard query")

// Config configures an Interceptor. Zero values select the defaults.
type Config struct {
	MaxEntries int           // IP->domain cache size (LRU)
	MinTTL     time.Duration // cache TTL floor
	MaxTTL     time.Duration // cache TTL ceiling
	// MaxPending bounds outstanding queries; when full, new queries are still forwarded
	// but their responses are not snooped.
	MaxPending   int
	QueryTimeout time.Duration // lifetime of an outstanding query
	Now          func() time.Time
}

// queryKey identifies one outstanding query: a response must come from server to the
// client address and port the query came from, with the same transaction ID.
type queryKey struct {
	client, server netip.AddrPort
	id             uint16
}

type pendingQuery struct {
	name    string // normalized qname
	seen    time.Time
	expires time.Time
}

// Interceptor is safe for concurrent use.
type Interceptor struct {
	cfg   Config
	cache *domainCache

	mu       sync.Mutex
	stats    map[string]*AppStats
	pending  map[queryKey]pendingQuery
	dnsTimes []time.Duration
}

// AppStats counts DNS queries per app ("" = unknown app).
type AppStats struct {
	App     string `json:"app"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

// QueryResult is the outcome of HandleQuery.
type QueryResult struct {
	Name     string // lowercase, no trailing dot
	QType    uint16
	Blocked  bool
	ListID   string // blocklist id, "" if not from a list
	Response []byte // full IP+UDP packet to write to the TUN; nil if not blocked
}

// New returns an Interceptor.
func New(cfg Config) *Interceptor {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = DefaultMinTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = DefaultMaxTTL
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = DefaultMaxPending
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = DefaultQueryTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Interceptor{
		cfg: cfg, cache: newDomainCache(cfg.MaxEntries),
		stats: make(map[string]*AppStats), pending: make(map[queryKey]pendingQuery),
	}
}

// NormalizeName lowercases a DNS name and strips the trailing dot.
func NormalizeName(n string) string {
	return strings.ToLower(strings.TrimSuffix(n, "."))
}

// HandleQuery decides the DNS query in payload (UDP payload sent by app from src to dst).
// If the compiled policy blocks the name, Response holds the synthesised answer from dst
// back to src. A nil policy never blocks (the firewall is responsible for fail-closed when
// there is no snapshot). A forwarded (not blocked) query is remembered so that only its
// response is snooped (see SnoopResponse).
func (i *Interceptor) HandleQuery(c *policy.Compiled, app string, src, dst netip.AddrPort, payload []byte) (QueryResult, error) {
	var req dns.Msg
	if err := req.Unpack(payload); err != nil {
		return QueryResult{}, fmt.Errorf("dnsfilter: unpack query: %w", err)
	}
	if req.Response || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		return QueryResult{}, ErrNotQuery
	}
	q := req.Question[0]
	res := QueryResult{Name: NormalizeName(q.Name), QType: q.Qtype}
	if c != nil {
		res.Blocked, res.ListID = c.EvaluateDNS(res.Name)
	}
	i.count(app, res.Blocked)
	if !res.Blocked {
		i.remember(queryKey{client: unmapAP(src), server: unmapAP(dst), id: req.Id}, res.Name)
		return res, nil
	}
	zero := c.BlockResponse() == "zero"
	resp, err := blockResponse(&req, zero)
	if err != nil {
		return res, err
	}
	res.Response, err = buildUDPPacket(dst, src, resp)
	return res, err
}

// blockResponse builds the packed DNS block answer for req.
func blockResponse(req *dns.Msg, zero bool) ([]byte, error) {
	m := new(dns.Msg)
	q := req.Question[0]
	switch {
	case zero && q.Qtype == dns.TypeA:
		m.SetReply(req)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: blockAnswerTTL},
			A:   []byte{0, 0, 0, 0},
		}}
	case zero && q.Qtype == dns.TypeAAAA:
		m.SetReply(req)
		m.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: blockAnswerTTL},
			AAAA: make([]byte, 16),
		}}
	case zero:
		m.SetReply(req) // NODATA for other types
	default:
		m.SetRcode(req, dns.RcodeNameError)
	}
	m.RecursionAvailable = true
	return m.Pack()
}

// SnoopResponse learns IP->name mappings from a DNS response sent by server to client.
// The response is only used if it answers an outstanding query from HandleQuery: same
// client address and port, same server, same transaction ID and the same question name.
// The outstanding query is consumed, so a second (spoofed or duplicate) response is
// ignored. A/AAAA records anywhere in a CNAME chain are mapped to the queried name. It
// returns the number of addresses learned.
func (i *Interceptor) SnoopResponse(server, client netip.AddrPort, payload []byte) int {
	var m dns.Msg
	if err := m.Unpack(payload); err != nil || !m.Response || len(m.Question) != 1 {
		return 0
	}
	now := i.cfg.Now()
	key := queryKey{client: unmapAP(client), server: unmapAP(server), id: m.Id}
	name := NormalizeName(m.Question[0].Name)
	i.mu.Lock()
	pq, ok := i.pending[key]
	matched := ok && pq.name == name && now.Before(pq.expires) && name != ""
	if ok && pq.name == name {
		delete(i.pending, key)
	}
	if matched {
		d := max(0, now.Sub(pq.seen))
		i.recordDNSTimeLocked(d)
	}
	i.mu.Unlock()
	if !matched || m.Rcode != dns.RcodeSuccess {
		return 0
	}
	n := 0
	for _, rr := range m.Answer {
		var ip netip.Addr
		var ok bool
		switch r := rr.(type) {
		case *dns.A:
			ip, ok = netip.AddrFromSlice(r.A.To4())
		case *dns.AAAA:
			ip, ok = netip.AddrFromSlice(r.AAAA.To16())
		default:
			continue
		}
		if !ok || ip.IsUnspecified() {
			continue
		}
		ttl := time.Duration(rr.Header().Ttl) * time.Second
		ttl = max(i.cfg.MinTTL, min(ttl, i.cfg.MaxTTL))
		i.cache.put(ip, name, now.Add(ttl))
		n++
	}
	return n
}

// recordDNSTimeLocked adds d to dnsTimes, keeping at most maxDNSTimes and dropping the oldest.
// Caller must hold mu.
func (i *Interceptor) recordDNSTimeLocked(d time.Duration) {
	if len(i.dnsTimes) < maxDNSTimes {
		i.dnsTimes = append(i.dnsTimes, d)
		return
	}
	copy(i.dnsTimes, i.dnsTimes[1:])
	i.dnsTimes[len(i.dnsTimes)-1] = d
}

// TakeDNSTimes returns and clears the recorded DNS resolution durations.
// It is safe for concurrent use.
func (i *Interceptor) TakeDNSTimes() []time.Duration {
	i.mu.Lock()
	defer i.mu.Unlock()
	times := i.dnsTimes
	i.dnsTimes = nil
	return times
}

// remember records an outstanding query. When the table is full, expired entries are
// purged; if it is still full the query is not recorded (its response will not be snooped).
func (i *Interceptor) remember(k queryKey, name string) {
	now := i.cfg.Now()
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.pending) >= i.cfg.MaxPending {
		for k, q := range i.pending {
			if !now.Before(q.expires) {
				delete(i.pending, k)
			}
		}
		if len(i.pending) >= i.cfg.MaxPending {
			return
		}
	}
	i.pending[k] = pendingQuery{name: name, seen: now, expires: now.Add(i.cfg.QueryTimeout)}
}

// PendingLen returns the number of outstanding queries.
func (i *Interceptor) PendingLen() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.pending)
}

func unmapAP(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

// Domain returns the snooped domain for ip, or "" if unknown or expired.
func (i *Interceptor) Domain(ip netip.Addr) string {
	name, _ := i.cache.get(ip, i.cfg.Now())
	return name
}

// CacheLen returns the number of cached IP->domain entries.
func (i *Interceptor) CacheLen() int { return i.cache.len() }

func (i *Interceptor) count(app string, blocked bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	s, ok := i.stats[app]
	if !ok {
		s = &AppStats{App: app}
		i.stats[app] = s
	}
	s.Queries++
	if blocked {
		s.Blocked++
	}
}

// Stats returns per-app DNS counters sorted by app.
func (i *Interceptor) Stats() []AppStats {
	i.mu.Lock()
	out := make([]AppStats, 0, len(i.stats))
	for _, s := range i.stats {
		out = append(out, *s)
	}
	i.mu.Unlock()
	sort.Slice(out, func(a, b int) bool { return out[a].App < out[b].App })
	return out
}
