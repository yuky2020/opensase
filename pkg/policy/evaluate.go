package policy

import (
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// CurrentSchemaVersion is the only Snapshot schema version this package accepts.
const CurrentSchemaVersion = 1

// AlgEd25519 is the only Envelope algorithm accepted today.
const AlgEd25519 = "ed25519"

// Decision layers.
const (
	LayerTenant   = "tenant"
	LayerUser     = "user"
	LayerApp      = "app"
	LayerLockdown = "lockdown"
	LayerZTNA     = "ztna"
	LayerDefault  = "default"
	LayerCloud    = "cloud"
)

// ListIDCustom is the listID EvaluateDNS returns for DNSPolicy.BlockDomains.
const ListIDCustom = "custom"

// Errors returned by Verify. Compile returns wrapped *ValidationError values.
var (
	ErrBadAlgorithm   = errors.New("policy: unsupported envelope algorithm")
	ErrUnknownKey     = errors.New("policy: unknown signing key")
	ErrBadSignature   = errors.New("policy: invalid snapshot signature")
	ErrSchemaVersion  = errors.New("policy: unsupported schema version")
	ErrMissingSubject = errors.New("policy: snapshot has empty tenantId or deviceId")
)

// ValidationError describes why Compile rejected a Snapshot.
type ValidationError struct {
	Field string // e.g. "firewall.rules[3].match.cidrs[0]"
	Msg   string
}

func (e *ValidationError) Error() string {
	return "policy: invalid " + e.Field + ": " + e.Msg
}

func verr(field, format string, args ...any) error {
	return &ValidationError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// protocol bits
const (
	protoTCP uint8 = 1 << iota
	protoUDP
	protoICMP
	protoICMPv6
)

// maxLabels bounds the number of labels in a valid DNS name (253 chars => at most 127 labels).
const maxLabels = 128

// maxNameLen is the maximum length of a DNS name without the trailing dot.
const maxNameLen = 253

// Compiled is an immutable, pre-processed Snapshot ready for evaluation. It is safe for
// concurrent use; swap whole values with atomic.Pointer[Compiled] when a new Snapshot arrives.
type Compiled struct {
	version        uint64
	blockResponse  string
	defaultAction  Action
	lockdown       bool
	tenantRules    []compiledRule
	userRules      []compiledRule // empty when !AllowUserRules
	apps           map[string]compiledApp
	ruleDomains    domainIndex // pattern -> pattern ID, for rule Domains
	hasDomainRules bool

	dnsAllow domainSet // AllowDomains
	dnsBlock domainSet // BlockDomains
	dnsLists domainSet // all blocklists; value = listID

	privateApps []compiledPrivateApp
	appIndex    appIndex // PrivateApp domain pattern -> indexes into privateApps
}

// compiledPrivateApp is a PrivateApp with normalized ports and a precomputed rule ID.
type compiledPrivateApp struct {
	app    PrivateApp // Ports normalized (To >= From); Domains as given
	ruleID string     // "ztna:<id>"
}

// appIndex maps exact and suffix patterns to the PrivateApps that list them, in snapshot order.
type appIndex struct {
	exact  map[string][]int32
	suffix map[string][]int32 // "*.example.com" stored as "example.com"
}

type compiledRule struct {
	id         string
	action     Action
	log        bool
	deviceOnly bool // has Apps or Networks: skipped in edge mode
	protos     uint8
	apps       []string
	networks   []NetworkType
	prefixes   []netip.Prefix
	ports      []PortRange // normalized: To >= From
	domainIDs  []int32     // sorted pattern IDs; nil = any domain
}

type compiledApp struct {
	wifi, cellular, roaming Action
	ruleID                  string // "app:<pkg>"
	// userSourced marks an entry that is not listed in FirewallPolicy.TenantApps, i.e. it
	// comes from the user layer. Under Lockdown only tenant entries may allow (or ask);
	// user entries can only block (ADR-0012, review D1). Computed once in Compile.
	userSourced bool
}

// domainIndex assigns IDs to exact and suffix patterns.
type domainIndex struct {
	exact  map[string]int32
	suffix map[string]int32 // "*.example.com" stored as "example.com"
}

// domainSet maps exact and suffix patterns to a value (a list ID, or "" for plain sets).
type domainSet struct {
	exact  map[string]string
	suffix map[string]string
}

// Version returns the Snapshot version this was compiled from.
func (c *Compiled) Version() uint64 { return c.version }

// BlockResponse returns DNSPolicy.BlockResponse, defaulting to "nxdomain".
func (c *Compiled) BlockResponse() string {
	if c.blockResponse == "" {
		return "nxdomain"
	}
	return c.blockResponse
}

// Compile validates s and builds its evaluation form. s is not retained or modified.
func Compile(s *Snapshot) (*Compiled, error) {
	if s == nil {
		return nil, verr("snapshot", "nil")
	}
	if s.SchemaVersion != CurrentSchemaVersion {
		return nil, verr("schemaVersion", "got %d, want %d", s.SchemaVersion, CurrentSchemaVersion)
	}
	fw := &s.Firewall
	if !validAction(fw.DefaultAction) {
		return nil, verr("firewall.defaultAction", "invalid action %q", fw.DefaultAction)
	}
	c := &Compiled{
		version:       s.Version,
		defaultAction: fw.DefaultAction,
		lockdown:      fw.Lockdown,
		apps:          make(map[string]compiledApp, len(fw.Apps)),
		ruleDomains:   domainIndex{exact: map[string]int32{}, suffix: map[string]int32{}},
	}

	var tenant, user []compiledRule
	for i := range fw.Rules {
		r := &fw.Rules[i]
		field := fmt.Sprintf("firewall.rules[%d]", i)
		cr, err := c.compileRule(r, field)
		if err != nil {
			return nil, err
		}
		switch r.Source {
		case SourceTenant:
			tenant = append(tenant, cr)
		case SourceUser:
			user = append(user, cr)
		default:
			return nil, verr(field+".source", "invalid source %q", r.Source)
		}
	}
	// Stable sort keeps the snapshot order for equal priorities. The priority is read from
	// a side slice to avoid storing it in compiledRule.
	c.tenantRules = sortByPriority(tenant, fw.Rules, SourceTenant)
	if fw.AllowUserRules {
		c.userRules = sortByPriority(user, fw.Rules, SourceUser)
		if fw.Lockdown {
			// Tenant mandates are absolute (ADR-0012, review D1): under Lockdown the user
			// layer can only restrict, so user allow and ask rules are dropped. Filtering
			// happens after sorting because sortByPriority aligns priorities by index.
			c.userRules = slices.DeleteFunc(c.userRules, func(r compiledRule) bool { return r.action != ActionBlock })
		}
	}

	tenantApps := make(map[string]struct{}, len(fw.TenantApps))
	for i, pkg := range fw.TenantApps {
		if pkg == "" {
			return nil, verr(fmt.Sprintf("firewall.tenantApps[%d]", i), "empty package name")
		}
		tenantApps[pkg] = struct{}{}
	}
	for pkg, ap := range fw.Apps {
		field := "firewall.apps[" + pkg + "]"
		if pkg == "" {
			return nil, verr(field, "empty package name")
		}
		for _, a := range []Action{ap.WiFi, ap.Cellular, ap.Roaming} {
			if a != "" && !validAction(a) {
				return nil, verr(field, "invalid action %q", a)
			}
		}
		_, tenant := tenantApps[pkg]
		c.apps[pkg] = compiledApp{wifi: ap.WiFi, cellular: ap.Cellular, roaming: ap.Roaming, ruleID: "app:" + pkg, userSourced: !tenant}
	}

	dns := &s.DNS
	switch dns.BlockResponse {
	case "", "nxdomain", "zero":
		c.blockResponse = dns.BlockResponse
	default:
		return nil, verr("dns.blockResponse", "invalid value %q", dns.BlockResponse)
	}
	var err error
	if c.dnsAllow, err = buildSet(dns.AllowDomains, "", "dns.allowDomains"); err != nil {
		return nil, err
	}
	if c.dnsBlock, err = buildSet(dns.BlockDomains, ListIDCustom, "dns.blockDomains"); err != nil {
		return nil, err
	}
	total := 0
	for _, bl := range dns.Blocklists {
		total += len(bl.Domains)
	}
	c.dnsLists = domainSet{exact: make(map[string]string, total), suffix: map[string]string{}}
	for i, bl := range dns.Blocklists {
		field := fmt.Sprintf("dns.blocklists[%d]", i)
		if bl.ID == "" {
			return nil, verr(field+".id", "empty")
		}
		for j, d := range bl.Domains {
			if err := c.dnsLists.add(d, bl.ID, fmt.Sprintf("%s.domains[%d]", field, j)); err != nil {
				return nil, err
			}
		}
	}
	if err := c.compilePrivateApps(s.PrivateApps); err != nil {
		return nil, err
	}
	return c, nil
}

// compilePrivateApps validates the ZTNA apps (ADR-0013): non-empty unique IDs, valid domain
// patterns (at least one), valid port ranges. Empty Ports is valid and grants no access.
func (c *Compiled) compilePrivateApps(apps []PrivateApp) error {
	if len(apps) == 0 {
		return nil
	}
	c.privateApps = make([]compiledPrivateApp, 0, len(apps))
	c.appIndex = appIndex{exact: map[string][]int32{}, suffix: map[string][]int32{}}
	seen := make(map[string]struct{}, len(apps))
	for i := range apps {
		a := &apps[i]
		field := fmt.Sprintf("privateApps[%d]", i)
		if a.ID == "" {
			return verr(field+".id", "empty")
		}
		if _, dup := seen[a.ID]; dup {
			return verr(field+".id", "duplicate id %q", a.ID)
		}
		seen[a.ID] = struct{}{}
		if len(a.Domains) == 0 {
			return verr(field+".domains", "empty")
		}
		ca := compiledPrivateApp{app: *a, ruleID: "ztna:" + a.ID}
		ca.app.Domains = slices.Clone(a.Domains)
		ca.app.Ports = make([]PortRange, 0, len(a.Ports))
		for j, pr := range a.Ports {
			to := pr.To
			if to == 0 {
				to = pr.From
			}
			if to < pr.From {
				return verr(fmt.Sprintf("%s.ports[%d]", field, j), "to %d < from %d", to, pr.From)
			}
			ca.app.Ports = append(ca.app.Ports, PortRange{From: pr.From, To: to})
		}
		idx := int32(len(c.privateApps))
		for j, d := range a.Domains {
			name, wildcard, err := normalizePattern(d)
			if err != nil {
				return verr(fmt.Sprintf("%s.domains[%d]", field, j), "%v", err)
			}
			m := c.appIndex.exact
			if wildcard {
				m = c.appIndex.suffix
			}
			if l := m[name]; len(l) == 0 || l[len(l)-1] != idx {
				m[name] = append(l, idx)
			}
		}
		c.privateApps = append(c.privateApps, ca)
	}
	return nil
}

func sortByPriority(rules []compiledRule, src []Rule, source RuleSource) []compiledRule {
	if len(rules) == 0 {
		return nil
	}
	prio := make([]int, 0, len(rules))
	for i := range src {
		if src[i].Source == source {
			prio = append(prio, src[i].Priority)
		}
	}
	idx := make([]int, len(rules))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int { return cmp.Compare(prio[a], prio[b]) })
	out := make([]compiledRule, len(rules))
	for i, j := range idx {
		out[i] = rules[j]
	}
	return out
}

func (c *Compiled) compileRule(r *Rule, field string) (compiledRule, error) {
	if r.ID == "" {
		return compiledRule{}, verr(field+".id", "empty")
	}
	if !validAction(r.Action) {
		return compiledRule{}, verr(field+".action", "invalid action %q", r.Action)
	}
	m := &r.Match
	cr := compiledRule{
		id:         r.ID,
		action:     r.Action,
		log:        r.Log,
		deviceOnly: len(m.Apps) > 0 || len(m.Networks) > 0,
	}
	for i, a := range m.Apps {
		if a == "" {
			return compiledRule{}, verr(fmt.Sprintf("%s.match.apps[%d]", field, i), "empty")
		}
	}
	cr.apps = slices.Clone(m.Apps)
	for i, n := range m.Networks {
		switch n {
		case NetworkWiFi, NetworkCellular, NetworkRoaming, NetworkEthernet, NetworkUnknown:
		default:
			return compiledRule{}, verr(fmt.Sprintf("%s.match.networks[%d]", field, i), "invalid network %q", n)
		}
	}
	cr.networks = slices.Clone(m.Networks)
	for i, p := range m.Protocols {
		switch strings.ToLower(p) {
		case "tcp":
			cr.protos |= protoTCP
		case "udp":
			cr.protos |= protoUDP
		case "icmp": // matches ICMPv4 and ICMPv6
			cr.protos |= protoICMP | protoICMPv6
		case "icmpv6":
			cr.protos |= protoICMPv6
		default:
			return compiledRule{}, verr(fmt.Sprintf("%s.match.protocols[%d]", field, i), "invalid protocol %q", p)
		}
	}
	for i, s := range m.CIDRs {
		p, err := parsePrefix(s)
		if err != nil {
			return compiledRule{}, verr(fmt.Sprintf("%s.match.cidrs[%d]", field, i), "%v", err)
		}
		cr.prefixes = append(cr.prefixes, p)
	}
	for i, pr := range m.Ports {
		to := pr.To
		if to == 0 {
			to = pr.From
		}
		if to < pr.From {
			return compiledRule{}, verr(fmt.Sprintf("%s.match.ports[%d]", field, i), "to %d < from %d", to, pr.From)
		}
		cr.ports = append(cr.ports, PortRange{From: pr.From, To: to})
	}
	for i, d := range m.Domains {
		name, wildcard, err := normalizePattern(d)
		if err != nil {
			return compiledRule{}, verr(fmt.Sprintf("%s.match.domains[%d]", field, i), "%v", err)
		}
		cr.domainIDs = append(cr.domainIDs, c.ruleDomains.id(name, wildcard))
	}
	if len(cr.domainIDs) > 0 {
		slices.Sort(cr.domainIDs)
		cr.domainIDs = slices.Compact(cr.domainIDs)
		c.hasDomainRules = true
	}
	return cr, nil
}

func (ix *domainIndex) id(name string, wildcard bool) int32 {
	m := ix.exact
	if wildcard {
		m = ix.suffix
	}
	if id, ok := m[name]; ok {
		return id
	}
	id := int32(len(ix.exact) + len(ix.suffix))
	m[name] = id
	return id
}

func buildSet(domains []string, value, field string) (domainSet, error) {
	s := domainSet{exact: make(map[string]string, len(domains)), suffix: map[string]string{}}
	for i, d := range domains {
		if err := s.add(d, value, fmt.Sprintf("%s[%d]", field, i)); err != nil {
			return domainSet{}, err
		}
	}
	return s, nil
}

// add inserts a pattern; the first value inserted for a pattern wins.
func (s *domainSet) add(pattern, value, field string) error {
	name, wildcard, err := normalizePattern(pattern)
	if err != nil {
		return verr(field, "%v", err)
	}
	m := s.exact
	if wildcard {
		m = s.suffix
	}
	if _, ok := m[name]; !ok {
		m[name] = value
	}
	return nil
}

func validAction(a Action) bool {
	return a == ActionAllow || a == ActionBlock || a == ActionAsk
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Zone() != "" {
			return netip.Prefix{}, errors.New("zones not allowed")
		}
		if p.Addr().Is4In6() {
			// Store v4-mapped prefixes as plain IPv4 so they match unmapped flows.
			bits := p.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, errors.New("v4-mapped prefix shorter than /96")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), bits)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if a.Zone() != "" {
		return netip.Prefix{}, errors.New("zones not allowed")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// normalizePattern lowercases a domain pattern, strips one trailing dot, splits off a leading
// "*." and validates the remaining name.
func normalizePattern(p string) (name string, wildcard bool, err error) {
	p = strings.ToLower(strings.TrimSuffix(p, "."))
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		p, wildcard = rest, true
	}
	if err := validName(p); err != nil {
		return "", false, err
	}
	return p, wildcard, nil
}

// validName checks a lowercase name without trailing dot: 1..253 chars, labels of 1..63
// chars from [a-z0-9_-], no label starting or ending with '-'.
func validName(s string) error {
	if s == "" {
		return errors.New("empty domain")
	}
	if len(s) > maxNameLen {
		return errors.New("domain longer than 253 characters")
	}
	label := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if label == 0 {
				return fmt.Errorf("empty label in %q", s)
			}
			if s[i-1] == '-' || s[i-label] == '-' {
				return fmt.Errorf("label starts or ends with '-' in %q", s)
			}
			label = 0
			continue
		}
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return fmt.Errorf("invalid character %q in %q", ch, s)
		}
		label++
		if label > 63 {
			return fmt.Errorf("label longer than 63 characters in %q", s)
		}
	}
	return nil
}

// nameBuf holds a normalized query name on the stack.
type nameBuf struct {
	b [maxNameLen]byte
	n int
}

// load lowercases s into the buffer and strips one trailing dot. It reports false when s
// cannot be a valid name (empty or too long).
func (nb *nameBuf) load(s string) bool {
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		nb.b[i] = ch
	}
	nb.n = len(s)
	return true
}

// lookup returns the value for the most specific pattern matching the name: exact match on
// the full name first, then suffix patterns from the longest to the shortest.
func (s *domainSet) lookup(nb *nameBuf) (string, bool) {
	name := nb.b[:nb.n]
	if v, ok := s.exact[string(name)]; ok {
		return v, true
	}
	if len(s.suffix) == 0 {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		if i == 0 || name[i-1] == '.' {
			if v, ok := s.suffix[string(name[i:])]; ok {
				return v, true
			}
		}
	}
	return "", false
}

// EvaluateDNS reports whether a DNS query for name is blocked and by which list. AllowDomains
// override everything, then BlockDomains (listID "custom"), then the blocklists in order.
// name may be mixed case and may carry a trailing dot.
func (c *Compiled) EvaluateDNS(name string) (blocked bool, listID string) {
	var nb nameBuf
	if !nb.load(name) {
		return false, ""
	}
	if _, ok := c.dnsAllow.lookup(&nb); ok {
		return false, ""
	}
	if id, ok := c.dnsBlock.lookup(&nb); ok {
		return true, id
	}
	if id, ok := c.dnsLists.lookup(&nb); ok {
		return true, id
	}
	return false, ""
}

// flowCtx is the per-flow precomputed state used by rule matching.
type flowCtx struct {
	f        *Flow
	proto    uint8
	ip       netip.Addr // invalid when DstIP is empty or unparsable
	nDomains int
	domains  [maxLabels]int32 // pattern IDs matched by f.Domain, unsorted
}

func flowProto(p string) uint8 {
	switch {
	case strings.EqualFold(p, "tcp"):
		return protoTCP
	case strings.EqualFold(p, "udp"):
		return protoUDP
	case strings.EqualFold(p, "icmp"):
		return protoICMP
	case strings.EqualFold(p, "icmpv6"):
		return protoICMPv6
	}
	return 0
}

// Evaluate returns the verdict for a new flow. Precedence: tenant rules, then user rules (if
// the snapshot allows them), then the per-app policy for the flow's network (roaming falls
// back to cellular), then lockdown, then the ZTNA private apps (TCP flows with a Domain whose
// name and port match an entitled app: allow, RuleID "ztna:<id>"), then the default action.
// First match wins in each rule layer. In edgeMode, rules with Apps or Networks are skipped,
// as are the app and lockdown layers; the ZTNA layer applies in both modes. Evaluate does
// not allocate.
func (c *Compiled) Evaluate(f Flow, edgeMode bool) Decision {
	fc := flowCtx{f: &f, proto: flowProto(f.Protocol)}
	if f.DstIP != "" {
		if ip, err := netip.ParseAddr(f.DstIP); err == nil {
			fc.ip = ip.Unmap()
		}
	}
	if c.hasDomainRules && f.Domain != "" {
		c.matchDomains(&fc)
	}

	if d, ok := matchRules(c.tenantRules, &fc, edgeMode, LayerTenant); ok {
		return d
	}
	if d, ok := matchRules(c.userRules, &fc, edgeMode, LayerUser); ok {
		return d
	}
	if !edgeMode {
		if app, ok := c.apps[f.App]; ok && f.App != "" {
			var a Action
			switch f.Network {
			case NetworkWiFi:
				a = app.wifi
			case NetworkCellular:
				a = app.cellular
			case NetworkRoaming:
				a = app.roaming
				if a == "" {
					a = app.cellular
				}
			}
			if c.lockdown && app.userSourced && a != ActionBlock {
				a = "" // a user per-app allow/ask does not count under Lockdown
			}
			if a != "" {
				return Decision{Action: a, RuleID: app.ruleID, Layer: LayerApp}
			}
		}
		if c.lockdown {
			return Decision{Action: ActionBlock, RuleID: LayerLockdown, Layer: LayerLockdown}
		}
	}
	// ZTNA layer (ADR-0013): an entitled private app, by name and TCP port.
	if len(c.privateApps) > 0 && fc.proto == protoTCP && f.Domain != "" {
		if i, ok := c.privateAppIndex(f.Domain, f.DstPort, true); ok {
			return Decision{Action: ActionAllow, RuleID: c.privateApps[i].ruleID, Layer: LayerZTNA}
		}
	}
	return Decision{Action: c.defaultAction, Layer: LayerDefault}
}

// PrivateApp returns the private app whose Domains match name (Match.Domains semantics:
// exact, or "*.x" for x and every name below it; case-insensitive; one trailing dot
// ignored). The exact pattern wins over suffixes, the longest suffix over shorter ones, and
// the first app in snapshot order among apps listing the same pattern. The returned value
// shares its slices with c and must not be modified.
func (c *Compiled) PrivateApp(name string) (PrivateApp, bool) {
	if i, ok := c.privateAppIndex(name, 0, false); ok {
		return c.privateApps[i].app, true
	}
	return PrivateApp{}, false
}

// PrivateAppAccess is PrivateApp restricted to apps that also list port in Ports: the most
// specific matching pattern whose apps include one with the port wins. An app with empty
// Ports never grants access. The returned value must not be modified.
func (c *Compiled) PrivateAppAccess(name string, port uint16) (PrivateApp, bool) {
	if i, ok := c.privateAppIndex(name, port, true); ok {
		return c.privateApps[i].app, true
	}
	return PrivateApp{}, false
}

// privateAppIndex finds the app for name (and port, if checkPort). It does not allocate.
func (c *Compiled) privateAppIndex(name string, port uint16, checkPort bool) (int32, bool) {
	if len(c.privateApps) == 0 {
		return 0, false
	}
	var nb nameBuf
	if !nb.load(name) {
		return 0, false
	}
	n := nb.b[:nb.n]
	if i, ok := c.pickApp(c.appIndex.exact[string(n)], port, checkPort); ok {
		return i, true
	}
	if len(c.appIndex.suffix) == 0 {
		return 0, false
	}
	for i := 0; i < len(n); i++ {
		if i == 0 || n[i-1] == '.' {
			if j, ok := c.pickApp(c.appIndex.suffix[string(n[i:])], port, checkPort); ok {
				return j, true
			}
		}
	}
	return 0, false
}

func (c *Compiled) pickApp(cands []int32, port uint16, checkPort bool) (int32, bool) {
	for _, i := range cands {
		if !checkPort {
			return i, true
		}
		for _, p := range c.privateApps[i].app.Ports {
			if port >= p.From && port <= p.To {
				return i, true
			}
		}
	}
	return 0, false
}

// matchDomains fills fc.domains with the IDs of every rule pattern that matches f.Domain.
func (c *Compiled) matchDomains(fc *flowCtx) {
	var nb nameBuf
	if !nb.load(fc.f.Domain) {
		return
	}
	name := nb.b[:nb.n]
	if id, ok := c.ruleDomains.exact[string(name)]; ok {
		fc.domains[fc.nDomains] = id
		fc.nDomains++
	}
	if len(c.ruleDomains.suffix) == 0 {
		return
	}
	for i := 0; i < len(name) && fc.nDomains < maxLabels; i++ {
		if i == 0 || name[i-1] == '.' {
			if id, ok := c.ruleDomains.suffix[string(name[i:])]; ok {
				fc.domains[fc.nDomains] = id
				fc.nDomains++
			}
		}
	}
}

func matchRules(rules []compiledRule, fc *flowCtx, edgeMode bool, layer string) (Decision, bool) {
	for i := range rules {
		r := &rules[i]
		if edgeMode && r.deviceOnly {
			continue
		}
		if r.matches(fc) {
			return Decision{Action: r.action, RuleID: r.id, Layer: layer, Log: r.log}, true
		}
	}
	return Decision{}, false
}

func (r *compiledRule) matches(fc *flowCtx) bool {
	f := fc.f
	if r.protos != 0 && r.protos&fc.proto == 0 {
		return false
	}
	if len(r.ports) > 0 {
		if fc.proto != protoTCP && fc.proto != protoUDP {
			return false
		}
		ok := false
		for _, p := range r.ports {
			if f.DstPort >= p.From && f.DstPort <= p.To {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.prefixes) > 0 {
		if !fc.ip.IsValid() {
			return false
		}
		ok := false
		for _, p := range r.prefixes {
			if p.Contains(fc.ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.apps) > 0 && (f.App == "" || !slices.Contains(r.apps, f.App)) {
		return false
	}
	if len(r.networks) > 0 && (f.Network == "" || !slices.Contains(r.networks, f.Network)) {
		return false
	}
	if len(r.domainIDs) > 0 {
		ok := false
		for _, id := range fc.domains[:fc.nDomains] {
			if _, found := slices.BinarySearch(r.domainIDs, id); found {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Sign validates s, marshals it and signs the JSON bytes with priv.
func Sign(s *Snapshot, keyID string, priv ed25519.PrivateKey) (*Envelope, error) {
	if keyID == "" {
		return nil, errors.New("policy: empty key ID")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("policy: invalid ed25519 private key")
	}
	if _, err := Compile(s); err != nil {
		return nil, err
	}
	if s.TenantID == "" || s.DeviceID == "" {
		return nil, ErrMissingSubject
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal snapshot: %w", err)
	}
	return &Envelope{
		KeyID:     keyID,
		Algorithm: AlgEd25519,
		Payload:   payload,
		Signature: ed25519.Sign(priv, payload),
	}, nil
}

// Verify checks the envelope signature over the exact Payload bytes and only then decodes the
// Snapshot. An expired snapshot is not an error; use Snapshot.Stale. The returned Snapshot is
// not compiled; call Compile before use.
func Verify(e *Envelope, pub map[string]ed25519.PublicKey) (*Snapshot, error) {
	if e == nil {
		return nil, errors.New("policy: nil envelope")
	}
	if e.Algorithm != AlgEd25519 {
		return nil, fmt.Errorf("%w: %q", ErrBadAlgorithm, e.Algorithm)
	}
	key, ok := pub[e.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, e.KeyID)
	}
	if len(e.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, e.Payload, e.Signature) {
		return nil, ErrBadSignature
	}
	var s Snapshot
	if err := json.Unmarshal(e.Payload, &s); err != nil {
		return nil, fmt.Errorf("policy: decode snapshot: %w", err)
	}
	if s.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("%w: %d", ErrSchemaVersion, s.SchemaVersion)
	}
	if s.TenantID == "" || s.DeviceID == "" {
		return nil, ErrMissingSubject
	}
	return &s, nil
}

// Stale reports whether the snapshot has expired at now. A zero ExpiresAt counts as stale.
// A stale snapshot is still enforced; the device only reports it.
func (s *Snapshot) Stale(now time.Time) bool {
	return s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt)
}
