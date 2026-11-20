package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

// MergeLayers builds the firewall and DNS sections of a device Snapshot from the tenant layer
// and the user's layer:
//
//   - tenant rules are forced to Source=tenant;
//   - user rules are forced to Source=user and dropped entirely unless AllowUserRules;
//   - tenant Apps are mandatory: user Apps (only if AllowUserRules) add packages the tenant
//     did not set and never override a tenant entry (security review D1, ADR-0012); the
//     tenant's package names are listed, sorted, in FirewallPolicy.TenantApps;
//   - DefaultAction, AllowUserRules, Lockdown and DNS come from the tenant only.
//
// An empty DefaultAction fails closed (block). ur may be nil.
func MergeLayers(tp api.TenantPolicy, ur *api.UserRules) (policy.FirewallPolicy, policy.DNSPolicy) {
	fw := policy.FirewallPolicy{
		DefaultAction:  tp.DefaultAction,
		AllowUserRules: tp.AllowUserRules,
		Lockdown:       tp.Lockdown,
		Rules:          make([]policy.Rule, 0, len(tp.Rules)),
		Apps:           make(map[string]policy.AppPolicy, len(tp.Apps)),
	}
	if fw.DefaultAction == "" {
		fw.DefaultAction = policy.ActionBlock
	}
	for _, r := range tp.Rules {
		r.Source = policy.SourceTenant
		fw.Rules = append(fw.Rules, r)
	}
	maps.Copy(fw.Apps, tp.Apps)
	// TenantApps tells evaluators which per-app entries are tenant mandates (D1).
	if len(tp.Apps) > 0 {
		fw.TenantApps = slices.Sorted(maps.Keys(tp.Apps))
	}
	if tp.AllowUserRules && ur != nil {
		for _, r := range ur.Rules {
			r.Source = policy.SourceUser
			fw.Rules = append(fw.Rules, r)
		}
		for pkg, ap := range ur.Apps {
			if _, mandated := tp.Apps[pkg]; !mandated {
				fw.Apps[pkg] = ap
			}
		}
	}
	dns := tp.DNS
	if dns.BlockResponse == "" {
		dns.BlockResponse = "nxdomain"
	}
	return fw, dns
}

// validateTenantPolicy compiles a throw-away snapshot to reject invalid policies early.
func validateTenantPolicy(tp api.TenantPolicy) error {
	for i, r := range tp.Rules {
		if r.Source != "" && r.Source != policy.SourceTenant {
			return &policy.ValidationError{Field: fmt.Sprintf("rules[%d].source", i), Msg: fmt.Sprintf("must be %q", policy.SourceTenant)}
		}
	}
	switch tp.DecideDefault {
	case "", policy.ActionAllow, policy.ActionBlock:
	default:
		return &policy.ValidationError{Field: "decideDefault", Msg: fmt.Sprintf("must be allow or block, got %q", tp.DecideDefault)}
	}
	if tp.DefaultAction != "" && tp.DefaultAction != policy.ActionAllow && tp.DefaultAction != policy.ActionBlock && tp.DefaultAction != policy.ActionAsk {
		return &policy.ValidationError{Field: "defaultAction", Msg: fmt.Sprintf("invalid action %q", tp.DefaultAction)}
	}
	if _, err := compileDecide(tp); err != nil {
		return err
	}
	if err := validatePrivateApps(tp.PrivateApps); err != nil {
		return err
	}
	fw, dns := MergeLayers(tp, nil)
	_, err := policy.Compile(&policy.Snapshot{SchemaVersion: policy.CurrentSchemaVersion, TenantID: "t", DeviceID: "d", Firewall: fw, DNS: dns,
		PrivateApps: stripUsers(tp.PrivateApps)})
	return remapField(err, 0)
}

// normalizePrivateApps defaults an empty ConnectorGroup to "default" (ADR-0013).
func normalizePrivateApps(apps []api.TenantPrivateApp) {
	for i := range apps {
		if apps[i].ConnectorGroup == "" {
			apps[i].ConnectorGroup = defaultGroup
		}
	}
}

// validatePrivateApps checks what policy.Compile does not: IDs are pki-valid identifiers,
// every app has at least one port and a valid connector group, and Users entries are
// non-empty. Compile then checks domains, port ranges and ID uniqueness.
func validatePrivateApps(apps []api.TenantPrivateApp) error {
	seen := make(map[string]bool, len(apps))
	for i, a := range apps {
		field := fmt.Sprintf("privateApps[%d]", i)
		switch {
		case !pki.ValidID(a.ID):
			return &policy.ValidationError{Field: field + ".id", Msg: "must match [a-zA-Z0-9][a-zA-Z0-9._-]*"}
		case seen[a.ID]:
			return &policy.ValidationError{Field: field + ".id", Msg: fmt.Sprintf("duplicate id %q", a.ID)}
		case len(a.Name) > maxNameLen:
			return &policy.ValidationError{Field: field + ".name", Msg: "longer than 128 characters"}
		case len(a.Domains) == 0:
			return &policy.ValidationError{Field: field + ".domains", Msg: "at least one domain is required"}
		case len(a.Ports) == 0:
			return &policy.ValidationError{Field: field + ".ports", Msg: "at least one port is required"}
		case !pki.ValidID(a.ConnectorGroup):
			return &policy.ValidationError{Field: field + ".connectorGroup", Msg: "must match [a-zA-Z0-9][a-zA-Z0-9._-]*"}
		}
		seen[a.ID] = true
		for j, p := range a.Ports {
			if p.From == 0 {
				return &policy.ValidationError{Field: fmt.Sprintf("%s.ports[%d]", field, j), Msg: "port 0 is not valid"}
			}
		}
		for j, u := range a.Users {
			if strings.TrimSpace(u) == "" {
				return &policy.ValidationError{Field: fmt.Sprintf("%s.users[%d]", field, j), Msg: "empty"}
			}
		}
	}
	return nil
}

// stripUsers returns the apps without their entitlement lists.
func stripUsers(apps []api.TenantPrivateApp) []policy.PrivateApp {
	if len(apps) == 0 {
		return nil
	}
	out := make([]policy.PrivateApp, 0, len(apps))
	for _, a := range apps {
		out = append(out, a.PrivateApp)
	}
	return out
}

// entitledApps returns the private apps user u may reach: those with an empty Users list,
// or listing u's ID or (case-insensitively) u's email. Users is stripped.
func entitledApps(apps []api.TenantPrivateApp, u store.User) []policy.PrivateApp {
	var out []policy.PrivateApp
	for _, a := range apps {
		ok := len(a.Users) == 0
		for _, x := range a.Users {
			if x == u.ID || (u.Email != "" && strings.EqualFold(x, u.Email)) {
				ok = true
				break
			}
		}
		if ok {
			out = append(out, a.PrivateApp)
		}
	}
	return out
}

var ruleIndex = regexp.MustCompile(`^firewall\.rules\[(\d+)\]`)

// remapField rewrites a ValidationError field of the compiled snapshot to the path in the
// request body: "firewall." is dropped (TenantPolicy and UserRules are flat), and rule
// indexes are shifted by skip (the tenant rules that precede user rules in the merge).
func remapField(err error, skip int) error {
	var ve *policy.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	f := ve.Field
	if m := ruleIndex.FindStringSubmatch(f); m != nil {
		n, _ := strconv.Atoi(m[1])
		f = fmt.Sprintf("rules[%d]", n-skip) + f[len(m[0]):]
	} else {
		f = strings.TrimPrefix(f, "firewall.")
	}
	return &policy.ValidationError{Field: f, Msg: ve.Msg}
}

// validateUserRules checks the user layer on top of the tenant layer.
func validateUserRules(tp api.TenantPolicy, ur api.UserRules) error {
	for i, r := range ur.Rules {
		if r.Source != "" && r.Source != policy.SourceUser {
			return &policy.ValidationError{Field: fmt.Sprintf("rules[%d].source", i), Msg: fmt.Sprintf("must be %q", policy.SourceUser)}
		}
	}
	fw, dns := MergeLayers(tp, &ur)
	_, err := policy.Compile(&policy.Snapshot{SchemaVersion: policy.CurrentSchemaVersion, TenantID: "t", DeviceID: "d", Firewall: fw, DNS: dns})
	return remapField(err, len(tp.Rules))
}

// tenantPolicy returns the stored tenant layer, or the zero policy (default block).
func (s *Server) tenantPolicy(ctx context.Context, tenantID string) (api.TenantPolicy, error) {
	tp, err := s.cfg.Store.GetTenantPolicy(ctx, tenantID)
	if errors.Is(err, store.ErrNotFound) {
		return api.TenantPolicy{}, nil
	}
	return tp, err
}

// compileDevices builds, signs and stores a new snapshot for each device, then wakes
// long-pollers. Devices must belong to one tenant.
func (s *Server) compileDevices(ctx context.Context, tenantID string, devs []store.Device) (map[string]store.SnapshotRecord, error) {
	tp, err := s.tenantPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rules := map[string]*api.UserRules{}
	users := map[string][]policy.PrivateApp{} // user ID -> entitled private apps
	out := make(map[string]store.SnapshotRecord, len(devs))
	for _, d := range devs {
		if d.TenantID != tenantID {
			return nil, fmt.Errorf("device %s is not in tenant %s", d.ID, tenantID)
		}
		ur, ok := rules[d.UserID]
		if !ok {
			r, err := s.cfg.Store.GetUserRules(ctx, tenantID, d.UserID)
			switch {
			case err == nil:
				ur = &r
			case !errors.Is(err, store.ErrNotFound):
				return nil, err
			}
			rules[d.UserID] = ur
		}
		apps, ok := users[d.UserID]
		if !ok && len(tp.PrivateApps) > 0 {
			u, err := s.cfg.Store.GetUser(ctx, tenantID, d.UserID)
			if err != nil {
				return nil, fmt.Errorf("load user %s: %w", d.UserID, err)
			}
			apps = entitledApps(tp.PrivateApps, u)
			users[d.UserID] = apps
		}
		fw, dns := MergeLayers(tp, ur)
		now := s.now().UTC().Truncate(time.Second)
		exp := now.Add(s.cfg.SnapshotTTL)
		rec, err := s.cfg.Store.SaveSnapshot(ctx, d.ID, now, exp, func(v uint64) ([]byte, error) {
			snap := &policy.Snapshot{
				SchemaVersion: policy.CurrentSchemaVersion,
				Version:       v,
				TenantID:      d.TenantID,
				UserID:        d.UserID,
				DeviceID:      d.ID,
				IssuedAt:      now,
				ExpiresAt:     exp,
				Firewall:      fw,
				DNS:           dns,
				PrivateApps:   apps,
			}
			env, err := policy.Sign(snap, s.cfg.SigningKeyID, s.cfg.SigningKey)
			if err != nil {
				return nil, err
			}
			return json.Marshal(env)
		})
		if err != nil {
			return nil, fmt.Errorf("compile snapshot for device %s: %w", d.ID, err)
		}
		out[d.ID] = rec
		s.notify.notify(d.ID)
	}
	s.log.InfoContext(ctx, "snapshots compiled", "tenant", tenantID, "devices", len(devs))
	return out, nil
}

// refreshExpiring re-signs snapshots that pass half their lifetime.
func (s *Server) refreshExpiring(ctx context.Context) error {
	act, err := s.cfg.Store.ActiveSnapshots(ctx)
	if err != nil {
		return err
	}
	limit := s.now().Add(s.cfg.SnapshotTTL / 2)
	byTenant := map[string][]store.Device{}
	for _, a := range act {
		if a.Snapshot.ExpiresAt.Before(limit) {
			byTenant[a.Device.TenantID] = append(byTenant[a.Device.TenantID], a.Device)
		}
	}
	for t, devs := range byTenant {
		if _, err := s.compileDevices(ctx, t, devs); err != nil {
			return err
		}
	}
	return nil
}

// notifier wakes long-pollers waiting for a device's next snapshot.
type notifier struct {
	mu sync.Mutex
	ch map[string]chan struct{}
}

func newNotifier() *notifier { return &notifier{ch: map[string]chan struct{}{}} }

// wait returns a channel that is closed on the next notify(deviceID).
func (n *notifier) wait(deviceID string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.ch[deviceID]
	if !ok {
		c = make(chan struct{})
		n.ch[deviceID] = c
	}
	return c
}

func (n *notifier) notify(deviceID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if c, ok := n.ch[deviceID]; ok {
		close(c)
		delete(n.ch, deviceID)
	}
}

// compiledCache keeps the compiled form of each device's latest snapshot for /v1/decide.
type compiledCache struct {
	mu sync.Mutex
	m  map[string]*compiledEntry
}

type compiledEntry struct {
	version uint64
	c       *policy.Compiled
}

func newCompiledCache() *compiledCache { return &compiledCache{m: map[string]*compiledEntry{}} }

func (cc *compiledCache) get(rec store.SnapshotRecord) (*policy.Compiled, error) {
	cc.mu.Lock()
	e, ok := cc.m[rec.DeviceID]
	cc.mu.Unlock()
	if ok && e.version == rec.Version {
		return e.c, nil
	}
	var env policy.Envelope
	if err := json.Unmarshal(rec.Envelope, &env); err != nil {
		return nil, err
	}
	// The envelope was signed by this server; decoding the payload directly is enough.
	var snap policy.Snapshot
	if err := json.Unmarshal(env.Payload, &snap); err != nil {
		return nil, err
	}
	c, err := policy.Compile(&snap)
	if err != nil {
		return nil, err
	}
	cc.mu.Lock()
	cc.m[rec.DeviceID] = &compiledEntry{version: rec.Version, c: c}
	cc.mu.Unlock()
	return c, nil
}

// decideEntry is the compiled cloud-only decision data of a tenant.
type decideEntry struct {
	domains *policy.Compiled // EvaluateDNS over DecideBlockDomains
	cidrs   []netip.Prefix
	def     policy.Action
}

func compileDecide(tp api.TenantPolicy) (*decideEntry, error) {
	e := &decideEntry{def: tp.DecideDefault}
	if e.def == "" {
		e.def = policy.ActionBlock // fail closed
	}
	// Reuse the policy package's domain matcher ("example.com" exact, "*.example.com" suffix).
	c, err := policy.Compile(&policy.Snapshot{
		SchemaVersion: policy.CurrentSchemaVersion, TenantID: "t", DeviceID: "d",
		Firewall: policy.FirewallPolicy{DefaultAction: policy.ActionAllow},
		DNS:      policy.DNSPolicy{BlockDomains: tp.DecideBlockDomains},
	})
	if err != nil {
		var ve *policy.ValidationError
		if errors.As(err, &ve) {
			return nil, &policy.ValidationError{Field: strings.Replace(ve.Field, "dns.blockDomains", "decideBlockDomains", 1), Msg: ve.Msg}
		}
		return nil, err
	}
	e.domains = c
	for i, s := range tp.DecideBlockCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, &policy.ValidationError{Field: fmt.Sprintf("decideBlockCidrs[%d]", i), Msg: err.Error()}
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		e.cidrs = append(e.cidrs, p.Masked())
	}
	return e, nil
}

// cloudDecide resolves an "ask" verdict with the tenant's cloud-only data. Never returns ask.
func (e *decideEntry) cloudDecide(f policy.Flow) policy.Decision {
	if f.Domain != "" {
		if blocked, _ := e.domains.EvaluateDNS(f.Domain); blocked {
			return policy.Decision{Action: policy.ActionBlock, RuleID: "decide:domain", Layer: policy.LayerCloud, Log: true}
		}
	}
	if ip, err := netip.ParseAddr(f.DstIP); err == nil {
		ip = ip.Unmap()
		for _, p := range e.cidrs {
			if p.Contains(ip) {
				return policy.Decision{Action: policy.ActionBlock, RuleID: "decide:cidr", Layer: policy.LayerCloud, Log: true}
			}
		}
	}
	return policy.Decision{Action: e.def, RuleID: "decide:default", Layer: policy.LayerCloud, Log: true}
}

func (s *Server) decideFor(ctx context.Context, tenantID string) (*decideEntry, error) {
	// The lock is held across the store read so that invalidateDecide, which runs after a
	// policy write, cannot be overtaken by a compute that read the old policy.
	s.decideMu.Lock()
	defer s.decideMu.Unlock()
	if e, ok := s.decide[tenantID]; ok {
		return e, nil
	}
	tp, err := s.tenantPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	e, err := compileDecide(tp)
	if err != nil {
		return nil, err
	}
	s.decide[tenantID] = e
	return e, nil
}

func (s *Server) invalidateDecide(tenantID string) {
	s.decideMu.Lock()
	delete(s.decide, tenantID)
	s.decideMu.Unlock()
}
