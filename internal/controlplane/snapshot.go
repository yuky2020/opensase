package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/saas"
	"github.com/yuky2020/opensase/pkg/store"
	"github.com/yuky2020/opensase/pkg/tunneladdr"
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
		DefaultAction:     tp.DefaultAction,
		AllowUserRules:    tp.AllowUserRules,
		Lockdown:          tp.Lockdown,
		DisableKillSwitch: tp.DisableKillSwitch,
		Rules:             make([]policy.Rule, 0, len(tp.Rules)),
		Apps:              make(map[string]policy.AppPolicy, len(tp.Apps)),
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
			r.Users, r.Groups = nil, nil // scoping is for tenant rules only (issue #68)
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
	// Copy before appending so the tenant policy's slice is never shared.
	dns.Blocklists = append(slices.Clone(dns.Blocklists), saasBlocklists(tp.SaaS)...)
	return fw, dns
}

// saasBlocklists compiles a SaaS policy into one DNS blocklist per blocked catalog app
// (ADR-0017): every app in BlockApps, plus every app of BlockCategories not in AllowApps.
// Unknown IDs are skipped here; validateSaaS refuses them when the policy is stored.
func saasBlocklists(sp api.SaaSPolicy) []policy.Blocklist {
	var out []policy.Blocklist
	for _, a := range saas.Apps() {
		blocked := slices.Contains(sp.BlockApps, a.ID) ||
			slices.Contains(sp.BlockCategories, a.Category) && !slices.Contains(sp.AllowApps, a.ID)
		if !blocked {
			continue
		}
		bl := policy.Blocklist{ID: "saas:" + a.ID, Name: a.Name, Category: "saas:" + a.Category}
		for _, d := range a.Domains {
			bl.Domains = append(bl.Domains, "*."+d)
		}
		out = append(out, bl)
	}
	return out
}

// validateSaaS checks that a SaaS policy names only catalog apps and categories.
func validateSaaS(sp api.SaaSPolicy) error {
	for field, ids := range map[string][]string{"saas.blockApps": sp.BlockApps, "saas.allowApps": sp.AllowApps} {
		for i, id := range ids {
			if _, ok := saas.ByID(id); !ok {
				return &policy.ValidationError{Field: fmt.Sprintf("%s[%d]", field, i), Msg: fmt.Sprintf("unknown SaaS app %q", id)}
			}
		}
	}
	for i, c := range sp.BlockCategories {
		if !saas.IsCategory(c) {
			return &policy.ValidationError{Field: fmt.Sprintf("saas.blockCategories[%d]", i), Msg: fmt.Sprintf("unknown SaaS category %q", c)}
		}
	}
	return nil
}

// validateTenantPolicy compiles a throw-away snapshot to reject invalid policies early.
func validateTenantPolicy(tp api.TenantPolicy) error {
	for i, r := range tp.Rules {
		if r.Source != "" && r.Source != policy.SourceTenant {
			return &policy.ValidationError{Field: fmt.Sprintf("rules[%d].source", i), Msg: fmt.Sprintf("must be %q", policy.SourceTenant)}
		}
		switch r.Posture {
		case "", policy.PostureCompliant, policy.PostureNoncompliant:
		default:
			return &policy.ValidationError{Field: fmt.Sprintf("rules[%d].posture", i), Msg: fmt.Sprintf("invalid posture condition %q", r.Posture)}
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
	if err := validateSaaS(tp.SaaS); err != nil {
		return err
	}
	if err := validateMesh(tp.Mesh); err != nil {
		return err
	}
	if err := validatePosturePolicy(tp.Posture); err != nil {
		return err
	}
	fw, dns := MergeLayers(tp, nil)
	_, err := policy.Compile(&policy.Snapshot{SchemaVersion: policy.CurrentSchemaVersion, TenantID: "t", DeviceID: "d", Firewall: fw, DNS: dns,
		PrivateApps: stripUsers(tp.PrivateApps), Web: tp.Web, Categories: tp.Categories,
		MeshInbound: meshInbound(api.MeshPolicy{Rules: allTo(tp.Mesh.Rules)}, store.Device{})})
	return remapField(err, 0)
}

// validateMesh checks the mesh rules (ADR-0034); the compiler checks protocols and ports.
func validateMesh(m api.MeshPolicy) error {
	seen := map[string]bool{}
	for i, r := range m.Rules {
		f := fmt.Sprintf("mesh.rules[%d]", i)
		if r.ID == "" || seen[r.ID] {
			return &policy.ValidationError{Field: f + ".id", Msg: "a unique id is required"}
		}
		seen[r.ID] = true
		for name, sel := range map[string]api.MeshSelector{"from": r.From, "to": r.To} {
			if !sel.All && len(sel.Users) == 0 && len(sel.Devices) == 0 {
				return &policy.ValidationError{Field: f + "." + name, Msg: "select all, some users or some devices"}
			}
		}
	}
	return nil
}

// allTo returns the rules with To set to all devices, so validation compiles every rule.
func allTo(rules []api.MeshRule) []api.MeshRule {
	out := slices.Clone(rules)
	for i := range out {
		out[i].To = api.MeshSelector{All: true}
	}
	return out
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
		switch a.Posture {
		case "", policy.PostureCompliant, policy.PostureNoncompliant:
		default:
			return &policy.ValidationError{Field: field + ".posture", Msg: fmt.Sprintf("invalid posture condition %q", a.Posture)}
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

// entitledApps returns the private apps user u may reach on a device with compliance status compliant:
// those matching the posture condition, and with an empty Users list or listing u's ID or email.
// Users is stripped.
func entitledApps(apps []api.TenantPrivateApp, u store.User, compliant bool) []policy.PrivateApp {
	var out []policy.PrivateApp
	for _, a := range apps {
		if a.Posture == policy.PostureCompliant && !compliant {
			continue
		}
		if a.Posture == policy.PostureNoncompliant && compliant {
			continue
		}
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
	users := map[string]store.User{} // user ID -> user, for private app entitlement
	out := make(map[string]store.SnapshotRecord, len(devs))
	for _, d := range devs {
		if d.TenantID != tenantID {
			return nil, fmt.Errorf("device %s is not in tenant %s", d.ID, tenantID)
		}
		dp, err := s.cfg.Store.DevicePosture(ctx, d.ID)
		var failing []string
		now := s.now().UTC().Truncate(time.Second)
		if errors.Is(err, store.ErrNotFound) {
			// A device created less than 10 minutes ago with no report is treated as compliant (grace period, ADR-0035).
			if now.Sub(d.CreatedAt) >= 10*time.Minute {
				failing = postureFailing(tp.Posture, nil)
			}
		} else if err != nil {
			return nil, fmt.Errorf("load posture for device %s: %w", d.ID, err)
		} else {
			failing = postureFailing(tp.Posture, &dp.Posture)
		}
		compliant := len(failing) == 0

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
		fw, dns := MergeLayers(tp, ur)

		// Filter tenant rules by device posture condition:
		// PostureCompliant is kept only when compliant, PostureNoncompliant only when !compliant.
		// Rule.Posture is cleared in the compiled snapshot.
		var filteredRules []policy.Rule
		for _, r := range fw.Rules {
			if r.Source == policy.SourceTenant {
				if r.Posture == policy.PostureCompliant && !compliant {
					continue
				}
				if r.Posture == policy.PostureNoncompliant && compliant {
					continue
				}
				r.Posture = policy.PostureAny
			}
			filteredRules = append(filteredRules, r)
		}
		fw.Rules = filteredRules

		if needsUserScope(tp) {
			u, err := s.cfg.Store.GetUser(ctx, tenantID, d.UserID)
			if err != nil {
				return nil, fmt.Errorf("load user %s: %w", d.UserID, err)
			}
			groups, err := s.cfg.Store.UserGroups(ctx, d.UserID)
			if err != nil {
				return nil, err
			}
			fw.Rules = scopeRules(fw.Rules, u, groups)
		}

		var apps []policy.PrivateApp
		if len(tp.PrivateApps) > 0 {
			u, ok := users[d.UserID]
			if !ok {
				var err error
				if u, err = s.cfg.Store.GetUser(ctx, tenantID, d.UserID); err != nil {
					return nil, fmt.Errorf("load user %s: %w", d.UserID, err)
				}
				users[d.UserID] = u
			}
			apps = entitledApps(tp.PrivateApps, u, compliant)
		}

		snapFW := fw
		snapApps := apps
		snapMesh := meshInbound(tp.Mesh, d)
		var postureFailingList []string
		if !compliant {
			postureFailingList = failing
		}

		if !compliant && tp.Posture.Restrict {
			// Restricted snapshot (ADR-0035):
			// Keep envelope, identity, DNS servers and signing as normal.
			// Firewall default action is block, with only:
			// 1. DNS (udp and tcp port 53) to tunnel resolver addresses (100.64.0.1, fd7a:5a5e::1).
			// 2. TCP 443 to Control Plane address(es). Assumption: Control Plane host is
			//    derived from s.cfg.ControlURL, falling back to 127.0.0.1 if unconfigured.
			// 3. Remediation domains (rules with Match.Domains).
			// No private apps; no mesh grants.
			var restrictedRules []policy.Rule
			rulePrio := 1

			// 1. Allow DNS to tunnel resolver addresses
			restrictedRules = append(restrictedRules, policy.Rule{
				ID:       "posture:dns",
				Source:   policy.SourceTenant,
				Priority: rulePrio,
				Action:   policy.ActionAllow,
				Match: policy.Match{
					Protocols: []string{"udp", "tcp"},
					CIDRs:     []string{tunneladdr.EdgeIPv4.String() + "/32", tunneladdr.EdgeIPv6.String() + "/128"},
					Ports:     []policy.PortRange{{From: 53, To: 53}},
				},
			})
			rulePrio++

			// 2. Allow TCP 443 to Control Plane address(es)
			cpMatch := policy.Match{
				Protocols: []string{"tcp"},
				Ports:     []policy.PortRange{{From: 443, To: 443}},
			}
			if s.cfg.ControlURL != "" {
				if u, err := url.Parse(s.cfg.ControlURL); err == nil {
					if p, err := strconv.ParseUint(u.Port(), 10, 16); err == nil && p > 0 {
						cpMatch.Ports = []policy.PortRange{{From: uint16(p), To: uint16(p)}}
					}
					h := u.Hostname()
					if ip, err := netip.ParseAddr(h); err == nil {
						if ip.Is4() {
							cpMatch.CIDRs = []string{ip.String() + "/32"}
						} else {
							cpMatch.CIDRs = []string{ip.String() + "/128"}
						}
					} else if h != "" {
						cpMatch.Domains = []string{h}
					}
				}
			}
			if len(cpMatch.CIDRs) == 0 && len(cpMatch.Domains) == 0 {
				cpMatch.CIDRs = []string{"127.0.0.1/32"}
			}
			restrictedRules = append(restrictedRules, policy.Rule{
				ID:       "posture:controlplane",
				Source:   policy.SourceTenant,
				Priority: rulePrio,
				Action:   policy.ActionAllow,
				Match:    cpMatch,
			})
			rulePrio++

			// 3. Allow remediation domains
			if len(tp.Posture.RemediationDomains) > 0 {
				restrictedRules = append(restrictedRules, policy.Rule{
					ID:       "posture:remediation",
					Source:   policy.SourceTenant,
					Priority: rulePrio,
					Action:   policy.ActionAllow,
					Match: policy.Match{
						Domains: tp.Posture.RemediationDomains,
					},
				})
			}

			snapFW = policy.FirewallPolicy{
				DefaultAction:     policy.ActionBlock,
				AllowUserRules:    false,
				Lockdown:          tp.Lockdown, // never weaker than the normal snapshot
				DisableKillSwitch: tp.DisableKillSwitch,
				Rules:             restrictedRules,
			}
			snapApps = nil
			snapMesh = nil
		}

		exp := now.Add(s.cfg.SnapshotTTL)
		rec, err := s.cfg.Store.SaveSnapshot(ctx, d.ID, now, exp, func(v uint64) ([]byte, error) {
			snap := &policy.Snapshot{
				SchemaVersion:  policy.CurrentSchemaVersion,
				Version:        v,
				TenantID:       d.TenantID,
				UserID:         d.UserID,
				DeviceID:       d.ID,
				IssuedAt:       now,
				ExpiresAt:      exp,
				Firewall:       snapFW,
				DNS:            dns,
				PrivateApps:    snapApps,
				Web:            tp.Web,
				Categories:     append(slices.Clone(tp.Categories), listCategories(tenantID, tp)...),
				SafeSearch:     tp.SafeSearch,
				MeshInbound:    snapMesh,
				PostureFailing: postureFailingList,
			}
			env, err := policy.Sign(snap, s.cfg.SigningKeyID, s.cfg.SigningKey)
			if err != nil {
				return nil, err
			}
			return json.Marshal(env)
		})
		if err != nil {
			s.obs.compileFail.Inc()
			return nil, fmt.Errorf("compile snapshot for device %s: %w", d.ID, err)
		}
		out[d.ID] = rec
		s.wake(ctx, d.ID)
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

// notifyAll wakes every waiter, after cross-replica wake-ups may have been lost.
func (n *notifier) notifyAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, c := range n.ch {
		close(c)
		delete(n.ch, k)
	}
}

// wake wakes the long-pollers waiting for key on this replica and, through the store, on the
// other Control Plane replicas (ADR-0033).
func (s *Server) wake(ctx context.Context, key string) {
	s.notify.notify(key)
	if err := s.cfg.Store.Publish(context.WithoutCancel(ctx), key); err != nil {
		s.log.WarnContext(ctx, "wake-up not published to the other replicas", "err", err)
	}
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
	version uint64           // tenant policy version it was built from (ADR-0033)
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
		p, err := parseDecidePrefix(s)
		if err != nil {
			return nil, &policy.ValidationError{Field: fmt.Sprintf("decideBlockCidrs[%d]", i), Msg: err.Error()}
		}
		e.cidrs = append(e.cidrs, p)
	}
	return e, nil
}

// parseDecidePrefix parses a CIDR or bare IP address for DecideBlockCIDRs, mirroring
// policy.parsePrefix: IPv6 zones are rejected and IPv4-mapped IPv6 addresses/prefixes are
// unmapped to plain IPv4 so they match unmapped flows in cloudDecide.
func parseDecidePrefix(s string) (netip.Prefix, error) {
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
	// The entry records the policy version it was built from, so a policy written through
	// another Control Plane replica is picked up on the next call (ADR-0033). The lock is
	// held across the store reads so that invalidateDecide cannot be overtaken by a compute
	// that read the old policy.
	s.decideMu.Lock()
	defer s.decideMu.Unlock()
	v, err := s.cfg.Store.TenantPolicyVersion(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if e, ok := s.decide[tenantID]; ok && e.version == v {
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
	e.version = v
	s.decide[tenantID] = e
	return e, nil
}

func (s *Server) invalidateDecide(tenantID string) {
	s.decideMu.Lock()
	delete(s.decide, tenantID)
	s.decideMu.Unlock()
}

// meshInbound turns the tenant mesh rules whose To selects d into d's grants (ADR-0034).
//
// CONTRACT-CHANGE-REQUEST: api.MeshRule.Protocol in pkg/api/types.go documents
// "tcp, udp, icmp; empty: any"; it now also accepts "icmpv6".
func meshInbound(m api.MeshPolicy, d store.Device) []policy.MeshGrant {
	var out []policy.MeshGrant
	for _, r := range m.Rules {
		if !r.To.All && !slices.Contains(r.To.Users, d.UserID) && !slices.Contains(r.To.Devices, d.ID) {
			continue
		}
		out = append(out, policy.MeshGrant{RuleID: r.ID, FromAll: r.From.All, FromUsers: r.From.Users,
			FromDevices: r.From.Devices, Protocol: r.Protocol, Ports: r.Ports})
	}
	return out
}

// needsUserScope reports whether some tenant rule is limited to users or groups (issue #68).
func needsUserScope(tp api.TenantPolicy) bool {
	for _, r := range tp.Rules {
		if len(r.Users) > 0 || len(r.Groups) > 0 {
			return true
		}
	}
	return false
}

// scopeRules keeps the rules that apply to user u (in groups) and clears their Users and
// Groups, which only the Control Plane evaluates (issue #68).
func scopeRules(rules []policy.Rule, u store.User, groups []string) []policy.Rule {
	out := rules[:0:0]
	for _, r := range rules {
		if len(r.Users) > 0 || len(r.Groups) > 0 {
			match := slices.Contains(r.Users, u.ID) || slices.ContainsFunc(r.Users, func(x string) bool { return strings.EqualFold(x, u.Email) })
			for _, g := range r.Groups {
				if slices.Contains(groups, g) {
					match = true
				}
			}
			if !match {
				continue
			}
			r.Users, r.Groups = nil, nil
		}
		out = append(out, r)
	}
	return out
}
