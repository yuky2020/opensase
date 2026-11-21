// Package policy defines the Policy Snapshot: the signed, versioned, compiled policy that the
// Control Plane distributes to Clients and Edges. The same evaluator runs on
// the device and on the Edge (see ADR-0012).
//
// CONTRACT FILE: types and function signatures here are shared by the client core, the
// Control Plane and the Edge. Change them only together with all three.
package policy

import "time"

// Action is a verdict for a flow or DNS query.
type Action string

// Actions.
const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	// ActionAsk defers the decision to the Control Plane decision API (POST /v1/decide).
	// It is never returned by the decision API itself.
	ActionAsk Action = "ask"
)

// NetworkType is the kind of network the device is currently using.
type NetworkType string

// Network types.
const (
	NetworkWiFi     NetworkType = "wifi"
	NetworkCellular NetworkType = "cellular"
	NetworkRoaming  NetworkType = "roaming"
	NetworkEthernet NetworkType = "ethernet"
	NetworkUnknown  NetworkType = "unknown"
)

// RuleSource says which policy layer a rule belongs to. Precedence: tenant > user.
type RuleSource string

// Rule sources.
const (
	SourceTenant RuleSource = "tenant"
	SourceUser   RuleSource = "user"
)

// Snapshot is the compiled policy for one device (tenant layer + that user's layer).
type Snapshot struct {
	SchemaVersion int       `json:"schemaVersion"` // currently 1
	Version       uint64    `json:"version"`       // strictly increasing per device
	TenantID      string    `json:"tenantId"`
	UserID        string    `json:"userId"`
	DeviceID      string    `json:"deviceId"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"` // device keeps enforcing after expiry but reports "stale"

	Firewall FirewallPolicy `json:"firewall"`
	DNS      DNSPolicy      `json:"dns"`
	// PrivateApps are the ZTNA apps this user is entitled to (ADR-0013). The Control Plane
	// includes only entitled apps, so presence here IS the access grant.
	PrivateApps []PrivateApp `json:"privateApps,omitempty"`
	// Web is the tenant's web inspection policy (ADR-0018). Only the Edge enforces it;
	// devices validate it and otherwise ignore it.
	Web WebPolicy `json:"web,omitzero"`
}

// WebPolicy decrypts and controls the HTTPS (and plain HTTP) traffic of the tenant's devices
// at the Edge (ADR-0018). It is tenant-only: user rules cannot change it.
type WebPolicy struct {
	// Inspect turns TLS interception on. Without it Rules and Headers apply to plain HTTP
	// only, and HTTPS is controlled by hostname alone (ADR-0017).
	Inspect bool `json:"inspect,omitempty"`
	// Bypass lists domains whose TLS is never decrypted: certificate-pinned apps, banking,
	// health. Same syntax as Match.Domains.
	Bypass []string `json:"bypass,omitempty"`
	// Rules are matched in order on each request; the first match decides. No match allows.
	Rules []WebRule `json:"rules,omitempty"`
	// Headers are set on every request to a matching host, replacing any value the client
	// sent (for example a header that limits a SaaS login to the company's own tenant).
	Headers []WebHeader `json:"headers,omitempty"`
}

// WebRule matches requests by host, path and method.
type WebRule struct {
	ID      string   `json:"id"`
	Domains []string `json:"domains"` // same syntax as Match.Domains; at least one
	// PathPrefixes match the start of the normalized request path (dot segments resolved,
	// duplicate slashes collapsed, case-insensitive). Empty matches every path.
	PathPrefixes []string `json:"pathPrefixes,omitempty"`
	Methods      []string `json:"methods,omitempty"` // empty matches every method
	Action       Action   `json:"action"`            // allow or block
}

// WebHeader is a request header the Edge sets for matching hosts.
type WebHeader struct {
	Domains []string `json:"domains"`
	Name    string   `json:"name"`
	Value   string   `json:"value"`
}

// PrivateApp is a private application published through Connectors (ADR-0013).
// It is reachable only by name: the Edge resolver answers Domains with synthetic addresses
// from SyntheticPrefix and brokers TCP connections to a connector of ConnectorGroup.
type PrivateApp struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Domains        []string    `json:"domains"`        // same syntax as Match.Domains
	Ports          []PortRange `json:"ports"`          // TCP only; empty = no access
	ConnectorGroup string      `json:"connectorGroup"` // connectors of the tenant with this group serve the app
}

// SyntheticPrefix is the Edge-local pool of addresses handed out for PrivateApp names.
// It is disjoint from the tunnel pool (100.64.0.0/16).
const SyntheticPrefix = "100.96.0.0/12"

// FirewallPolicy is evaluated per new flow in this order:
//  1. Rules with Source=tenant, ordered by Priority ascending, first match wins.
//  2. If AllowUserRules: rules with Source=user, same ordering.
//  3. Apps[package] for the current NetworkType (if Lockdown, missing apps are blocked).
//  4. Snapshot.PrivateApps: TCP flow whose Domain and DstPort match an entitled app ->
//     allow, Layer "ztna", RuleID "ztna:<appId>" (ADR-0013).
//  5. DefaultAction.
type FirewallPolicy struct {
	DefaultAction  Action               `json:"defaultAction"`
	AllowUserRules bool                 `json:"allowUserRules"`
	Lockdown       bool                 `json:"lockdown"`
	Rules          []Rule               `json:"rules"`
	Apps           map[string]AppPolicy `json:"apps"` // key: Android package name
	// TenantApps lists the packages whose Apps entry was set by the tenant layer. Those entries are
	// mandatory, and under Lockdown only they can allow an app (ADR-0012, review D1).
	TenantApps []string `json:"tenantApps,omitempty"`
}

// AppPolicy is the per-app, per-network verdict. Empty field = not set,
// i.e. fall through to DefaultAction.
type AppPolicy struct {
	WiFi     Action `json:"wifi,omitempty"`
	Cellular Action `json:"cellular,omitempty"`
	Roaming  Action `json:"roaming,omitempty"`
}

// Rule is one firewall rule. All non-empty Match fields must match (AND); values inside one
// field are alternatives (OR).
type Rule struct {
	ID          string     `json:"id"`
	Source      RuleSource `json:"source"`
	Priority    int        `json:"priority"`
	Action      Action     `json:"action"`
	Match       Match      `json:"match"`
	Log         bool       `json:"log"`
	Description string     `json:"description,omitempty"`
}

// Match holds the conditions of a Rule (see Rule for how they combine).
type Match struct {
	Apps      []string      `json:"apps,omitempty"`      // package names; device-only attribute
	Networks  []NetworkType `json:"networks,omitempty"`  // device-only attribute
	Protocols []string      `json:"protocols,omitempty"` // "tcp","udp","icmp"
	CIDRs     []string      `json:"cidrs,omitempty"`     // destination prefixes, v4 or v6
	Ports     []PortRange   `json:"ports,omitempty"`     // destination ports
	Domains   []string      `json:"domains,omitempty"`   // "example.com" exact, "*.example.com" suffix incl. apex
}

// PortRange is an inclusive destination port range.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"` // inclusive; To==0 means To=From
}

// DNSPolicy is enforced by the client DNS interceptor and again by the Edge resolver.
type DNSPolicy struct {
	BlockResponse string      `json:"blockResponse"` // "nxdomain" | "zero"
	Blocklists    []Blocklist `json:"blocklists"`
	AllowDomains  []string    `json:"allowDomains,omitempty"` // override blocklists; same syntax as Match.Domains
	BlockDomains  []string    `json:"blockDomains,omitempty"`
}

// Blocklist is a named list of blocked domains in one category.
type Blocklist struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"` // "ads","trackers","malware","adult",...
	Domains  []string `json:"domains"`  // inline; same syntax as Match.Domains
}

// Flow is the input to evaluation. Fields the evaluator does not know are left empty;
// on the Edge, App and Network are always empty and rules matching them are skipped.
type Flow struct {
	App      string      `json:"app,omitempty"`
	UID      int         `json:"uid,omitempty"`
	Network  NetworkType `json:"network,omitempty"`
	Protocol string      `json:"protocol"`
	DstIP    string      `json:"dstIp"`
	DstPort  uint16      `json:"dstPort"`
	Domain   string      `json:"domain,omitempty"` // from DNS snooping, lowercase, no trailing dot
}

// Decision is the result of evaluation.
type Decision struct {
	Action Action `json:"action"`
	RuleID string `json:"ruleId,omitempty"` // "" for default, "app:<pkg>" for AppPolicy, "lockdown"
	Layer  string `json:"layer"`            // "tenant","user","app","lockdown","ztna","default","cloud"
	Log    bool   `json:"log"`
}

// Envelope is the signed wire form of a Snapshot. Payload is the exact JSON bytes that were
// signed; verify Signature over Payload BEFORE unmarshalling.
type Envelope struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"alg"`       // "ed25519" (hybrid with ML-DSA planned, ADR-0008)
	Payload   []byte `json:"payload"`   // JSON-encoded Snapshot (base64 in JSON)
	Signature []byte `json:"signature"` // base64 in JSON
}

// Evaluator is implemented in evaluate.go. It must be safe for concurrent use, and its
// compiled form must be swappable without locks on the hot path (atomic.Pointer).
//
//	func Compile(s *Snapshot) (*Compiled, error)
//	func (c *Compiled) Evaluate(f Flow, edgeMode bool) Decision
//	func (c *Compiled) EvaluateDNS(name string) (blocked bool, listID string)
//	func (c *Compiled) PrivateApp(name string) (PrivateApp, bool)          // name match only
//	func (c *Compiled) PrivateAppAccess(name string, port uint16) (PrivateApp, bool) // name + port
//	func Sign(s *Snapshot, keyID string, priv ed25519.PrivateKey) (*Envelope, error)
//	func Verify(e *Envelope, pub map[string]ed25519.PublicKey) (*Snapshot, error)
