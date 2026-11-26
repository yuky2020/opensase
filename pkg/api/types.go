// Package api defines the JSON wire types of the Control Plane and Edge HTTP APIs.
//
// CONTRACT FILE shared by mobile core, Control Plane and Edge.
//
// Transport: HTTPS, TLS 1.3 only, key exchange restricted to X25519MLKEM768 (ADR-0002).
// Device endpoints use mTLS with the device certificate issued at enrollment.
// Enrollment trust bootstrap: the device pins the SHA-256 of the provider root CA certificate,
// given as a "#sha256=<hex>" fragment of the control URL (the QR code carries URL + key + pin).
// Servers MUST send the full chain including the root, so the pinned certificate is present.
// Server identity: clients MUST check the server leaf's SPIFFE URI SAN, not only the DNS name:
// spiffe://opensase/controlplane for the Control Plane, spiffe://opensase/edge/<EdgeInfo.ID>
// for an Edge session URL (pkg/pki.ParseURI). Each server certificate has its own SANs.
// Device certificates are short-lived (24h); devices renew at 50% of the lifetime.
// Admin endpoints use "Authorization: Bearer <admin token>". The token configured on the
// Control Plane is the super-admin: every tenant, tenant creation and the Edge registry. A
// tenant admin token (AdminTokenCreated.Token, prefix "osa_") administers only its tenant
// (ST-03): other tenants answer 404 as if they did not exist, and super-admin routes 403.
//
// Control Plane endpoints:
//
//	POST /v1/enroll                     EnrollRequest -> EnrollResponse        (no client cert)
//	GET  /v1/snapshot                   -> policy.Envelope; ETag = version; 304 if If-None-Match matches (mTLS)
//	GET  /v1/snapshot?wait=30           long-poll: returns as soon as a newer version exists, else 304 after wait seconds
//	POST /v1/renew                      RenewRequest -> RenewResponse (mTLS device cert, still valid; new CSR with a NEW key; old serial is replaced;
//	                                    the just-superseded cert is accepted ONLY here, to retry after a lost response)
//	GET  /v1/self/rules                 -> UserRules (the stored user layer, unmerged) (mTLS)
//	PUT  /v1/self/rules                 UserRules -> policy.Envelope (new snapshot) ; 403 if tenant disallows user rules (mTLS)
//	POST /v1/decide                     DecideRequest -> DecideResponse (mTLS device cert, or edge cert with ?device=<id>, evaluated in edge mode)
//	POST /v1/flows                      FlowBatch -> 202 (mTLS device or edge cert; with an edge cert the tenant comes from each record's DeviceID)
//	GET  /v1/edge/peers                 -> EdgePeers; for Edges, mTLS with edge cert (a Private Edge gets only its tenant)
//	POST /v1/edge/sessions              EdgeSessions -> 204 (edge cert; devices with a live session on that edge, sent every 10s)
//	GET  /v1/edge/categories?names=a,b  -> binary category data (pkg/categories wire format); ETag, 304; 503 if no list is loaded
//	POST /v1/edge/inspection-ca         InspectionCARequest -> InspectionCAResponse (edge cert; 403 unless the tenant has
//	                                    web.inspect on and the edge serves that tenant; ADR-0018)
//	GET  /v1/pki/ca                     -> PEM bundle of tenant CAs + snapshot public keys (JSON PKIBundle)
//
//	Connector endpoints (ADR-0013). Connector certs: spiffe://opensase/tenant/<t>/connector/<id>,
//	issued by the tenant CA, ClientAuth, 24h, renewed at 50%:
//	POST /v1/connector/enroll           ConnectorEnrollRequest -> ConnectorEnrollResponse (no client cert; connector provisioning key)
//	GET  /v1/connector/config           -> ConnectorConfig (mTLS connector cert; ETag/long-poll like /v1/snapshot)
//	POST /v1/connector/renew            RenewRequest -> RenewResponse (mTLS connector cert; same rules as /v1/renew)
//
//	POST /v1/admin/tenants              AdminTenant -> AdminTenant
//	POST /v1/admin/tenants/{t}/users    AdminUser -> AdminUser
//	POST /v1/admin/tenants/{t}/provisioning-keys   ProvisioningKeyRequest -> ProvisioningKey
//	PUT  /v1/admin/tenants/{t}/policy   TenantPolicy -> 204 (recompiles all device snapshots)
//	GET  /v1/admin/tenants/{t}/flows?limit=   -> FlowBatch
//	GET  /v1/admin/tenants/{t}/policy  -> TenantPolicy
//	GET  /v1/admin/tenants/{t}/devices -> []AdminDevice (internal/controlplane)
//	POST /v1/admin/tenants/{t}/devices/{d}/revoke -> 204
//	GET  /v1/admin/tenants/{t}/devices/{d}/routes -> DeviceRoutes (tenant role admin only)
//	PUT  /v1/admin/tenants/{t}/devices/{d}/routes DeviceRoutes -> DeviceRoutes (tenant role admin only)
//	POST /v1/admin/edges                AdminEdge -> 201 | 409 | 404 (unknown tenant); TenantID set = Private Edge (ADR-0014)
//	GET  /v1/admin/edges                -> []AdminEdge
//	POST /v1/admin/edges/{e}/revoke     -> 204 | 404
//	POST /v1/admin/tenants/{t}/connectors              AdminConnectorRequest -> AdminConnectorCreated (one-time provisioning key)
//	GET  /v1/admin/tenants/{t}/connectors              -> []AdminConnector
//	POST /v1/admin/tenants/{t}/connectors/{c}/revoke   -> 204 | 404
//	GET  /v1/admin/tenants                -> []AdminTenant (a tenant admin sees only its tenant)
//	GET  /v1/admin/whoami                 -> AdminIdentity
//	GET  /v1/admin/info                   -> AdminInfo (pinned control URL for enrollment QR codes, version)
//	GET  /v1/admin/tenants/{t}/policy sets ETag; PUT accepts If-Match and answers 412 if the policy changed
//	GET  /v1/admin/saas/catalog           -> []SaaSApp (the built-in catalog, ADR-0017)
//	POST /v1/admin/tenants/{t}/admin-tokens            AdminTokenRequest -> AdminTokenCreated (token shown once)
//	GET  /v1/admin/tenants/{t}/admin-tokens            -> []AdminToken
//	POST /v1/admin/tenants/{t}/admin-tokens/{id}/revoke -> 204 | 404
//	GET  /v1/admin/tenants/{t}/audit?limit=   -> []AuditEntry (admin writes on that tenant, newest first)
//	GET  /v1/admin/audit?limit=&tenant=       -> []AuditEntry (super-admin: every entry, or one tenant)
//	GET  /v1/admin/audit/verify[?id=N&hash=H] -> AuditVerification (super-admin; hash chain check, ADR-0028)
//	Super-admin only (403 for a tenant admin): POST /v1/admin/tenants, /v1/admin/edges* and /v1/admin/audit.
//	GET  /v1/admin/tenants/{t}/users      -> []AdminUser
//	PUT  /v1/admin/tenants/{t}/dlp-datasets/{name}  DLPDatasetRequest -> DLPDataset (ADR-0029; only hashes are kept)
//	GET  /v1/admin/tenants/{t}/dlp-datasets         -> []DLPDataset
//	DELETE /v1/admin/tenants/{t}/dlp-datasets/{name} -> 204 | 404
//	GET  /v1/edge/dlp-datasets?tenant=T&names=a,b   -> EdgeDatasets (edge cert; edge must serve T)
//	GET  /v1/admin/categories             -> CategoryCatalog (the loaded category list, ADR-0022)
//	GET  /v1/admin/tenants/{t}/inspection-ca  -> PEM of the tenant's web inspection root (ADR-0018), to install on devices
//	GET  /v1/admin/tenants/{t}/oidc       -> TenantOIDC (HasSecret, RedirectURL; secret omitted)
//	PUT  /v1/admin/tenants/{t}/oidc       TenantOIDC -> TenantOIDC (admin role only)
//	DELETE /v1/admin/tenants/{t}/oidc     -> 204 | 404 (admin role only)
//	GET  /v1/auth/oidc/{tenant}/login     -> 302 to IdP authorize URL (no auth)
//	GET  /v1/auth/oidc/callback?state=&code= -> 303 to /admin/#/oidc-signin?token=... (no auth)
//
// Admin portal: the Control Plane serves the static Flutter web build at /admin/ (flag -portal-dir).
//
// Edge-cert forms of /v1/decide?device= and /v1/flows are accepted only for devices the edge
// reported via /v1/edge/sessions within the last 2 minutes. Unregistered/revoked edges get 403.
//
// Enrollment QR / deep link: opensase://enroll?control=<url-encoded control URL incl. #sha256=>&key=<provisioning key>
//
// Decision layers: "tenant","user","app","lockdown","ztna","default","cloud" (decide API), "dns" (DNS block, RuleID "dns:<listId>").
//
// Broker channel (Edge <-> Connector, ADR-0013): the connector dials EdgeInfo.BrokerAddr with
// TLS 1.3 (pqsession.Harden, ALPN "opensase-broker/1", mTLS connector cert; connector checks the
// Edge SPIFFE URI). Over that one connection the roles invert: the Edge is the HTTP/2 CLIENT and
// the connector the HTTP/2 SERVER. For each brokered TCP connection the Edge sends
//
//	POST /v1/dial   headers BrokerHeaderTarget, BrokerHeaderApp, BrokerHeaderDevice
//
// with a streaming body (client->app bytes); the connector answers 200 and streams app->client
// bytes, 403 if the target is not in one of its ConnectorConfig.Apps (name AND port), 502 if the dial fails.
//
// Edge endpoints (session-setup channel, ADR-0002), mTLS with device cert:
//
//	POST /v1/session                    SessionRequest -> SessionResponse
//	GET  /v1/session/{sessionId}        204 if it is the device's live session here, else 404 (issue #70)
//	The WireGuard PSK is derived by both sides with
//	  tls.ConnectionState.ExportKeyingMaterial(pqsession.ExporterLabel, pqsession.Context(...), 32)
package api

import (
	"time"

	"github.com/yuky2020/opensase/pkg/policy"
)

// EnrollRequest is the body of POST /v1/enroll.
type EnrollRequest struct {
	ProvisioningKey string `json:"provisioningKey"`
	DeviceName      string `json:"deviceName"`
	Platform        string `json:"platform"` // "android","linux","windows","macos","ios"
	CSRPEM          string `json:"csrPem"`   // PKCS#10, ECDSA P-256 key generated on device
}

// EnrollResponse is the reply to POST /v1/enroll: the device identity and trust material.
type EnrollResponse struct {
	TenantID       string       `json:"tenantId"`
	UserID         string       `json:"userId"`
	DeviceID       string       `json:"deviceId"`
	CertificatePEM string       `json:"certificatePem"`
	CAPEM          string       `json:"caPem"` // trust anchor for Control Plane and Edge server certs too
	Edges          []EdgeInfo   `json:"edges"`
	SnapshotKeys   []SigningKey `json:"snapshotKeys"`
	ControlURL     string       `json:"controlUrl"`
}

// EdgeInfo describes one Edge: where to set up sessions, the WireGuard endpoint and the broker address.
type EdgeInfo struct {
	ID          string `json:"id"`
	Region      string `json:"region"`
	SessionURL  string `json:"sessionUrl"`           // https://edge:8443
	WGEndpoint  string `json:"wgEndpoint"`           // host:51820
	WGPublicKey string `json:"wgPublicKey"`          // base64
	BrokerAddr  string `json:"brokerAddr,omitempty"` // host:8444, where Connectors dial (ADR-0013)
}

// SigningKey is a public key that verifies policy snapshot signatures.
type SigningKey struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"alg"`
	PublicKey []byte `json:"publicKey"`
}

// PKIBundle is the reply to GET /v1/pki/ca: tenant CAs and snapshot public keys.
type PKIBundle struct {
	CAPEM        string       `json:"caPem"`
	SnapshotKeys []SigningKey `json:"snapshotKeys"`
}

// UserRules replaces the user's whole layer (rules with Source=user + per-app policies).
type UserRules struct {
	Rules []policy.Rule               `json:"rules"`
	Apps  map[string]policy.AppPolicy `json:"apps"`
}

// TenantPrivateApp is a private app plus its entitlement. Users lists user IDs or emails;
// empty means every user of the tenant.
type TenantPrivateApp struct {
	policy.PrivateApp
	Users []string `json:"users,omitempty"`
}

// DecideRequest is the body of POST /v1/decide.
type DecideRequest struct {
	Flow policy.Flow `json:"flow"`
}

// DecideResponse is the reply to POST /v1/decide; TTL is how long the decision may be cached.
type DecideResponse struct {
	Decision policy.Decision `json:"decision"` // Action is never "ask"
	TTL      int             `json:"ttlSeconds"`
}

// FlowRecord is one logged flow with its decision and byte counts.
type FlowRecord struct {
	Start    time.Time       `json:"start"`
	End      time.Time       `json:"end,omitempty"`
	Flow     policy.Flow     `json:"flow"`
	Decision policy.Decision `json:"decision"`
	BytesOut uint64          `json:"bytesOut"`
	BytesIn  uint64          `json:"bytesIn"`
	Where    string          `json:"where"` // "device" | "edge" | "cloud" (decide API)
	DeviceID string          `json:"deviceId,omitempty"`
	// SaaSApp is the catalog app (pkg/saas) that Flow.Domain belongs to. The Control Plane sets
	// it when it stores the record; values sent by devices and Edges are ignored (ADR-0017).
	SaaSApp string `json:"saasApp,omitempty"`
	// Categories are the web categories (ADR-0022) of Flow.Domain, set by the Control Plane
	// like SaaSApp (issue #27).
	Categories []string `json:"categories,omitempty"`
}

// FlowBatch is the body of POST /v1/flows and the reply to the admin flows query.
type FlowBatch struct {
	Records []FlowRecord `json:"records"`
}

// SessionRequest is the body of POST /v1/session on an Edge.
type SessionRequest struct {
	WGPublicKey string `json:"wgPublicKey"` // base64 Curve25519
	Epoch       uint64 `json:"epoch"`       // 0 for a new session; incremented on each PSK rotation
	SessionID   string `json:"sessionId,omitempty"`
}

// SessionResponse is the reply to POST /v1/session: the tunnel configuration.
type SessionResponse struct {
	SessionID      string   `json:"sessionId"`
	Epoch          uint64   `json:"epoch"`
	TunnelIPv4     string   `json:"tunnelIpv4"` // e.g. 100.64.0.7/32
	TunnelIPv6     string   `json:"tunnelIpv6"` // e.g. fd7a:5a5e::7/128
	DNSServers     []string `json:"dnsServers"` // Edge resolver, e.g. 100.64.0.1
	EdgeWGKey      string   `json:"edgeWgPublicKey"`
	WGEndpoint     string   `json:"wgEndpoint"`
	RotateAfterSec int      `json:"rotateAfterSeconds"` // client must re-run /v1/session with Epoch+1
	MTU            int      `json:"mtu"`
}

// EdgePeers is the reply to GET /v1/edge/peers: the devices and connectors an Edge accepts.
type EdgePeers struct {
	Devices    []EdgeDevice    `json:"devices"`
	Connectors []EdgeConnector `json:"connectors"` // enrolled, non-revoked connectors; Edges refuse all others
}

// EdgeConnector is a connector an Edge may accept broker connections from.
type EdgeConnector struct {
	ConnectorID string `json:"connectorId"`
	TenantID    string `json:"tenantId"`
	Group       string `json:"group"`
	// CertSerial is the connector's current certificate serial (decimal). Edges accept only
	// that certificate on the broker (ST-04).
	CertSerial string `json:"certSerial"`
}

// EdgeDevice is a device an Edge may accept, with its signed policy snapshot.
type EdgeDevice struct {
	DeviceID string          `json:"deviceId"`
	TenantID string          `json:"tenantId"`
	Snapshot policy.Envelope `json:"snapshot"`
	// CertSerial is the device's current certificate serial (decimal). Edges set up sessions
	// only with that certificate, so a superseded or never-delivered one is refused (ST-01).
	CertSerial string   `json:"certSerial"`
	Routes     []string `json:"routes,omitempty"`
	// TunnelOffset is the device's host offset in the tunnel prefixes (pkg/tunneladdr),
	// assigned by the Control Plane so the device has the same tunnel addresses on every
	// Edge (issue #70). 0: the Edge picks one (older Control Plane).
	TunnelOffset uint32 `json:"tunnelOffset,omitempty"`
}

// DeviceRoutes is the body of GET/PUT /v1/admin/tenants/{tenant}/devices/{device}/routes (issue #21, slice B).
type DeviceRoutes struct {
	CIDRs []string `json:"cidrs"`
}

// AdminTenant is a tenant in the admin API.
type AdminTenant struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// AdminIdentity is the reply to GET /v1/admin/whoami.
type AdminIdentity struct {
	// Role is "super" (the configured token) or "tenant" (an admin token of TenantID).
	Role     string `json:"role"`
	TenantID string `json:"tenantId,omitempty"`
	TokenID  string `json:"tokenId,omitempty"`
	// TenantRole is the role of a tenant admin token (ADR-0027): admin, policy-editor or viewer.
	TenantRole string `json:"tenantRole,omitempty"`
}

// Roles of tenant admin tokens (ADR-0027).
const (
	TenantRoleAdmin        = "admin"         // everything in the tenant
	TenantRolePolicyEditor = "policy-editor" // read, and PUT the tenant policy
	TenantRoleViewer       = "viewer"        // read only
)

// AdminTokenRequest creates a tenant admin token. ValidFor defaults to 90 days, at most 365.
type AdminTokenRequest struct {
	Name     string `json:"name"`
	ValidFor int    `json:"validForSeconds"`
	Role     string `json:"role,omitempty"` // TenantRole*; default admin
}

// AdminToken is a tenant admin token in the admin API, without its secret.
type AdminToken struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Revoked   bool      `json:"revoked"`
	LastUsed  time.Time `json:"lastUsed,omitzero"`
	Role      string    `json:"role"`
}

// AdminTokenCreated is the reply to admin token creation. Token is shown only once.
type AdminTokenCreated struct {
	AdminToken
	Token string `json:"token"`
}

// AuditEntry is one admin write (POST, PUT, DELETE under /v1/admin), recorded whatever its
// outcome. Actor is "super" or "token:<admin token ID>"; secrets are never recorded.
type AuditEntry struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	TenantID string    `json:"tenantId,omitempty"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
}

// AdminUser is a user in the admin API.
type AdminUser struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ProvisioningKeyRequest asks for a device provisioning key for a user.
type ProvisioningKeyRequest struct {
	UserID   string `json:"userId"`
	MaxUses  int    `json:"maxUses"`
	ValidFor int    `json:"validForSeconds"`
}

// ProvisioningKey is a newly issued device provisioning key.
type ProvisioningKey struct {
	Key       string    `json:"key"`
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// TenantPolicy is the tenant layer. Rules must all have Source=tenant.
type TenantPolicy struct {
	DefaultAction  policy.Action               `json:"defaultAction"`
	AllowUserRules bool                        `json:"allowUserRules"`
	Lockdown       bool                        `json:"lockdown"`
	Rules          []policy.Rule               `json:"rules"`
	Apps           map[string]policy.AppPolicy `json:"apps"` // tenant-mandated per-app policy; user Apps override only if AllowUserRules
	DNS            policy.DNSPolicy            `json:"dns"`
	PrivateApps    []TenantPrivateApp          `json:"privateApps,omitempty"` // ZTNA apps (ADR-0013)
	SaaS           SaaSPolicy                  `json:"saas,omitzero"`         // SaaS app control (ADR-0017)
	Web            policy.WebPolicy            `json:"web,omitzero"`          // TLS inspection and URL rules, Edge only (ADR-0018)
	Categories     []string                    `json:"categories,omitempty"`  // web categories to block (ADR-0022)
	SafeSearch     bool                        `json:"safeSearch,omitempty"`  // force safe search and restricted video modes (ADR-0025)
	// Cloud-only decision data for "ask" flows, too large or too sensitive for devices.
	DecideBlockDomains []string      `json:"decideBlockDomains,omitempty"`
	DecideBlockCIDRs   []string      `json:"decideBlockCidrs,omitempty"`
	DecideDefault      policy.Action `json:"decideDefault"` // allow|block
}

// SaaSPolicy blocks applications of the built-in SaaS catalog (pkg/saas, ADR-0017). The
// Control Plane compiles it into DNS blocklists with IDs "saas:<app>", so it is enforced on
// DNS answers on the device and at the Edge, and on the TLS SNI or HTTP Host of Edge flows.
// DNS.AllowDomains still overrides it.
type SaaSPolicy struct {
	BlockApps       []string `json:"blockApps,omitempty"`       // catalog app IDs
	BlockCategories []string `json:"blockCategories,omitempty"` // catalog categories
	AllowApps       []string `json:"allowApps,omitempty"`       // exempt from BlockCategories (not from BlockApps)
}

// SaaSApp is one entry of the SaaS catalog (GET /v1/admin/saas/catalog).
type SaaSApp struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Domains  []string `json:"domains"`
}

// RenewRequest is the body of POST /v1/renew and POST /v1/connector/renew.
type RenewRequest struct {
	CSRPEM string `json:"csrPem"` // PKCS#10 for a freshly generated ECDSA P-256 key
}

// RenewResponse is the reply to a certificate renewal.
type RenewResponse struct {
	CertificatePEM string `json:"certificatePem"` // device cert followed by the tenant CA
	CAPEM          string `json:"caPem"`
}

// EdgeSessions is the body of POST /v1/edge/sessions: the peers with a live session on that Edge.
type EdgeSessions struct {
	DeviceIDs    []string `json:"deviceIds"`
	ConnectorIDs []string `json:"connectorIds,omitempty"` // connectors with a live broker connection
}

// AdminEdge is a registered Edge in the admin API.
type AdminEdge struct {
	ID string `json:"id"`
	// TenantID binds the Edge to one tenant (a Private Edge, ADR-0014); "" = public multi-tenant
	// Edge. Set at registration only.
	TenantID  string    `json:"tenantId,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"createdAt,omitzero"`
}

// Broker request headers (ADR-0013).
const (
	BrokerALPN         = "opensase-broker/1"
	BrokerHeaderTarget = "X-Opensase-Target" // "name:port", name is the PrivateApp domain the client resolved
	BrokerHeaderApp    = "X-Opensase-App"    // PrivateApp.ID
	BrokerHeaderDevice = "X-Opensase-Device" // device ID, for connector logs
)

// ConnectorEnrollRequest is the body of POST /v1/connector/enroll.
type ConnectorEnrollRequest struct {
	ProvisioningKey string `json:"provisioningKey"`
	CSRPEM          string `json:"csrPem"`
}

// ConnectorEnrollResponse is the reply to POST /v1/connector/enroll: the connector identity.
type ConnectorEnrollResponse struct {
	TenantID       string `json:"tenantId"`
	ConnectorID    string `json:"connectorId"`
	Group          string `json:"group"`
	CertificatePEM string `json:"certificatePem"`
	CAPEM          string `json:"caPem"`
	ControlURL     string `json:"controlUrl"`
}

// ConnectorConfig tells a connector which Edges to keep a broker connection to and which apps
// it may dial (the apps of its group). Version increases on every change.
type ConnectorConfig struct {
	Version uint64              `json:"version"`
	Edges   []EdgeInfo          `json:"edges"`
	Apps    []policy.PrivateApp `json:"apps"`
}

// AdminConnectorRequest creates a connector in the admin API.
type AdminConnectorRequest struct {
	Name  string `json:"name"`
	Group string `json:"group"` // default "default"
}

// AdminConnector is a connector in the admin API.
type AdminConnector struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	Name      string    `json:"name"`
	Group     string    `json:"group"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"createdAt"`
	LastSeen  time.Time `json:"lastSeen,omitempty"` // last time an Edge reported a live broker connection
}

// AdminConnectorCreated is the reply to connector creation, with its one-time provisioning key.
type AdminConnectorCreated struct {
	Connector       AdminConnector `json:"connector"`
	ProvisioningKey string         `json:"provisioningKey"` // single use, 24h
}

// InspectionCARequest asks the Control Plane for an Edge's inspection intermediate of one
// tenant (ADR-0018). CSR is a PEM PKCS#10 request for a P-256 key the Edge generated.
type InspectionCARequest struct {
	TenantID string `json:"tenantId"`
	CSR      string `json:"csr"`
}

// InspectionCAResponse carries the intermediate followed by the tenant inspection root (PEM).
type InspectionCAResponse struct {
	Chain     string    `json:"chain"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// CategoryCatalog describes the web category list the Control Plane loaded (ADR-0022).
type CategoryCatalog struct {
	Source     string        `json:"source"`
	Licence    string        `json:"licence"`
	URL        string        `json:"url"`
	Version    string        `json:"version,omitempty"` // "" when no list is loaded
	LoadedAt   time.Time     `json:"loadedAt,omitzero"`
	Categories []WebCategory `json:"categories"`
}

// WebCategory is one category of the list.
type WebCategory struct {
	Name        string   `json:"name"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type"` // black | white (allow lists, cannot be blocked)
	Domains     int      `json:"domains"`
	URLs        int      `json:"urls,omitempty"` // URL (path) entries, enforced on the inspected path
	Aliases     []string `json:"aliases,omitempty"`
}

// AdminInfo describes the Control Plane to admin clients (GET /v1/admin/info).
type AdminInfo struct {
	// ControlURL is the URL devices enroll with, including the "#sha256=<root pin>" fragment.
	ControlURL string   `json:"controlUrl,omitempty"`
	RootSHA256 string   `json:"rootSha256"`
	Version    string   `json:"version"`
	Features   []string `json:"features,omitempty"`
}

// AuditVerification is the result of checking the admin audit hash chain (ADR-0028).
type AuditVerification struct {
	OK       bool   `json:"ok"`
	Entries  int    `json:"entries"`
	HeadID   int64  `json:"headId"`
	Head     string `json:"head"` // hex SHA-256 of the newest entry: publish it to pin the history
	AnchorID int64  `json:"anchorId,omitempty"`
	BadID    int64  `json:"badId,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Pinned is the result of the id/hash check: match, mismatch, missing or removed by retention.
	Pinned string `json:"pinned,omitempty"`
}

// DLPDatasetRequest creates or replaces a DLP dataset (ADR-0029). For kind "values", Values
// are the records to protect (1 to 4 words each). For kind "document", Documents are files
// (text, Office, PDF, ZIP...) whose text is fingerprinted. The Control Plane keeps only keyed
// hashes and discards the content.
type DLPDatasetRequest struct {
	Kind      string   `json:"kind"`
	Values    []string `json:"values,omitempty"`
	Documents [][]byte `json:"documents,omitempty"`
}

// DLPDataset describes a stored dataset.
type DLPDataset struct {
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Entries   int       `json:"entries"` // distinct values or document shingles
	UpdatedAt time.Time `json:"updatedAt"`
}

// EdgeDatasets carries datasets to an Edge: the HMAC key and the sorted 64-bit hashes
// (8 bytes each, big-endian).
type EdgeDatasets struct {
	Datasets []EdgeDataset `json:"datasets"`
}

// EdgeDataset is one dataset for an Edge.
type EdgeDataset struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Key    []byte `json:"key"`
	Hashes []byte `json:"hashes"`
}

// TenantOIDC configures OpenID Connect sign-in for tenant admins (issue #17, slice B, ADR-0031).
// GroupRoles maps IdP group names to tenant roles ("admin", "policy-editor", "viewer").
// On GET, ClientSecret is omitted and HasSecret indicates whether a secret is configured.
// RedirectURL is the callback URL to configure with the identity provider.
type TenantOIDC struct {
	Issuer       string            `json:"issuer"`
	ClientID     string            `json:"clientId"`
	ClientSecret string            `json:"clientSecret,omitempty"`
	HasSecret    bool              `json:"hasSecret,omitempty"`
	GroupRoles   map[string]string `json:"groupRoles"`
	RedirectURL  string            `json:"redirectUrl,omitempty"`
}
