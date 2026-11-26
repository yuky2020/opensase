# Policy editor

The **Policy** screen (`/policy`) manages the tenant's security policy. When saved, the Control Plane
compiles and signs a new Policy Snapshot for every device of the tenant ([ADR-0005](../adr/0005-policy-language.md),
[ADR-0012](../adr/0012-android-client-first.md)).

```mermaid
flowchart TD
    Admin[Admin portal / CLI] -->|PUT /v1/admin/tenants/{t}/policy| CP[Control Plane]
    CP -->|Recompile & sign snapshots| DB[(Database)]
    CP -.->|Snapshot long-poll /v1/snapshot| Device[Device core]
    CP -.->|Peer feed /v1/edge/peers| Edge[Edge node]
```

## Policy structure

The policy is submitted as a JSON document to `PUT /v1/admin/tenants/{t}/policy`. It contains the
following main sections:

### General settings

- **Default action (`defaultAction`):** Fallback verdict when no rule matches. Values:
    - `allow`: Permit the flow.
    - `block`: Drop the flow.
    - `ask`: Defer the decision to the Control Plane cloud decision API (`POST /v1/decide`).
- **Allow user rules (`allowUserRules`):** When enabled, client users may configure their own user-layer
  rules on their devices. User rules are evaluated only after all tenant rules have been evaluated.
- **Lockdown mode (`lockdown`):** When enabled, applications not explicitly listed in the tenant or user
  per-app policies are blocked, and unclassified traffic is dropped.
- **Disable desktop kill switch (`disableKillSwitch`):** When set to `true`, turns off the desktop kill
  switch on Linux and Windows clients (default is `false`, keeping the kill switch active).

### Firewall rules (`rules`)

Tenant firewall rules are evaluated in order of **Priority** (ascending integer; lower values match first).
The first matching rule determines the verdict.

Each rule defines:

| Field | Description |
|---|---|
| `id` | Unique identifier (e.g. `rule-10`). |
| `priority` | Integer determining evaluation order. |
| `action` | Verdict: `allow`, `block`, or `ask`. |
| `log` | Boolean flag to record matching flows in flow logs. |
| `description` | Optional text description. |
| `match.domains` | Hostnames: exact (`app.example.com`) or wildcards (`*.example.com` matches subdomains and apex). |
| `match.cidrs` | Destination IPv4 or IPv6 prefixes (e.g. `192.168.1.0/24`). |
| `match.ports` | Destination port ranges with `from` and `to` (e.g. `{"from": 443, "to": 443}`). |
| `match.protocols` | Network protocols: `tcp`, `udp`, `icmp`. |
| `match.networks` | Interface types: `wifi`, `cellular`, `roaming`, `ethernet`, `unknown`. |
| `match.apps` | Application package names (Android). |

#### Scoping by user and group

Tenant rules can be scoped to specific users or identity provider groups ([ADR-0027](../adr/0027-tenant-roles.md), issue #68):

```json
{
  "id": "crm-access",
  "priority": 20,
  "action": "allow",
  "users": ["alice@example.com"],
  "groups": ["sales", "contractors"],
  "match": {
    "domains": ["crm.example.com"],
    "ports": [{"from": 443}]
  }
}
```

- `users`: User IDs or email addresses.
- `groups`: Names of IdP groups synchronized via OIDC or SCIM.

The Control Plane includes the rule **only** in the compiled snapshots of matching users and strips
both fields from the snapshot, ensuring devices and Edges never see user or group memberships.

### Mandatory app policies (`apps`)

Defines network access per application package on mobile devices:

```json
"apps": {
  "com.example.internal": {
    "wifi": "allow",
    "cellular": "allow",
    "roaming": "block"
  }
}
```

Under lockdown mode, only apps listed in the tenant layer or allowed user apps can establish flows.

### Web categories (`categories`)

Blocks domain and URL categories using the public UT1 category list loaded by the Control Plane
([ADR-0022](../adr/0022-web-categories-ut1.md)):

```json
"categories": ["malware", "phishing", "gambling", "adult"]
```

Edges enforce category blocks at the DNS resolver and on the TLS SNI or HTTP Host of every flow.

### SafeSearch (`safeSearch`)

When set to `true`, Edges force SafeSearch on search engines (Google, Bing, DuckDuckGo) and restricted
mode on video streaming sites ([ADR-0025](../adr/0025-safesearch.md)). Enforced via DNS rewrites,
flow hostnames, and HTTP request headers on inspected paths.

### SaaS app control (`saas`)

Controls applications from the built-in SaaS catalog ([ADR-0017](../adr/0017-web-saas-control-sni.md)):

```json
"saas": {
  "blockCategories": ["file-sharing", "social-media"],
  "allowApps": ["approved-storage"],
  "blockApps": ["unapproved-ai"]
}
```

The Control Plane compiles SaaS blocks into DNS blocklists with IDs `saas:<app>` and enforces them on
DNS lookups and Edge TLS SNI/HTTP Host headers without requiring decryption.

### TLS inspection (`web`)

The Edge decrypts and inspects HTTPS traffic for tenant devices ([ADR-0018](../adr/0018-tls-inspection.md)):

- `web.inspect`: Boolean enabling TLS interception.
- `web.blockECH`: Strips Encrypted Client Hello parameters from DNS HTTPS/SVCB responses ([ADR-0030](../adr/0030-ech-and-http3.md)).
- `web.bypass`: Domains exempted from TLS decryption (e.g. banking, health, certificate-pinned apps).
- `web.rules`: Ordered URL path and method rules matching `domains`, `pathPrefixes`, and `methods` with `action: allow | block`.
- `web.headers`: Injects custom HTTP headers into matching requests (e.g. limiting login to corporate tenants).
- `web.malware`: Malware scanning on uploads and downloads using ClamAV or ICAP ([ADR-0020](../adr/0020-malware-scanning.md)).

Devices must install the tenant inspection root CA, downloadable via the portal or CLI:

```bash
opensasectl inspection-ca -tenant <tenant> -o tenant-ca.crt
```

### Data Loss Prevention (`web.dlp`)

Scans HTTP request bodies on inspected uploads, and optionally file downloads ([ADR-0019](../adr/0019-dlp-request-bodies.md),
[ADR-0021](../adr/0021-dlp-documents-downloads.md)):

```json
"web": {
  "inspect": true,
  "dlp": [
    {
      "id": "block-cards",
      "detectors": ["credit-card", "iban"],
      "action": "block",
      "minMatches": 1,
      "blockUnscanned": true
    }
  ]
}
```

- **Built-in detectors:** `credit-card`, `iban`, `tax-id`, `private-key`.
- **Exact data match datasets (`datasets`):** Match keyed hashes of sensitive data records or documents ([ADR-0029](../adr/0029-dlp-exact-data-match.md)).
- **Custom patterns (`patterns`):** Case-insensitive RE2 regular expressions.

## Visual editor and JSON editor

The policy interface provides two synchronized tabs:

1. **Form tab:** Visual forms for general settings, firewall rules with drag-and-drop reordering,
   app policies, and resolver settings.
2. **JSON tab:** Direct editing of the raw `TenantPolicy` JSON document.

Changes in the form immediately update the JSON text. When editing the raw JSON, syntax and schema
validation run live:
- If the JSON contains errors, the **Form** tab is locked to prevent state corruption.
- Correcting the JSON unlocks the form editor.

## Concurrency and If-Match conflicts

To prevent concurrent administrators from overwriting each other's changes, OpenSASE uses HTTP ETags:

1. `GET /v1/admin/tenants/{t}/policy` returns an `ETag` header.
2. When saving, the portal sends `PUT /v1/admin/tenants/{t}/policy` with `If-Match: <etag>`.
3. If another administrator updated the policy in the meantime, the server rejects the request with
   `412 Precondition Failed`.
4. The portal displays a conflict error banner and disables saving.
5. Click **Reload** to fetch the latest server policy, resolve conflicting edits, and save again.
