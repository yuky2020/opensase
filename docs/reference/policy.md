# Tenant policy reference

OpenSASE defines tenant-level security configurations using a single JSON document conforming to the
JSON Schema standard.

The full JSON schema specification is available at [tenant-policy.schema.json](../schema/tenant-policy.schema.json).
The Go type definitions live in `pkg/api/types.go` (`api.TenantPolicy`).

Policies are managed with `opensasectl policy get` and `opensasectl policy set` (see [CLI reference](cli.md)),
or through the admin portal under **Policy**.

---

## Top-level fields

| Field | Type | Description |
|---|---|---|
| `defaultAction` | `string` | Fallback action when no firewall rule matches. Allowed values: `"allow"`, `"block"`, `"ask"`. |
| `allowUserRules` | `boolean` | When `true`, user-defined firewall rules and per-app policies are evaluated after tenant rules. When `false`, user rules return HTTP 403. |
| `lockdown` | `boolean` | When `true`, enables lockdown mode: unclassified traffic and unmanaged applications are blocked by default. |
| `disableKillSwitch` | `boolean` | When `true`, disables the fail-closed desktop kill switch on Linux and Windows clients, allowing traffic outside the tunnel. Default is `false` (kill switch active). |
| `rules` | `array` | Ordered list of tenant network firewall rules evaluated per flow. |
| `apps` | `object` | Mandatory per-application network restrictions keyed by application identifier (e.g. package name or executable). |
| `dns` | `object` | DNS security configuration, including custom zones, internal records, forwarders, and domain blocklists. |
| `privateApps` | `array` | ZTNA private applications published through Connectors ([ADR-0013](../adr/0013-ztna-connector.md)). |
| `saas` | `object` | Cloud SaaS application controls based on the built-in application catalog ([ADR-0017](../adr/0017-web-saas-control-sni.md)). |
| `web` | `object` | TLS inspection, URL filtering, HTTP header injection, DLP, and malware scanning configuration ([ADR-0018](../adr/0018-tls-inspection.md)). |
| `categories` | `array` | List of web category names to block across DNS queries and TLS SNI hostnames ([ADR-0022](../adr/0022-web-categories-ut1.md)). |
| `safeSearch` | `boolean` | When `true`, forces SafeSearch and restricted mode on supported search engines and video platforms ([ADR-0025](../adr/0025-safesearch.md)). |
| `customLists` | `array` | External domain blocklists downloaded from HTTPS URLs every 6 hours. |
| `builtinLists` | `array` | Built-in threat intelligence blocklist identifiers to enforce (for example `["malware"]`). |
| `mesh` | `object` | Device-to-device mesh connectivity rules ([ADR-0034](../adr/0034-device-mesh.md)). Off when omitted. |
| `decideBlockDomains` | `array` | Domain names blocked exclusively by the cloud decision API for deferred ("ask") flows. |
| `decideBlockCidrs` | `array` | Destination CIDR prefixes blocked exclusively by the cloud decision API for deferred ("ask") flows. |
| `decideDefault` | `string` | Fallback action for flows deferred to the cloud decision API (`"allow"` or `"block"`). |

---

## Field details

### `rules`

An array of firewall rule objects. Rules are evaluated in priority order (lowest priority integer first):

- `id`: Stable string identifier for the rule.
- `source`: Must be `"tenant"`.
- `priority`: Integer evaluation priority.
- `action`: Enforcement decision (`"allow"`, `"block"`, or `"ask"`).
- `match`: Flow match conditions:
  - `apps`: Array of matching application identifiers.
  - `networks`: Array of network types (`"wifi"`, `"cellular"`, `"roaming"`, `"ethernet"`, `"unknown"`).
  - `protocols`: Array of transport protocols (`"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"`; `"icmp"` matches both ICMPv4 and ICMPv6).
  - `cidrs`: Array of destination IP CIDRs (IPv4 and IPv6).
  - `ports`: Array of port ranges (`from` and `to` integers, `0` to `65535`).
  - `domains`: Array of matching destination domain names or wildcards.
- `users`: Optional list of user IDs or email addresses permitted to match this rule.
- `groups`: Optional list of identity provider group names permitted to match this rule.
- `log`: Boolean flag indicating whether flows matching this rule must generate audit flow logs.
- `description`: Plain-text description of the rule intent.

### `apps`

A map of application identifiers to network permission objects:

```json
{
  "com.example.app": {
    "wifi": "allow",
    "cellular": "block",
    "roaming": "block"
  }
}
```

Permitted values for network interfaces are `"allow"`, `"block"`, and `"ask"`.

### `dns`

Configures the Edge internal DNS resolver:

- `blockResponse`: DNS answer format for blocked queries (`"nxdomain"` or `"zero"`).
- `blocklists`: Array of domain blocklists embedded directly in the policy.
- `allowDomains`: Domains explicitly exempt from all DNS blocks and threat lists.
- `blockDomains`: Custom domain names blocked across all clients.
- `redirectQueries`: When `true`, intercepts plain DNS queries sent to foreign resolvers and answers them at the Edge.
- `zone`: Internal DNS zone suffix (e.g. `"corp.internal"`). Devices resolve as `<device>.<user>.<zone>`.
- `records`: Array of static internal DNS records (`name`, `type` [`A`, `AAAA`, `CNAME`, `TXT`], `value`, `ttl`).
- `forwarders`: Array of conditional DNS forwarders routing specific internal zones to upstream corporate resolvers (`zone`, `servers`).
- `logQueries`: When `true`, logs allowed DNS resolutions as flow records.

### `privateApps`

Defines ZTNA private applications reachable through Connectors:

- `id`: Unique application identifier.
- `name`: Display name.
- `domains`: Domain names that route to this application.
- `ports`: Allowed port ranges (`from`, `to`).
- `connectorGroup`: Connector group responsible for reaching the target application.
- `users`: User IDs or emails authorized to access the application. Omit to grant access to all tenant users.

### `saas`

Enforces access controls for cloud SaaS services without TLS decryption:

- `blockApps`: Array of catalog application IDs to block.
- `blockCategories`: Array of catalog application categories to block.
- `allowApps`: Array of catalog application IDs exempt from category-level blocks.

### `web`

Configures TLS inspection on Edge proxies:

- `inspect`: When `true`, enables man-in-the-middle TLS decryption using the tenant CA.
- `blockECH`: When `true`, strips Encrypted Client Hello (ECH) parameters from DNS HTTPS/SVCB records so domain SNIs remain inspectable ([ADR-0030](../adr/0030-ech-and-http3.md)).
- `bypass`: Array of domains exempt from TLS inspection (e.g. banking or privacy-sensitive services).
- `rules`: HTTP URL inspection rules (`id`, `domains`, `pathPrefixes`, `methods`, `action`).
- `headers`: Custom HTTP headers injected into outbound requests (`domains`, `name`, `value`).
- `dlp`: Data loss prevention scanning rules ([ADR-0019](../adr/0019-dlp-request-bodies.md), [ADR-0021](../adr/0021-dlp-documents-downloads.md)).
- `malware`: Antivirus scanning controls for uploads and downloads ([ADR-0020](../adr/0020-malware-scanning.md)).

### `mesh`

Configures peer-to-peer device mesh networking ([ADR-0034](../adr/0034-device-mesh.md)):

- `directLinks`: When `true`, allows devices on the same physical network to negotiate direct WireGuard links bypassing the Edge.
- `rules`: Access rules between devices specifying source (`from`), destination (`to`), protocol (`"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"`, or empty for any; `"icmp"` matches both ICMPv4 and ICMPv6), and port ranges.

---

## Minimal policy example

```json
{
  "defaultAction": "allow",
  "allowUserRules": true,
  "lockdown": false,
  "rules": [
    {
      "id": "block-quic",
      "source": "tenant",
      "priority": 100,
      "action": "block",
      "match": {
        "protocols": ["udp"],
        "ports": [{"from": 443, "to": 443}]
      },
      "description": "Block QUIC to force HTTP/2 inspection",
      "log": true
    }
  ],
  "dns": {
    "blockResponse": "nxdomain",
    "allowDomains": [],
    "blockDomains": []
  },
  "decideDefault": "allow"
}
```
