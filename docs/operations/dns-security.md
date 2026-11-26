# DNS security

Every device resolves names through its Edge resolver (`100.64.0.1`), which applies the
tenant policy. Three tenant policy settings control how DNS is protected (issue #63).

## Blocklists from URLs

`customLists` names domain blocklists that the Control Plane downloads and refreshes every
6 hours:

```json
"customLists": [
  {"id": "corp-bad", "title": "Corporate blocklist", "url": "https://lists.example.com/hosts.txt"}
]
```

- Formats: a hosts file (`0.0.0.0 bad.example`), one domain per line, or domain-only adblock
  rules (`||bad.example^`). Comments with `#` or `!` are skipped.
- An entry blocks the domain and all its subdomains, on DNS and on Edge web traffic, as a web
  category does.
- Only `https://` URLs on public addresses are fetched, up to 64 MiB per list and 32 lists per
  tenant.
- If a download fails, the last good copy stays in force.

## Built-in lists

`builtinLists` enables lists from the built-in catalog by ID
(`GET /v1/admin/blocklists`):

| ID | List | Licence |
|---|---|---|
| `malware` | Malware distribution sites (URLhaus, abuse.ch) | CC0 |

```json
"builtinLists": ["malware"]
```

## Web categories

`categories` blocks categories of the web category list; see
[the categories ADR](../adr/0022-web-categories-ut1.md).

## Forced DNS

By default the Edge blocks DNS that a device sends to any other resolver:

- plain DNS on port 53;
- DNS over TLS on port 853;
- known DNS-over-HTTPS endpoints.

With `dns.redirectQueries`, plain IPv4 DNS to another resolver is answered by the Edge
resolver instead, so applications with a hard-coded resolver keep working under the
policy:

```json
"dns": {"blockResponse": "nxdomain", "redirectQueries": true}
```

DNS over TLS, DNS over HTTPS and IPv6 DNS to other resolvers stay blocked.
