# ADR-0022: Web categories from a public list (UT1)

Status: accepted (2026-11-21)

## Context

Tenants want to block whole kinds of sites: adult, gambling, malware, phishing, and so on.
Listing domains by hand does not scale, and OpenSASE should not maintain its own category
database.

The commonly used open list is the **UT1 blacklists** of Université Toulouse Capitole:
- maintained since about 2000 for French schools and academic networks;
- the default or recommended list of SquidGuard, E2Guardian and the web filter plugins of
  pfSense and OPNsense;
- licensed CC BY-SA 4.0;
- updated almost daily.

It publishes one archive, `blacklists.tar.gz`, of about 26 MB compressed. On 2026-11-21 it
held 69 categories plus aliases, with 5.8 million unique domains; `adult` alone has
4.6 million.

That size rules out the existing paths:
- SaaS lists (ADR-0017) are compiled into every device snapshot, which would be far too large;
- devices have no need for the list, because their DNS already goes through the Edge resolver.

## Decision

### The list lives on the Control Plane

- `controlplane -categories-file FILE -categories-url URL` sets the list. The dev compose uses
  the UT1 archive URL and `data/categories.tar.gz`.
- At start the Control Plane loads the cached archive. It then downloads updates every 24 hours
  with `If-Modified-Since`.
- A download is parsed and validated before it atomically replaces the cache. A broken or
  oversized archive (over 256 MiB) never replaces a good one.
- Parsing (`pkg/categories.ParseUT1`):
  - reads every `<category>/domains` file;
  - turns the symbolic links between categories into aliases (`porn` → `adult`);
  - reads the `global_usage` catalogue: English titles and descriptions, and the type
    `black` or `white`.
- Entries are normalized (lower case, no trailing dot or leading `*.`) and invalid lines are
  skipped. Overlong lines are skipped, not fatal.
- Each category is stored as sorted 64-bit FNV-1a hashes of its names: 8 bytes per domain, and
  a lookup is one binary search per label suffix. As in SquidGuard, an entry matches the name
  and its subdomains. With 5.8 million names, the chance that an unlisted name hashes onto a
  listed one is about 10⁻¹².
- `GET /v1/admin/categories` lists the loaded categories, with domain counts, the source and
  the licence. It powers `opensasectl categories` and the portal page.
- The licence is honoured by attribution in the API, the CLI and the portal. The archive is
  never committed to this Apache-2.0 repository: it is downloaded at run time.

### Policy

- `TenantPolicy.categories` is the list of category names to block, copied into every device
  snapshot (`Snapshot.Categories`, a few bytes).
- When a list is loaded, the Control Plane refuses unknown names, and `white` categories (allow
  lists such as `liste_blanche`). Without a list only the syntax is checked, so policies can be
  written before the first download.

### Enforcement at the Edge

- Every 30 seconds the Edge computes the union of the categories in its devices' policies.
- It fetches exactly those from `GET /v1/edge/categories?names=…` (edge mTLS, binary format with
  an ETag). It fetches again when the set changes, and hourly with `If-None-Match`.
- A Private Edge only has its tenant's devices, so it only asks for that tenant's categories.
- The Edge checks categories:
  - in its **DNS resolver**: the queried name and every CNAME target. A block answers like the
    DNS policy (NXDOMAIN or zero) and is recorded as layer `dns`, rule `cat:<name>`;
  - on the **hostname of every TCP flow** (TLS SNI or HTTP Host, ADR-0017), so a hard-coded
    address or another resolver does not escape. A block resets the flow, layer `web`, rule
    `cat:<name>`.
- The tenant's DNS `allowDomains` override categories, for false positives.
- **Fail open:** until the Edge has a list, categories are not enforced. A category list is a
  coarse filter, and blocking all traffic while it loads would be worse. The Edge logs every
  failed sync and keeps the last good list.

## Consequences

- **Memory.** An Edge serving a tenant that blocks `adult` holds about 37 MB for it. The Control
  Plane holds the whole list, about 46 MB.
- **List quality.** False positives and gaps are those of UT1; `allowDomains` corrects them per
  tenant.
- **URL entries** (the `urls` files, about 75,000 path-level entries in 2026-11) are hashed like
  domains. They are enforced on the inspected path (ADR-0018): a request is refused when its
  host, or a parent domain, followed by its path up to a `/` boundary, the whole path, or the
  path with its query matches an entry. Matching ignores case. It is recorded as
  `cat:<name>:url`. Without inspection only whole domains are enforced. This was added after
  the first slice, in the same ADR.
- **Freshness.** A new UT1 release reaches the Edges within a day plus an hour.
- After an Edge restart without the Control Plane, categories wait for it (the list is not in
  the signed state cache). This is consistent with fail open.
- The list could be replaced by another source in the same archive layout, as many SquidGuard
  lists are, without code changes.
