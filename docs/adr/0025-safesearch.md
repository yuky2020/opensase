# ADR-0025: SafeSearch enforcement

Status: accepted (2026-11-21)

## Context

Schools and many organisations must keep explicit results out of search engines and video
sites (issue #11). The providers document network-level mechanisms for this:
- a DNS mapping of their hostnames to a "safe" hostname;
- request parameters;
- a request header.

A browser setting alone is not enough: users can turn it off.

## Decision

### Policy

`TenantPolicy.safeSearch: true`, copied into the snapshot (`Snapshot.SafeSearch`) and
enforced by the Edge. The portal switch is on the Web categories page.

### Covered names (`pkg/safesearch`)

| Provider | Names | Safe hostname |
|---|---|---|
| Google Search | `google.<tld>`, `google.co.<cc>`, `google.com.<cc>`, with or without `www.` | `forcesafesearch.google.com` |
| YouTube (strict restricted mode) | `www.`/`m.`/`music.youtube.com`, `youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrict.youtube.com` |
| Bing | `www.bing.com`, `bing.com` | `strict.bing.com` |
| DuckDuckGo | `duckduckgo.com`, `www.duckduckgo.com` | `safe.duckduckgo.com` |

The table is code, reviewed like the SaaS catalog. A provider changing its mechanism means a
code change.

### Enforcement

1. **Edge resolver.** A query for a covered name is answered with a CNAME to the safe hostname
   and that hostname's own A/AAAA records, resolved upstream.
   - HTTPS and SVCB queries get only the CNAME. Their address hints would point to the normal
     servers.
   - The addresses handed out are recorded as safe addresses.
2. **Flow hostnames.** A TCP flow whose TLS SNI or HTTP Host is a covered name must go to a
   safe address. Otherwise it is reset and recorded as `safesearch:bypass`, layer `web`. This
   closes hard-coded addresses and caches filled by another resolver.
   - The Edge refreshes the safe addresses every 5 minutes while any device has SafeSearch, so
     a restarted Edge knows them before the first query.
   - Each address stays known for 6 hours.
3. **Inspected path** (ADR-0018). Search requests also get the providers' parameters:
   - Google: `safe=active`;
   - Bing: `adlt=strict`;
   - DuckDuckGo: `kp=1`.

   YouTube requests get the `YouTube-Restrict: Strict` header. This adds protection where a
   provider honours both mechanisms.

## Consequences

- Other providers are not covered (image search sites, smaller engines). A tenant can block
  them with web categories (ADR-0022) or DNS rules.
- QUIC to a hard-coded address of a covered name is not checked, since there is no SNI check on
  UDP. QUIC to the safe address is fine. Inspecting tenants refuse QUIC anyway (ADR-0018).
- Strict YouTube mode is not configurable yet. A moderate mode (`restrictmoderate.youtube.com`)
  would be a policy option.
- Checks:
  - `pkg/safesearch` and `internal/edge` tests;
  - e2e section 13: CNAME, the safe address works, the bypass is reset;
  - SEC-DP-130: name variants, YouTube, Bing and DuckDuckGo, HTTPS hints, SNI over another
    address.
