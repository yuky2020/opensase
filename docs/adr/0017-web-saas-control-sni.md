# ADR-0017: Web and SaaS control, first slice (hostname inspection without decryption)

Status: accepted (2026-11-21)

## Context

`docs/components/swg.md` and `casb.md` describe a full Secure Web Gateway and CASB: TLS
interception with tenant CAs, URL categories, malware scanning and inline SaaS controls. That
is months of work and it needs a client-trusted CA on every device. Today policy at the Edge
sees addresses, ports and the name the device looked up through the Edge resolver (DNS snooping).
That leaves two gaps:

- **DNS bypass.** A client that reaches a name without asking the Edge resolver is not enforced
  by name. Examples: a hard-coded address, a stale cache, `/etc/hosts`, a second name on a
  shared CDN address.
- **No SaaS visibility or control.** Admins cannot see which SaaS apps are used, nor block an
  app or a whole category without listing its domains by hand.

## Decision

### The Edge reads the hostname of every allowed TCP flow, without decrypting

- When a TCP flow is allowed, the Edge keeps the first bytes the client sends: the client
  stream, reassembled in sequence order, up to 16 KiB.
- `pkg/peek` parses them:
  - a TLS ClientHello gives the `server_name`; the hello may span several segments, since a
    post-quantum key share makes it about 2 KiB, and several records;
  - an HTTP/1.x request head gives the `Host` header, or the CONNECT or absolute-form target.
- Every length is checked; the parser is fuzzed.
- The segments are forwarded while the message is incomplete, and the decision is taken on the
  segment that completes it, before that segment is forwarded. A blocked server therefore never
  receives a complete ClientHello or request head. A segment that arrives beyond a gap is held
  back (dropped, so TCP retransmits it) until the stream is contiguous, so the message cannot be
  completed out of order behind the Edge's back.
- With the hostname, the Edge re-applies policy. Only blocks count; "allow" and "ask" leave the
  earlier decision in place:
  1. the built-in Edge rules (DoH resolvers by name);
  2. the device's DNS policy (blocklists, block domains, SaaS lists; `allowDomains` still
     overrides);
  3. the firewall rules with the hostname as `Flow.Domain`, so a flow allowed for one name
     cannot carry another one.
- **On a block:**
  - the device gets a TCP reset and later segments are dropped;
  - the flow is recorded with layer `web` and rule `saas:<app>`, `dns:<list>` or
    `<layer>:<rule>`;
  - the hostname becomes the flow's `Domain` in the flow records.

### SaaS catalog and SaaS policy

- `pkg/saas` is a small, conservative catalog of well-known SaaS apps (ID, name, category,
  domains). A domain belongs to exactly one app.
- `TenantPolicy.saas` (`blockApps`, `blockCategories`, `allowApps` as exemptions from
  categories) is validated against the catalog.
- The Control Plane compiles the SaaS policy into one DNS blocklist per blocked app, with ID
  `saas:<app>`. **The Policy Snapshot format does not change.** The device resolver, the Edge
  resolver and the Edge hostname check therefore all enforce it.
- **Discovery:** the Control Plane tags every stored flow record with `saasApp`, derived from
  `Flow.Domain`. Values sent by devices or Edges are ignored. The portal's "SaaS apps" page shows
  the apps seen in recent flows and has the block switches.
- `GET /v1/admin/saas/catalog` serves the catalog.

### Why no decryption yet

Interception needs a tenant CA trusted by every device, a bypass list, and per-request
handling of HTTP/2 and pinning. The hostname closes the bypass gap and gives app-level control
at a fraction of the cost and risk. Path-level controls, tenant restrictions and DLP will need
interception later; they will build on the same flow hook.

## Consequences

- **What it cannot see:**
  - **Encrypted Client Hello (ECH):** the Edge sees only the outer, client-facing name, usually
    the provider's shared name. Blocking ECH-capable names needs policy on the outer name.
  - **QUIC (UDP 443):** not inspected. A tenant that wants full coverage blocks UDP 443 with a
    firewall rule, and browsers fall back to TCP.
  - **Long or odd streams:** a ClientHello over 16 KiB, or a stream that is neither TLS nor
    HTTP/1.x, keeps the address-based decision.
- **Cost:** the extra per-flow state (the peek buffer) is freed as soon as the hostname is known,
  normally on the first one or two data segments.
- **Catalog maintenance:** the catalog lives in the Control Plane. It is compiled into the
  snapshots' blocklists, so neither devices nor Edges need an update when it grows.
- **Tests:**
  - unit tests in `pkg/peek`, `pkg/saas`, `internal/edge/web_test.go` and
    `internal/controlplane/saas_test.go`;
  - e2e section 11;
  - security checks SEC-DP-110 to SEC-DP-112 (SNI, subdomain, case, HTTP Host, DNS blocklist
    by SNI).
