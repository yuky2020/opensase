# ADR-0014: Private Edge (single-tenant mode and offline operation)

Status: accepted (2026-11-20)

## Context

`docs/architecture.md` promises a Private Edge: the same Edge binary on customer premises,
serving one tenant, with local internet breakout, and still enforcing policy when the Control
Plane is unreachable. So far every Edge is multi-tenant. Every Edge receives every tenant's
devices and connectors, and an Edge with no Control Plane at startup waits for it forever.

## Decision

### Tenant binding is the Control Plane's decision

- `edges.tenant_id` (migration 0004) binds a registered Edge to one tenant. NULL means a public,
  multi-tenant Edge. It is set at registration (`POST /v1/admin/edges {"id","tenantId"}`,
  `opensasectl edge add -id X -tenant T`) and never changes: re-binding an Edge to another
  tenant means registering a new Edge ID.
- For a private Edge, the Control Plane scopes everything to that tenant:
  - `GET /v1/edge/peers` carries only that tenant's devices and connectors.
  - `POST /v1/decide` and `POST /v1/flows` refuse devices of other tenants. `edgeDevice` checks
    the device's tenant before the live-session check.
  - `POST /v1/edge/sessions` ignores other tenants' devices.
- Devices and connectors only learn about Edges they may use: the Edge list in `EnrollResponse`
  and in `ConnectorConfig` holds the public Edges plus the private Edges of the caller's own
  tenant.

### The Edge enforces the same binding (defence in depth)

`edge -tenant T`:
- keeps only `T`'s CA from the PKI bundle, so certificates of other tenants fail chain
  verification;
- drops devices and connectors of other tenants from the peer feed, and logs the drop because
  it means a misconfiguration.

A public Edge (no `-tenant`) behaves as before.

### Offline operation: a local state cache

`edge -state-dir DIR` persists the last good Control Plane state after every sync that changed
it: the PKI bundle and the peer feed, in `DIR/state.json`. The file is written atomically
(temp file, fsync, rename) with mode 0600.

At startup, the Edge tries the Control Plane once. If that fails and a cache exists, it loads the
cache and starts serving at once. It then keeps retrying in the background, as the periodic peer
sync already does.

The cache is treated as untrusted input on load and goes through the same checks as a live
response:
- tenant CAs must chain to the configured root;
- every snapshot must verify against the cached signing keys.

A cache that fails these checks is ignored. Someone who can write the state dir can also read the
Edge key, so the cache adds no new trust.

While offline:
- **Already enrolled devices** keep working. They set up sessions with their certificate, which
  is verified locally, and their signed snapshots are enforced, including after `ExpiresAt`
  (snapshot expiry only marks them stale, as on devices).
- **Connectors** keep their broker connections and can reconnect, because the allow-list comes
  from the cached feed.
- **"ask" verdicts** fail closed, as today.
- **Flows** buffer in memory (`maxFlowBuffer`) and are uploaded when the Control Plane is back.
  With `-flow-log FILE` the Edge also appends every flow record to a local JSONL file. The file
  is rotated to `FILE.1` at 64 MiB, so on-prem auditing does not depend on the cloud.

### Local breakout

This is not new: the Edge already NATs tunnel traffic out of its own uplink. A Private Edge
usually also sets `-allow-private` so that clients can reach the site LAN.

## Consequences

- Limitations of offline operation:
  - device certificates live 24h and are renewed at the Control Plane, so an outage longer than
    the remaining lifetime ends sessions;
  - new enrollments, policy changes and revocations wait for the Control Plane;
  - a revocation made during an outage only takes effect at the next successful sync.
- A private Edge's feed and decisions are limited to its tenant even if the Edge itself is
  compromised. This is the Control Plane's filter, not the Edge's.
- The Edge registry gains a column. Existing Edges stay public.
