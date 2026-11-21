---
hide:
  - navigation
---

# OpenSASE

**Open-source, post-quantum SASE platform: zero-trust access, secure egress and policy in one stack.**

OpenSASE connects users, sites and workloads to the internet and to private apps through Edges
that enforce one policy per tenant. Every tunnel and every API uses post-quantum hybrid key
exchange. There is no classic fallback.

[Get started](getting-started.md){ .md-button .md-button--primary }
[Architecture](architecture.md){ .md-button }
[GitHub](https://github.com/yuky2020/opensase){ .md-button }

!!! warning "Pre-alpha"
    The full path works end to end in the dev stack, and APIs and on-disk formats can still
    change. Do not run it in production yet.

<div class="grid cards" markdown>

-   :material-shield-key:{ .lg .middle } __Post-quantum by default__

    ---

    TLS 1.3 with `X25519MLKEM768` only, on every listener. WireGuard tunnels get a hybrid PQ
    pre-shared key.

    [:octicons-arrow-right-24: ADR-0002](adr/0002-client-tunnel-wireguard-pq-psk.md)

-   :material-door-closed-lock:{ .lg .middle } __Zero-trust private access__

    ---

    Private apps behind an outbound-only Connector, reached through the Edge broker. Nothing
    is exposed inbound.

    [:octicons-arrow-right-24: ADR-0013](adr/0013-ztna-connector.md)

-   :material-cellphone-lock:{ .lg .middle } __Android client__

    ---

    Flutter UI on a Go core with an on-device firewall, signed policy snapshots and full
    traffic capture.

    [:octicons-arrow-right-24: ADR-0012](adr/0012-android-client-first.md)

-   :material-office-building-cog:{ .lg .middle } __Private Edge__

    ---

    The same Edge on premises, bound to one tenant, starting offline from a signed cache.

    [:octicons-arrow-right-24: ADR-0014](adr/0014-private-edge.md)

-   :material-server-network:{ .lg .middle } __Workload Gateway__

    ---

    Whole subnets behind the PQ tunnel, with DNS diverted to the Edge and a fail-closed kill
    switch.

    [:octicons-arrow-right-24: ADR-0015](adr/0015-workload-gateway-mvp.md)

-   :material-account-key:{ .lg .middle } __Multi-tenant, audited__

    ---

    Per-tenant CA, a super-admin plus tenant-scoped admin tokens, and an audit log of every
    admin write.

    [:octicons-arrow-right-24: ADR-0016](adr/0016-tenant-admin-tokens.md)

</div>

## Architecture

```mermaid
flowchart LR
    subgraph Users
      A[📱 Android client]
      L[🐧 Linux client]
    end
    subgraph Site["Workload subnet"]
      W[Workloads] --> G[🖥️ Workload Gateway]
    end
    subgraph CP["Control Plane (multi-tenant)"]
      API[Admin API + portal]
      PKI[PKI · per-tenant CA]
      POL[Policy · signed snapshots]
    end
    subgraph Edges
      E[🌐 Public Edge]
      PE[🏢 Private Edge<br/>single tenant]
    end
    C[🔌 Connector<br/>outbound only] --> APP[(Private apps)]

    A -- PQ WireGuard --> E
    L -- PQ WireGuard --> E
    G -- PQ WireGuard --> PE
    E -- broker mTLS --- C
    PE -- broker mTLS --- C
    E --> NET((Internet))
    PE --> NET
    E -. peers · decide · flows .-> CP
    PE -. peers · decide · flows .-> CP
    A -. enroll · renew .-> CP
    C -. enroll · config .-> CP
```

| Component | What it does | Code |
|---|---|---|
| **Control Plane** | Tenants, users, devices, PKI, policy, decisions, flow logs, admin API and portal | `cmd/controlplane`, `internal/controlplane` |
| **Edge** | PQ WireGuard termination, policy enforcement, DNS filter, NAT breakout, ZTNA broker. Public or private | `cmd/edge`, `internal/edge` |
| **Connector** | Outbound-only link from a private network to the Edge broker | `cmd/connector`, `internal/connector` |
| **Linux client / Workload Gateway** | Headless client; `-gateway CIDRS` forwards whole subnets | `cmd/opensase-client` |
| **Android client** | Flutter app plus Go core (`gomobile`) | `clients/mobile`, `mobile/` |
| **Admin portal** | Flutter web, served by the Control Plane at `/admin/` | `clients/admin` |
| **CLI** | Admin and diagnostics (`opensasectl`, including `pq-check`) | `cmd/opensasectl` |

## What works today

| Area | State |
|---|---|
| PQ tunnel (WireGuard + hybrid PSK) | ✅ |
| Enrollment, 24h certificate renewal, revocation, certificate serial pinning | ✅ |
| Signed policy snapshots, on-device firewall, Edge decisions (`allow` / `deny` / `ask`) | ✅ |
| DNS policy (third-party DNS, DoT and DoH bypass blocked), IPv6 leak protection | ✅ |
| ZTNA through the Connector | ✅ |
| Private Edge: tenant binding, signed offline cache, local flow log | ✅ |
| Workload Gateway (routed subnet, NAT, DNS divert, MSS clamp, kill switch) | ✅ |
| Admin portal (tenants, users, policy, private apps, infrastructure, admin tokens, audit, activity) | ✅ |
| Tenant-scoped admin tokens: super-admin plus per-tenant admins ([ADR-0016](adr/0016-tenant-admin-tokens.md)) | ✅ |
| Admin audit log: every admin write, with its actor and result | ✅ |
| SWG / CASB / DLP, cloud GENEVE ingress for the gateway | 🗺️ planned |

## Roadmap

1. **SWG and CASB** on the Edge.
2. Roles inside a tenant, OIDC sign-in for the portal, and audit shipping to an append-only store.
3. Control Plane `GET /v1/admin/info` (pinned control URL for the portal's enrollment QR) and policy ETags.
4. Policy language decision ([ADR-0005](adr/README.md), proposed).
5. Workload Gateway for the cloud: GENEVE ingress, metadata-based identity, per-workload flows.

## Licence

Copyright 2026 The OpenSASE Authors. Licensed under the
[Apache License, Version 2.0](https://github.com/yuky2020/opensase/blob/main/LICENSE). No CLA is
required: contributions are accepted under the same licence.
