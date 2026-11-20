# OpenSASE — Architecture Overview (draft v0.1)

Working name: **OpenSASE**. Status: design phase, no code yet.

## Goal

An open-source SASE platform that can be self-hosted or run as a multi-tenant SaaS,
covering the same building blocks as commercial offerings (ZTNA, SWG, CASB, FWaaS, DLP)
with these deployable entities:

| Entity | Runs where | Role |
|---|---|---|
| **Client** | User endpoint (Win/macOS/Linux/iOS/Android) | Steers user traffic to the nearest Edge; posture checks; user identity |
| **Connector** | Customer DC / VPC, next to private apps | Dials *outbound* to Edges; exposes private apps without inbound ports |
| **Workload Gateway** | Customer VPC/VNet (workloads, not users) | Forwards workload-to-internet / workload-to-workload traffic into the fabric |
| **Edge (public)** | Provider PoPs | Multi-tenant data plane: ZTNA broker, SWG, FWaaS, inline CASB/DLP |
| **Private Edge** | Customer premises | Same Edge binary, single-tenant mode, local breakout, works if cloud is unreachable (cached policy) |
| **Control Plane** | Provider cloud (or self-hosted) | Tenants, identity, policy authoring/compilation, config distribution, enrollment PKI, logs, API/UI |

## Core design principles

1. **Zero trust, deny by default.** Every flow is authorized per user/device/app/context.
2. **Outbound-only connectors.** App/Workload Gateways never accept inbound connections.
3. **One Edge binary, many roles.** Public Edge, Private Edge and ZTNA broker are the same
   software with different config; reduces effort and drift.
4. **Control plane / data plane split.** Data plane keeps working on the last good policy
   snapshot when the control plane is unreachable.
5. **Policy compiled centrally, evaluated locally.** Policies are authored once, compiled into
   versioned, signed snapshots, pushed to Edges/Connectors, evaluated in-process (no RPC per flow).
6. **Strong workload identity.** Every component enrolls with a one-time token and gets a
   short-lived mTLS certificate (SPIFFE-style IDs) from the tenant CA.
7. **Multi-tenancy from day one.** Tenant ID in every object, cert, log line and policy snapshot.
8. **Quantum safe by default.** All key exchanges are hybrid (X25519 + ML-KEM-768). There is no classic-only downgrade (ADR-0002).
9. **Standards over invention.** WireGuard / MASQUE (HTTP/3 CONNECT-IP/UDP), OIDC/SAML, SCIM,
   OpenTelemetry, ICAP.

## Traffic flows

```
           ┌────────────────────── Control Plane ───────────────────────┐
           │ API/UI · Tenants · Policy compiler · PKI · Config bus · Logs│
           └───────▲──────────────▲────────────────▲───────────────▲────┘
                   │ mTLS (cfg/telemetry)          │               │
 ┌──────────────┐  │      ┌───────┴────────┐       │      ┌────────┴───────┐
 │Client Conn.  │──┴─────▶│  Edge  │◀──────┴──────│ Connector  │──▶ private apps
 │(user device) │ tunnel  │ (public/private)│ outbound    │ (customer DC)  │
 └──────────────┘         │ ZTNA broker    │ reverse tun. └────────────────┘
                          │ SWG / FWaaS    │
 ┌──────────────┐ tunnel  │ CASB / DLP     │──────────▶ Internet / SaaS
 │Cloud Conn.   │────────▶│                │
 │(VPC workloads)│        └────────────────┘
 └──────────────┘
```

- **ZTNA (private apps):** Client → nearest Edge → policy check → Edge stitches the flow onto
  an existing outbound tunnel from a Connector that can reach the app → app.
  Apps are addressed by FQDN; the Client resolves them to synthetic IPs (DNS interception).
- **Internet/SaaS:** Client or Workload Gateway → Edge → SWG (TLS inspection optional) →
  URL/category/CASB/DLP policy → egress.
- **Workloads:** Workload Gateway routes VPC egress (via cloud route tables / GWLB GENEVE) into Edge.

## Proposed technology baseline (to be confirmed via ADRs)

| Area | Proposal | Alternatives |
|---|---|---|
| Language (control plane, edge, connectors) | Go | Rust for data-plane hot path later |
| Client tunnel | WireGuard (wireguard-go + gVisor netstack) with post-quantum hybrid PSK (ADR-0002) | MASQUE over QUIC (Phase 2 fallback) |
| Connector ↔ Edge | Outbound mTLS over HTTP/2 or QUIC, multiplexed streams | WireGuard |
| SWG proxy | Custom Go proxy (forward + transparent, TLS MITM) | Envoy + ext_authz |
| Policy language | OPA/Rego for authoring, compiled to Go decision tables | Cedar |
| Config distribution | gRPC streaming (xDS-like), NATS JetStream internally | etcd watch |
| Primary DB | PostgreSQL | — |
| Logs/analytics | ClickHouse via OpenTelemetry collector | OpenSearch |
| Identity | External IdP via OIDC/SAML + SCIM; Keycloak bundled for self-host | — |
| UI | React + TypeScript admin portal | — |
| Deployment | Kubernetes (Helm) for control plane & public edge; single binary/VM image for connectors & private edge | — |

## Repository layout (planned monorepo)

```
cmd/            edge, connector, workload-gateway, controlplane, client (CLI/daemon)
pkg/            tunnel, policy, pki, enroll, proxy, dns, telemetry, configbus
clients/        desktop (Go daemon + per-OS UI), mobile (Swift/Kotlin wrappers)
web/            admin portal
deploy/         helm, terraform (AWS/Azure/GCP), packer images
docs/           architecture, components, adr
```

See `docs/components/` for per-component specs and `docs/effort-estimate.md` for sizing.
