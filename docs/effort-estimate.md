# OpenSASE — Effort Estimate (draft v0.1)

Unit: **person-months (PM)** of experienced engineers. Ranges reflect uncertainty at design
phase (±40%). Estimates assume Go everywhere except UI and mobile, and reuse of mature OSS
(wireguard-go, gVisor netstack, OPA, ClamAV, Keycloak, ClickHouse, OTel).
AI-assisted coding lowers implementation time for boilerplate (API, UI, docs, tests),
but not for OS integration, protocol debugging, security review or scale testing — so it
is applied only partially (column "AI-adj.", roughly −25% on suitable work).

## Per component

| # | Component | MVP (PM) | Full parity (PM) | AI-adj. MVP | Hardest parts |
|---|---|---|---|---|---|
| 1 | Control Plane (tenants, API, config bus, inventory) | 6–9 | 18–24 | 4–7 | multi-tenancy, config fan-out at scale, upgrades |
| 2 | Enrollment & PKI (incl. PQ hybrid PSK, ADR-0002) | 3–4.5 | 5–7.5 | 2.5–3.5 | key rotation, revocation, HSM/KMS integration |
| 3 | Identity (OIDC/SAML, SCIM, groups) | 2–3 | 5–7 | 1.5–2 | IdP quirks, SCIM edge cases |
| 4 | Policy engine + compiler + simulation | 4–6 | 10–14 | 3–5 | semantics, performance, safe rollout/rollback |
| 5 | Edge core (tunnels, ZTNA broker, stitching) | 8–12 | 20–30 | 7–10 | performance, multi-tenant isolation, HA |
| 6 | Connector | 3–4 | 6–8 | 2.5–3.5 | reconnection logic, health checks, UDP |
| 7 | Client — Linux/Windows/macOS | 10–14 | 24–36 | 9–12 | WFP/NetworkExtension, DNS, captive portals, updates |
| 8 | Client — iOS/Android | — | 12–18 | — | store review, background limits |
| 9 | Workload Gateway (AWS first) | — | 8–12 | — | GWLB/GENEVE, symmetric routing, per-cloud modules |
| 10 | Private Edge packaging/offline mode | 1–2 | 4–6 | 1–1.5 | cached policy, local logging |
| 11 | SWG (proxy, TLS inspection, URL categories) | 6–8 | 18–24 | 5–6.5 | TLS edge cases, HTTP/2/3, performance |
| 12 | FWaaS + DNS security | 2–3 | 8–12 | 1.5–2.5 | identity-aware rules, IPS integration |
| 13 | CASB inline | — | 8–12 | — | app catalog maintenance, activity parsing |
| 14 | CASB API mode (M365, Google, …) | — | 12–18 | — | per-vendor APIs, rate limits |
| 15 | DLP engine | — | 8–12 | — | file extraction, false positives |
| 16 | Observability (logs, ClickHouse, SIEM export) | 3–4 | 8–12 | 2–3 | volume, retention per tenant |
| 17 | Admin portal + user portal | 4–6 | 12–18 | 2.5–4 | policy editor UX |
| 18 | Terraform provider + CLI | 1 | 3–4 | 0.5–1 | — |
| 19 | Infra: Helm, PoP automation, CI/CD, release signing | 3–4 | 10–14 | 2.5–3 | multi-region PoPs, anycast |
| 20 | Security engineering (threat model, audits, fuzzing, pentest) | 2–3 | 8–12 | 2–3 | not compressible |
| 21 | QA/perf/scale test harness | 2–3 | 8–12 | 1.5–2.5 | realistic load |
| | **Total** | **70–100** | **~216–317** | **~56–81** | |

## Phases

| Phase | Scope | Effort | Team of 4 | Team of 8 |
|---|---|---|---|---|
| **0. Foundations** | ADRs, threat model, monorepo, CI, PKI, enrollment, config bus skeleton | ~10 PM | 2.5 mo | 1.5 mo |
| **1. ZTNA MVP** | Control plane, IdP login, policy v1, Edge broker, Connector, Linux+Windows+macOS client, minimal portal, logs | ~45–60 PM | 11–15 mo | 6–8 mo |
| **2. Internet security** | SWG + TLS inspection, URL categories, FWaaS, DNS security, Private Edge | ~25–35 PM | 6–9 mo | 3–5 mo |
| **3. Data security** | CASB inline, DLP, CASB API (M365 + Google) | ~30–40 PM | — | 4–5 mo |
| **4. Workloads & mobile** | Workload Gateway (AWS, then Azure/GCP), iOS/Android | ~30–40 PM | — | 4–5 mo |
| **5. SaaS ops** | Multi-region PoPs, anycast, SLAs, billing hooks, SOC 2 readiness | ~25–40 PM | — | 4–6 mo |

## Reading the numbers

- **Credible ZTNA MVP** (usable open-source private app access):
  ~55–80 PM, so **1 year with 5–6 people** or about 2 years with 2–3.
- **Feature parity with commercial SASE** (SWG + ZTNA + CASB + DLP + Workload Gateway): roughly
  **20–25 person-years**, and that excludes the hard non-code parts: global PoP footprint,
  threat-intel feeds, 24/7 operations, certifications.
- **Solo developer + AI agents:** Phase 0 plus a reduced Phase 1 (Linux client only, a single
  Edge, no HA) is realistic in **6–9 months** part-time-intensive. The rest needs contributors.

## Biggest risks

1. **Client OS integration**, especially macOS NetworkExtension and Windows WFP/drivers:
   the largest and least AI-compressible item.
2. **Data-plane performance and multi-tenant isolation** in the Edge.
3. **Security of the product itself**: a SASE platform is a high-value target, so audits are mandatory.
4. **Data feeds** (URL categories, SaaS app catalog, threat intel): open sources exist but are
   weaker than commercial ones.
5. **Scope creep**: without a hard MVP cut (ZTNA first), the project never ships.

## Recommendation

Start with **Phase 0 + Phase 1 (ZTNA only)**, designed from the start for multi-tenancy and for
the single-binary Edge. Leave SWG/CASB/DLP as interfaces (policy rule kinds and proxy hooks)
without implementing them.
