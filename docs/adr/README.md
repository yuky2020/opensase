# Architecture Decision Records

Status values: Proposed, Accepted, Superseded. Each ADR gets its own file `NNNN-title.md` once discussed.

| ADR | Decision | Status | Proposal |
|---|---|---|---|
| 0001 | Primary language for control plane, edge and connectors | Proposed | Go |
| 0002 | Client ↔ Edge tunnel protocol | **Accepted** | WireGuard + PQ hybrid PSK (X25519MLKEM768 TLS exporter); MASQUE fallback later |
| 0003 | Connector ↔ Edge tunnel protocol | Proposed | Outbound mTLS (TLS 1.3, X25519MLKEM768 only), multiplexed HTTP/2 (QUIC later) |
| 0004 | Single Edge binary for public, private and broker roles | Proposed | Yes |
| 0005 | Policy language and evaluation model | Proposed | OPA/Rego authoring, compiled decision tables |
| 0006 | Config distribution mechanism | Proposed | gRPC streaming (xDS-like) + NATS JetStream |
| 0007 | Control plane shape | Proposed | Modular monolith first, split later |
| 0008 | Component identity and PKI | Proposed | Per-tenant intermediate CA, SPIFFE IDs, 24h certs; hybrid Ed25519 + ML-DSA-65 signatures |
| 0009 | Log/analytics store | Proposed | ClickHouse via OTel collector |
| 0010 | Licence | **Accepted** (2026-11-20) | Apache-2.0 for the whole repository; see `LICENSE` and `NOTICE` |
| 0011 | MVP scope cut | Proposed | ZTNA only (Phase 0 + 1) |
| 0012 | Android Client first | **Accepted** | Flutter app + Go core, on-device firewall, cloud decisions |
| 0013 | ZTNA private access via Connector | **Accepted** | Synthetic DNS + Edge broker + outbound connector over inverted HTTP/2 |
| 0014 | Private Edge | **Accepted** (2026-11-20) | Edge bound to one tenant by the Control Plane, local state cache for offline start, local flow log |
| 0015 | Workload Gateway, first slice | **Accepted** (2026-11-20) | Linux client in gateway mode: subnet forwarded into the PQ tunnel, NAT, DNS diverted to the Edge, fail closed |
| 0016 | Tenant-scoped admin credentials | **Accepted** (2026-11-21) | Configured token = super-admin; per-tenant `osa_` tokens (hashed, expiring, revocable) scoped by one middleware; other tenants answer 404 (ST-03) |
| 0017 | Web and SaaS control, first slice | **Accepted** (2026-11-21) | Edge reads TLS SNI / HTTP Host of each allowed TCP flow (no decryption) and re-applies DNS, SaaS and domain policy; SaaS catalog compiled into DNS blocklists; flows tagged for discovery |
| 0018 | TLS inspection at the Edge | **Accepted** (2026-11-21) | Opt-in per tenant: separate inspection root per tenant, 7-day per-Edge intermediates from a CSR, URL rules and header injection per request, bypass list, fail closed, QUIC/IPv6 web refused |
| 0019 | DLP on the inspected path, first slice | **Accepted** (2026-11-21) | Request bodies scanned at the Edge (8 MiB): checksum-validated card/IBAN/tax-code detectors, private keys, e-mail thresholds, RE2 patterns; block or record; unscannable bodies blocked on request; counts only, never the data |
| 0020 | Malware scanning on the inspected path | **Accepted** (2026-11-21) | ClamAV `clamd` over INSTREAM; uploads and file downloads (attachments, non-page types) up to 20 MiB; partial, oversized or unscannable content blocked on request; signature names sanitized |
| 0021 | DLP inside documents and on downloads | **Accepted** (2026-11-21) | Content-Encoding decoded; ZIP, Office Open XML, PDF (Flate streams, TJ strings) and gzip extracted within fixed bounds; encrypted or damaged containers count as unscanned; rules can also scan file downloads |
| 0022 | Web categories from UT1 | **Accepted** (2026-11-21) | Control Plane loads and refreshes the UT1 list (CC BY-SA 4.0); snapshots name the blocked categories; Edges fetch only those (64-bit hashes) and enforce them on DNS and on SNI/Host; allowDomains override; fail open |
