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
