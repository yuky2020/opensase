# Control Plane

## Purpose
The Control Plane provides centralized configuration management, identity synchronization, cryptographic trust, and operational visibility across the OpenSASE fabric without forwarding user data plane traffic. It manages tenants, compiles high-level access and security policies into immutable, signed Policy Snapshots, and tracks the health and inventory of all distributed nodes. By maintaining tenant-specific intermediate certificate authorities, it issues short-lived mTLS identities for secure node enrollment and inter-component communication. It delivers real-time configuration updates to Edges and Connectors while supporting both multi-tenant SaaS and air-gapped self-hosted deployments.

## Responsibilities
- Manage multi-tenant organization boundaries, subscriptions, resource quotas, and administrator role-based access control (RBAC).
- Synchronize directory objects, users, and groups from external IdPs using SCIM 2.0 and authenticate administrator and user sessions via OIDC and SAML 2.0.
- Operate an enrollment and PKI service that validates one-time Provisioning Keys and issues short-lived X.509 mTLS certificates with SPIFFE IDs.
- Author, validate, simulate, and compile security rules into versioned, cryptographically signed Policy Snapshots.
- Distribute configuration and Policy Snapshots to data plane entities (Edges, Clients, Connectors, Workload Gateways) using gRPC streaming.
- Maintain an active inventory, version tracking, and liveness heartbeat registry of all connected Edges and Connectors.
- Expose unified REST and gRPC administrative APIs defined by OpenAPI 3.0 specifications.
- Record tamper-evident audit logs for all administrative actions, configuration mutations, and component lifecycle transitions.
- Coordinate dynamic certificate rotation and distribute tenant revocation lists to edge proxies and connector daemons.
- Manage Application Segment definitions, mapping FQDN/IP patterns and port ranges to designated Connector Groups.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Admin Portal (Web UI / CLI) | HTTPS / REST / gRPC | Inbound | Tenant administration, policy authoring, node onboarding, and status querying |
| External Identity Provider (IdP) | HTTPS (OIDC / SAML / SCIM) | Inbound / Outbound | User and group directory synchronization (SCIM) and administrative/user authentication |
| Edge (Public / Private) | gRPC over mTLS | Inbound | Dynamic configuration distribution (xDS-like), node heartbeat, and revocation distribution |
| Client | HTTPS / gRPC over mTLS | Inbound | Device enrollment via Provisioning Key, certificate renewal, and steering policy delivery |
| Connector | gRPC over mTLS | Inbound | Provisioning Key exchange, certificate renewal, heartbeat, and Application Segment config fetch |
| Workload Gateway | gRPC over mTLS | Inbound | Provisioning Key exchange, certificate renewal, heartbeat, and workload routing policy fetch |
| PostgreSQL | TCP / PostgreSQL wire protocol | Outbound | Persistent state storage for tenants, configurations, audit trails, and inventory |
| Internal Services / Event Bus | NATS JetStream | Internal | Asynchronous event distribution, policy invalidation, and decoupling internal microservices |
| Telemetry Collector | gRPC / OTel | Inbound / Outbound | Ingest operational health metrics and export aggregated control plane telemetry |

## Key design decisions
- **Service decomposition**: Proposed: Modular monolith packaging tenant, identity, policy, and PKI services in a single Go binary with internal interfaces. Alternative: Microservices deployed independently from day one on distinct container workloads.
- **Configuration distribution protocol**: Proposed: gRPC streaming protocol inspired by Envoy xDS (state-of-the-world and delta) backed by NATS JetStream. Alternative: Periodic HTTP/REST polling with conditional `ETag` validation.
- **PKI and workload identity**: Proposed: In-process tenant intermediate CAs issuing short-lived X.509 certificates carrying SPIFFE IDs (`spiffe://opensase/<tenant-id>/<node-type>/<node-id>`). Alternative: External PKI integration delegating certificate issuance to HashiCorp Vault or cert-manager.
- **Primary storage engine**: Proposed: PostgreSQL with schema-level or row-level tenant isolation and ACID transaction guarantees. Alternative: Distributed key-value stores such as etcd or CockroachDB.
- **API design standard**: Proposed: Protocol Buffers / gRPC service definitions with grpc-gateway generating OpenAPI 3.0-compliant REST endpoints. Alternative: Independent handwritten REST controllers alongside separate gRPC handlers.
- **Administrative audit logging**: Proposed: Append-only PostgreSQL audit log tables with cryptographic hash-chaining to detect tampering. Alternative: Streaming audit events directly to an external immutable SIEM / object storage bucket without local retention.

## Security considerations
- Strict enforcement of tenant isolation across all storage queries, caching tiers, and event topics to prevent cross-tenant data leakage.
- Protection of tenant intermediate CA private keys using hardware security modules (HSM), cloud KMS, or envelope encryption at rest.
- Time-bounded, high-entropy one-time Provisioning Keys with strict expiration windows to prevent unauthorized node enrollment.
- Immutability of administrative audit logs, preventing alteration or truncation even by privileged tenant administrators.
- Mandatory mutual TLS (mTLS) with SPIFFE identity verification across all inter-component control and distribution channels.
- Rate limiting and payload size bounds on all inbound REST/gRPC endpoints to protect against denial-of-service vectors.
- Secure credential management preventing persistent storage of plaintext IdP secrets or administrative tokens.

## Failure modes & HA
- **PostgreSQL outage**: Control Plane switches to read-only mode; data plane nodes continue processing traffic uninterrupted on cached Policy Snapshots.
- **Control Plane process crash or network partition**: Stateless replicas auto-recover under Kubernetes; data plane nodes back off and reconnect without dropping user traffic.
- **Intermediate CA private key compromise**: Revocation of compromised intermediate CA, rotation of tenant trust root, and forced re-enrollment across all affected tenant nodes.
- **Internal event bus (NATS JetStream) failure**: Fall back to direct database polling or delayed distribution until message broker cluster quorum recovers.
- **IdP directory synchronization outage**: Cached user and group attributes remain valid; local authentication falls back to emergency break-glass administrator credentials.
- **Node mass reconnection storm**: Reconnection throttling, jittered backoff, and state-of-the-world snapshot caching prevent database and CPU exhaustion.

## MVP scope vs later
### MVP
- Modular monolith Go architecture with embedded or co-located NATS JetStream and PostgreSQL.
- OIDC authentication for administrator login and SCIM 2.0 inbound endpoint for user and group synchronization.
- Tenant intermediate CA issuing short-lived mTLS certificates for node enrollment via Provisioning Keys.
- Streaming gRPC configuration push for Edges, Clients, and Connectors.
- OpenAPI-documented administrative REST API and fundamental audit logging.
- Inventory tracking with periodic heartbeat registration for active data plane entities.
- Kubernetes deployment manifests and Helm charts for self-hosted and single-cluster deployment.

### Later
- Decomposition into independently scalable microservice deployments for hyperscale multi-tenant SaaS.
- SAML 2.0 integration for enterprise identity federation and IdP-initiated single sign-on.
- Hardware Security Module (HSM) and cloud KMS integration for CA private key management.
- Multi-region database replication with active-active cross-region control plane failover.
- Granular attribute-based access control (ABAC) for multi-tier administrative role delegation.
- Automated canary rollouts and phased deployment rings for data plane configuration snapshots.

## Open questions
- Whether to bundle an embedded PostgreSQL engine for single-node air-gapped self-hosted proof-of-concept deployments.
- Balance between short-lived certificates (e.g., 12-24 hours) versus real-time CRL/OCSP stapling for node revocation.
- Optimal sharding and scaling strategy for NATS JetStream consumer groups across tens of thousands of concurrently connected Connectors.
- Database tenancy pattern trade-off: schema-per-tenant versus shared tables with PostgreSQL Row-Level Security (RLS).
- Strategy for syncing dynamic group membership updates from SCIM in near real time without triggering excessive policy re-compilations.
- Mechanism for handling offline Clients that miss multiple sequential configuration versions while powered down.

## Effort drivers
- Designing an xDS-like streaming distribution protocol that handles mass reconnect storms from distributed edges and connectors.
- Handling edge cases and schema inconsistencies across heterogeneous enterprise SCIM 2.0 identity providers.
- Automated certificate lifecycle management, renewal state machines, and non-disruptive CA rotation under load.
- Maintaining operational parity between multi-tenant cloud-native deployments and lightweight self-hosted footprints.
- Preventing noisy-neighbor starvation and ensuring fair resource allocation across tenants on shared control services.
- Building robust transactional rollback mechanisms for failed configuration and policy distribution cycles.
