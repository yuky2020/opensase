# Edge

## Purpose
The Edge is the primary data-plane component of OpenSASE, deployed across provider PoPs in public multi-tenant mode or on customer premises as a single-tenant Private Edge. It terminates WireGuard tunnels from Clients and Workload Gateways, terminates multiplexed mTLS tunnels from Connectors, and dynamically stitches ZTNA Microtunnels to private applications. Operating with in-process policy evaluation against locally cached, cryptographically signed Policy Snapshots, it enforces FWaaS, SWG, and inline CASB/DLP controls with sub-millisecond overhead. Even during prolonged Control Plane disconnects, it guarantees uninterrupted traffic forwarding, tenant isolation, and autonomous local breakout.

## Responsibilities
- Terminate inbound WireGuard tunnels from Clients and Workload Gateways with multi-tenant session segregation.
- Terminate inbound multiplexed mTLS connections (HTTP/2 or QUIC) from Connectors across diverse Connector Groups.
- Function as a high-performance ZTNA broker, dynamically stitching client connection requests into Microtunnels routed to healthy Connectors.
- Enforce FWaaS policies (Layer 3/4 stateful filtering, protocol validation, and geo-IP restrictions) on all transit traffic.
- Enforce SWG policies including domain/URL categorization, threat intelligence lookups, and selective TLS MITM inspection.
- Execute inline CASB controls (tenant restriction headers, SaaS cloud application activity enforcement) and invoke DLP inspections.
- Receive, cryptographically verify, and locally cache immutable Policy Snapshots pushed from the Control Plane via streaming gRPC.
- Maintain strict multi-tenant isolation across policy rule tables, connection state, memory pools, and dedicated per-tenant egress IP allocations.
- Support horizontal scaling behind L4 load balancers using consistent 5-tuple hashing to maintain WireGuard session affinity.
- Enable Anycast BGP announcements and GeoDNS routing for global PoP selection and automatic traffic migration.
- Operate in Private Edge mode for single tenants with local internet breakout and completely autonomous cached policy evaluation.
- Stream rich structured flow logs, security incident records, and performance metrics to the Control Plane via OpenTelemetry.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Client | WireGuard over UDP | Inbound | Client data-plane tunnel for steered application and internet traffic |
| Workload Gateway | WireGuard (or IPsec) over UDP | Inbound | Workload data-plane tunnel for cloud egress and ZTNA forwarding |
| Connector | HTTP/2 or QUIC over mTLS | Inbound | Multiplexed transport for Microtunnel stitching and application reachability |
| Control Plane | gRPC over mTLS | Outbound | Registration, Policy Snapshot synchronization, PKI distribution, telemetry export |
| Internet / SaaS Destinations | Native IP (TCP/UDP) | Outbound | Egress delivery for inspected internet and cloud application traffic |
| DLP Engine / ICAP Server | ICAP / gRPC | Outbound | Streaming content payload offloading for inline data loss prevention |
| External Identity Provider | HTTPS / OIDC (JWKS) | Outbound | Real-time cryptographic validation of end-user identity tokens |
| L4 Load Balancer (PoP) | TCP/UDP Probes / BGP | Bidirectional | Health check monitoring, Anycast routing, and flow distribution |

## Key design decisions
- **Binary architecture and deployment model**: Proposed: Single unified Go binary configurable via flags and environment variables to operate as a public multi-tenant edge or private single-tenant edge. Alternative: Multiple discrete specialized microservices (separate ZTNA broker binary, SWG proxy binary, and FWaaS packet filter).
- **Policy evaluation engine**: Proposed: In-process compiled Go decision tables generated from signed Policy Snapshots, executing evaluations without inter-process or network RPC latency. Alternative: Embedded Open Policy Agent (OPA) / Rego engine compiled to WebAssembly evaluated dynamically per flow.
- **Client tunnel termination stack**: Proposed: Userspace WireGuard (wireguard-go) integrated with optimized network ring buffers and direct tenant session mapping. Alternative: Linux kernel-space WireGuard combined with eBPF TC (traffic control) filters for packet classification.
- **SWG and TLS inspection engine**: Proposed: Custom high-performance Go forward proxy with selective TLS MITM based on policy categories, tenant intermediate CAs, and ALPN negotiation. Alternative: Embedded Envoy proxy managed via dynamic xDS configuration push.
- **PoP traffic distribution and clustering**: Proposed: BGP Anycast combined with ECMP routing to L4 load balancers (e.g., Maglev/IPVS) providing consistent 5-tuple session affinity. Alternative: GeoDNS routing directing clients directly to specific Edge IP addresses without Anycast.
- **Microtunnel stitching model**: Proposed: Userspace zero-copy pipe stitching between Client WireGuard streams and Connector multiplexed sessions. Alternative: Kernel-level socket splicing (splice/vmsplice) requiring host kernel access.

## Security considerations
- Multi-tenancy assurance: Tenant ID is embedded into every cryptographic certificate, memory context, routing table, and log line to prevent cross-tenant information disclosure.
- Egress IP segregation: Outbound internet traffic routes through dedicated per-tenant egress IP pools or strictly partitioned NAT gateways to prevent cross-tenant IP reputation contamination.
- TLS inspection security: Per-tenant intermediate CA private keys are kept strictly in memory with zero persistence to disk and protected against memory-dump extraction.
- Snapshot validation: Incoming Policy Snapshots must pass ed25519 signature checks against known Control Plane root keys before being committed to active memory.
- Multi-tenant resource quotas: Enforces hard limits per tenant for maximum concurrent sessions, bandwidth consumption, and buffer allocations to prevent noisy-neighbor denial of service.
- Ephemeral payload handling: Inspected plaintext data buffers during SWG/DLP processing are immediately overwritten in memory upon flow completion.

## Failure modes & HA
- **Node failure in PoP**: External L4 load balancer detects node failure within sub-second thresholds and redistributes WireGuard flows across surviving nodes; clients rekey seamlessly.
- **PoP-wide outage**: Anycast BGP routes withdraw automatically from upstream transit providers, causing global internet routing to divert client traffic to the nearest surviving PoP.
- **Control Plane disconnection**: Edge continues full forwarding and inspection operations indefinitely using its last valid cached Policy Snapshot; telemetry spools locally.
- **Connector disconnection**: If a Connector drops connection, active Microtunnels terminate with TCP resets, and new sessions dynamically route to alternate connectors in the group.
- **Private Edge disconnection**: Operates completely stand-alone on customer premises, performing local internet breakout and ZTNA brokering without internet connectivity.
- **Memory pressure / buffer exhaustion**: Enforces graceful flow shedding by rejecting new low-priority sessions while preserving active Microtunnels and critical flows.

## Private Edge (ADR-0014)

The same binary runs as a Private Edge on customer premises:

```
opensasectl edge add -id site-1 -tenant acme      # bind the Edge to one tenant
edge -tenant acme -state-dir /var/lib/opensase-edge -flow-log /var/lib/opensase-edge/flows.jsonl -allow-private ...
```

- **Tenant binding.** The Control Plane scopes the peer feed, decisions, flow ingestion and session
  reports of a bound Edge to its tenant. It tells only that tenant's devices and connectors about
  the Edge. `-tenant` makes the Edge enforce the same binding locally: it trusts only that tenant's
  CA and drops other tenants from the feed.
- **Offline start.** `-state-dir` caches the last good PKI bundle and peer feed in `state.json`
  (mode 0600). If the Control Plane is unreachable at startup, the Edge verifies the cache like a
  live response (CA chain, snapshot signatures) and serves from it.
- **Local logging.** `-flow-log` appends every flow record as JSONL, rotated to `FILE.1` at 64 MiB.
- **Limits.** Device certificates (24h) still need the Control Plane to renew. Enrollments, policy
  changes and revocations wait until it is reachable again.

## TLS inspection (ADR-0018)

```
edge -inspect-listen 0.0.0.0:15002 ...          # dev compose: EDGE_INSPECT_PORT (default 15002)
opensasectl inspection-ca -tenant acme -o acme-inspection.crt   # root to install on devices
edge -clamd clamav:3310 ...                     # malware scanning (ADR-0020); dev: --profile av
```

- The kernel REDIRECTs tunnel TCP to ports 80 and 443 to the listener. Connections of tenants
  without `web.inspect`, and bypassed hosts, are spliced unchanged.
- For inspecting tenants the Edge terminates TLS with leaves signed by its own 7-day
  intermediate, which it gets from the Control Plane for a key that never leaves the Edge.
  It applies `web.rules` and `web.headers` per request and verifies the upstream certificate.
- HTTP/2 is negotiated with browsers and servers that offer it (ADR-0023).
- Without a valid intermediate it refuses inspected connections (fail closed). QUIC and IPv6 web
  traffic of inspecting devices are refused so that browsers use the inspected path.

## MVP scope vs later
- **MVP**:
  - Single Go binary supporting both public multi-tenant and private single-tenant modes.
  - Inbound WireGuard tunnel termination for Clients (Workload Gateway arrives in Phase 4).
  - Inbound HTTP/2 multiplexed mTLS termination for Connectors.
  - ZTNA Microtunnel stitching for TCP-based Application Segments.
  - Hooks (rule kinds, proxy interfaces) for FWaaS and SWG, not implemented; they arrive in Phase 2.
  - Streaming gRPC ingestion of compiled multi-tenant Policy Snapshots.
  - Basic per-tenant egress NAT IP pool assignment.
  - OpenTelemetry structured flow logging and metrics export.
- **Later**:
  - URL-category bypass of TLS inspection (financial, medical) beyond the per-domain bypass list.
  - Cloud application activity enforcement beyond paths, methods and request headers.
  - Inline DLP inspection via streaming ICAP integration and native content pattern matchers.
  - QUIC / HTTP/3 transport for Connector multiplexed tunnels.
  - eBPF/XDP kernel acceleration for WireGuard tunnel handling and packet classification.
  - Advanced bandwidth QoS rate-limiting and dynamic noisy-neighbor traffic shaping.

## Open questions
- What memory footprint and GC pause characteristics emerge when running wireguard-go, SWG proxying, and TLS inspection together under 10+ Gbps load in Go?
- How should session affinity for L4 load balancing be preserved across WireGuard roaming events where the client public IP or port changes?
- Should DLP inspections be performed fully inline synchronously, or asynchronously with optimistic streaming and stream reset on violation?
- How should per-tenant egress IP addresses be dynamically provisioned and bound to egress sockets across distributed public cloud regions?
- What is the optimal caching and eviction strategy for large threat intelligence URL databases on edge instances with limited RAM?

## Effort drivers
- Achieving high packet throughput, low memory allocations, and minimal GC latency in userspace Go under heavy connection concurrency.
- Implementing robust, standards-compliant TLS MITM inspection handling complex cipher suites, ALPN negotiation, and client certificate validations.
- Designing race-free, lock-contention-minimized Microtunnel stream stitching between Client WireGuard tunnels and Connector multiplexed sessions.
- Enforcing rigorous multi-tenant data isolation and resource scheduling across shared memory, network buffers, and outbound IP namespaces.
- Building resilient state-reconciliation mechanisms for Policy Snapshots during high-frequency configuration changes across thousands of active connections.
