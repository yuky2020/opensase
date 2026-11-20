# Policy Engine

## Purpose
The Policy Engine defines, compiles, and evaluates all security policies across the OpenSASE data plane, encompassing ZTNA Access, SWG Internet, Firewall, CASB, and DLP rules. It transforms high-level multi-attribute rules authored in the Control Plane into deterministic, cryptographically signed Policy Snapshots delivered to Edges and Connectors. By executing evaluations in-process within data plane daemons, it eliminates external network hops and guarantees sub-50-microsecond decision latencies per flow. It provides policy validation, dry-run simulation, semantic diffing, and zero-downtime rollback capabilities.

## Responsibilities
- Provide a unified policy authoring model expressing conditions over identity (user, group), device Posture, location, time, Application Segments, URL categories, CASB activities, and DLP profiles.
- Enforce deterministic rule evaluation ordering and conflict resolution across disparate policy domains.
- Compile human-authored declarative rules into optimized, cache-friendly in-memory lookup structures.
- Cryptographically sign and version compiled Policy Snapshots for tamper-proof distribution to data plane nodes.
- Execute zero-allocation, thread-safe, in-process policy evaluation within Edges, Connectors, and Clients.
- Provide dry-run simulation and shadow-mode evaluation to model policy impacts against historical or real-time traffic without enforcement.
- Generate semantic policy diffs, maintain snapshot lineage, and orchestrate atomic rollbacks to previous known-good snapshots.
- Validate rule syntax, schema conformity, and circular reference safety during authoring and prior to compilation.
- Calculate rule hit counters, rule execution latencies, and policy coverage metrics for operational telemetry.
- Support hot-reloading of Policy Snapshots without interrupting active microtunnels or long-lived proxy sessions.
- Invalidate active evaluation caches immediately upon arrival of a signed newer Policy Snapshot generation.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Control Plane (Policy Service) | In-process API / Go interface | Inbound | Receive raw policy definitions, invoke compilation, validate rule syntax, and trigger simulations |
| Config Distribution (gRPC xDS) | Internal serialized structs | Outbound | Hand off signed Policy Snapshots for streaming delivery to Edges and Connectors |
| Edge (Worker Threads) | In-process C-Go / Go function call | Inbound | Evaluate per-flow context (user, Posture, URL, CASB, DLP) against active Policy Snapshot |
| Client | In-process Go function call | Inbound | Evaluate local steering rules and posture-gated application access conditions |
| Connector | In-process Go function call | Inbound | Evaluate local application segmentation reachability and tenant identity assertions |
| Workload Gateway | In-process Go function call | Inbound | Evaluate workload forwarding rules and egress security boundaries |
| Telemetry Collector | In-process channel / OTel | Outbound | Export policy evaluation audit events, rule hit counts, and dry-run decision logs |
| Threat Intelligence Feed | Internal Go structs | Inbound | Feed real-time IP reputation and malicious URL indicators into compiled rule tables |

## Key design decisions
- **Evaluation runtime representation**: Proposed: Custom Go decision tables (radix trees, bitmasks, interval sets) compiled centrally and evaluated in-process for predictable sub-50µs latency. Alternative: Embedding the Open Policy Agent (OPA/Rego) or AWS Cedar runtime engine directly inside the data plane.
- **Compilation target & distribution artifact**: Proposed: FlatBuffers or Protocol Buffers serialized binary snapshots with Ed25519 signatures and monotonic sequence numbers. Alternative: Distributing raw JSON/YAML ASTs or Rego files evaluated dynamically at runtime.
- **Rule conflict resolution & evaluation order**: Proposed: Explicit ordered list of rules evaluated first-match-wins per policy domain, with an implicit default deny. Alternative: Priority scoring or multi-attribute lattice resolution where highest specific weight wins.
- **Policy authoring language**: Proposed: Strongly-typed JSON/YAML schema mapped to UI builders with support for Cedar-like DSL expressions. Alternative: Pure Rego policy files authored directly by tenant administrators.
- **Dry-run simulation execution**: Proposed: Shadow-mode evaluation running candidate snapshots asynchronously in parallel with active rules on live traffic. Alternative: Synthetic offline replay of historical audit logs stored in ClickHouse.
- **Policy snapshot memory management**: Proposed: Dual-buffer pointer swapping (Read-Copy-Update style) to achieve lock-free hot swapping during traffic forwarding. Alternative: Read-write mutex locking wrapping snapshot evaluations.
- **Dynamic posture attribute evaluation**: Proposed: Local client posture evaluations baked into signed ephemeral posture tokens passed in flow headers. Alternative: Continuous real-time remote posture verification lookups per new session.

## Security considerations
- Cryptographic verification of Policy Snapshot signatures (Ed25519) by data plane nodes prior to loading into memory.
- Prevention of privilege escalation by isolating tenant policy evaluation contexts and validating tenant ownership of all referenced objects.
- In-process evaluation isolation ensuring malformed attributes or unexpected input types fail closed (default deny) without crashing the daemon.
- Safe compiler resource bounds preventing denial-of-service via deeply nested rule expressions or catastrophic regex backtracking.
- Strict input validation on device Posture claims to prevent spoofed posture attributes from bypassing ZTNA rules.
- Cryptographic immutability of compiled snapshots preventing runtime tampering on compromised host file systems.
- Sanitization of user-provided regular expressions and string matching predicates before compiler execution.

## Failure modes & HA
- **Snapshot compilation failure**: Compiler rejects invalid policy revisions, preserves the existing active snapshot, and returns syntax and validation errors to the administrator.
- **Corrupted or unsigned snapshot received by Edge**: Edge fails verification, drops the corrupt snapshot, continues running the last verified snapshot, and raises an alert.
- **Evaluation timeout or runtime panic**: Runtime catches panics, fails closed (flow blocked), increments error counters, and logs detailed context for diagnostics.
- **Stale policy snapshot**: If an Edge is partitioned from the Control Plane, it continues enforcing the cached snapshot indefinitely until connectivity is restored.
- **Memory exhaustion during snapshot compilation**: Compiler enforces tenant quota limits on total rule count and condition complexity before memory allocation.
- **Posture attribute staleness**: Clients unable to refresh posture claims fall back to an untrusted posture state, triggering restricted access policies.
- **Version skew across distributed Edges**: Sequential monotonic version tracking flags outdated Edges, triggering prioritized snapshot synchronization.

## MVP scope vs later
### MVP
- Structured rule schema for Access (ZTNA) policies supporting user, group, basic Posture (OS version, disk encryption), IP/port and Application Segment matchers; Internet (SWG) rule kind reserved in the schema for Phase 2.
- First-match-wins rule evaluation engine compiled into in-memory Go decision tables.
- Cryptographic signing of Policy Snapshots with Ed25519 tenant keys.
- In-process evaluation integrated into the Edge with benchmarked sub-50µs execution latency.
- Basic policy rollback to previous snapshot version and synthetic policy evaluation test suite.
- Lock-free snapshot swapping in the data plane upon receiving configuration updates.
- Basic hit-counter metrics exported to the local Prometheus/OTel collector.

### Later
- Integration of complex device Posture criteria, risk-score thresholds, time-of-day/geofencing matchers, and DLP profiles.
- Native dry-run and shadow evaluation mode comparing live traffic decisions against candidate snapshots.
- Visual policy diff tool showing rule additions, removals, and semantic shadow impacts in the admin portal.
- Pluggable policy compilation targets (such as eBPF maps for kernel-level packet filtering).
- Support for Cedar DSL export and formal verification of rule invariants.
- Automated anomaly detection flagging unused rules or redundant policy branches.
- Dynamic compilation of tenant-specific WebAssembly (Wasm) evaluation routines for custom enterprise logic.

## Open questions
- Whether custom decision tables remain maintainable as condition permutations (CASB, DLP, Posture) grow in complexity.
- How to best benchmark and enforce the strict sub-50µs evaluation SLA across diverse edge hardware profiles.
- Strategy for incremental policy updates (delta snapshots) versus full snapshot replacement for tenants with tens of thousands of rules.
- Memory consumption overhead of maintaining two concurrent policy snapshots (active and candidate) in resource-constrained Connectors.
- Performance implications of evaluating complex regex patterns inside DLP and URL matching rules within the fast path.
- Whether to compile separate snapshots per component role (Edge vs Client vs Connector) or a single unified tenant snapshot.
- Granularity of rule evaluation metrics: per-rule hit counters versus full execution trace sampling.

## Effort drivers
- Optimizing in-memory lookup algorithms (combining trie lookups, CIDR matches, and bitmap set intersections) for zero-allocation execution under 50 microseconds.
- Designing an intuitive rule authoring and inheritance model that remains deterministic when combining ZTNA, SWG, and CASB rules.
- Building a deterministic policy compiler that guarantees identical evaluation outcomes across different platform architectures.
- Implementing semantic diff and conflict detection algorithms that detect shadowed or dead rules before compilation.
- Managing snapshot lifecycle, atomic hot-swapping, and cache invalidation under heavy packet processing workloads.
- Ensuring rock-solid fail-close error handling without introducing thread panics in data plane processes.
- Developing reproducible micro-benchmarks that validate sub-50µs evaluation latencies across heterogeneous compute environments.
