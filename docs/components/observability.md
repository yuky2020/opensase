# Observability

## Purpose
The OpenSASE Observability component provides end-to-end telemetry collection, persistent storage, and analytical query capabilities across the Control Plane and Data Plane. It ingests high-volume structured logs, metrics, distributed traces, and security events from Edges, Connectors, and administrative services. Built around OpenTelemetry and ClickHouse, it enables real-time threat investigation, compliance auditing, operational monitoring, and streaming export to external enterprise SIEM systems.

## Responsibilities
- Ingest and normalize structured logs: connection sessions, SWG web transactions, FWaaS drops, DLP incidents, posture updates, and Control Plane audit trails.
- Store multi-tenant event streams in ClickHouse with automated partition management and per-tenant retention policies.
- Collect and aggregate operational metrics from all components using Prometheus exposition formats and OpenTelemetry collectors.
- Trace end-to-end request latency across Control Plane services, Edge proxies, and Connector microtunnels via OpenTelemetry distributed tracing.
- Stream normalized security and audit events to external third-party SIEM and data lakes (Syslog over TLS, AWS S3 / Cloud Storage, Splunk HTTP Event Collector).
- Provide performant, filtered query APIs for the Admin Portal log explorer, analytics dashboards, and compliance reporting tools.
- Monitor data plane health, tunnel connectivity, and policy synchronization latency across all distributed PoPs.
- Ensure cryptographic integrity, non-repudiation, and tamper detection of administrative audit logs.
- Provide data lifecycle management to expire and drop tenant log partitions based on configured compliance limits.
- Expose system health and SLO alerting feeds for infrastructure operators and enterprise tenant administrators.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Edge / Connectors | OTLP (gRPC / Protobuf) | Inbound to OTel Collector | Stream raw event logs, connection records, and runtime metrics |
| Control Plane Services | OTLP (gRPC / HTTP) | Inbound to OTel Collector | Ingest administrative audit trails, policy compilation events, and tracing spans |
| ClickHouse Cluster | Native TCP / ClickHouse HTTP | Outbound from OTel Collector | Write structured columnar logs and read analytical queries from Control Plane |
| Prometheus / Grafana | HTTP Pull (/metrics) | Outbound from Collectors | Scrape aggregated infrastructure and operational metrics |
| External SIEM / Storage | Syslog TLS, S3 API, Splunk HEC | Outbound from Exporter | Forward filtered real-time security events to customer security tools |
| Admin Portal (via Public API) | HTTPS / gRPC | Outbound to Admin Portal | Deliver paginated query results, aggregations, and log search filters |

## Key design decisions
- **Proposed:** OpenTelemetry (OTel) Collector agent deployed alongside ClickHouse as the core ingestion pipeline, using ClickHouse's native columnar storage engine for high-compression log analytics.
  *Alternative:* Elastic/OpenSearch stack, which provides rich full-text search but demands significantly higher RAM, disk storage, and indexing overhead for high-volume network flow logs.
- **Proposed:** Unified schema with fixed top-level fields (timestamp, tenant_id, component, user_id, action, rule_id) and typed nested attributes per log category (web, firewall, dlp, audit).
  *Alternative:* Raw JSON schema-less string storage, which offers ingestion flexibility but severely degrades query speed and compression efficiency in ClickHouse.
- **Proposed:** Decentralized streaming buffer on Edge nodes with local disk-backed ring buffers to absorb transient network partitions between Edge and the central OTel Collector.
  *Alternative:* Synchronous remote RPC logging directly from the packet path, which risks blocking or dropping user traffic during telemetry collector outages.
- **Proposed:** Event export router built as an asynchronous worker pipeline in the Control Plane reading from ClickHouse or Kafka/NATS streams to push to customer SIEMs.
  *Alternative:* Configuring each Edge to connect directly to every customer's SIEM endpoint, which creates complex egress firewall rules and unreliable delivery guarantees.
- **Proposed:** Materialized views in ClickHouse to compute hourly and daily rollups for dashboard metric widgets and bandwidth usage counters.
  *Alternative:* Querying raw flow event tables on-demand for dashboards, which causes unacceptable query latencies and CPU spikes over multi-day ranges.

## Security considerations
- Enforce strict tenant isolation in ClickHouse using tenant ID query partitioning and Row-Level Security (RLS) or tenant-specific views.
- Redact or mask sensitive user data (passwords in URLs, PII in query strings, match snippets in DLP) at the collection layer before persistent storage.
- Encrypt all telemetry data in transit via mTLS and at rest using storage encryption.
- Maintain immutable, append-only tables for administrative audit trails to guarantee audit integrity and tamper resistance.
- Restrict SIEM export configurations with scoped permissions so tenant administrators can only export their own tenant's data.
- Enforce rate limits and query timeouts on analytics APIs to prevent denial-of-service through resource-heavy regex or wildcard queries.

## Failure modes & HA
- **ClickHouse node failure:** ClickHouse deployed as a replicated cluster (ClickHouse Keeper / ZooKeeper); ingestion queries automatically fail over to healthy replica nodes.
- **OTel Collector crash or saturation:** Edge local queues buffer up to a configured storage limit; if collectors are unreachable long-term, oldest logs are dropped according to a FIFO drop policy while metrics track dropped counts.
- **External SIEM outage:** Outbound export workers retry with exponential backoff and dead-letter queues, preserving events in ClickHouse without impeding internal analytics.
- **High ingestion spikes:** OTel Collector applies batching, memory limiter processors, and backpressure signaling to throttle collector ingestion gracefully.
- **Disk saturation:** ClickHouse disk monitors trigger automatic eviction of oldest partitions once storage thresholds are crossed, preserving recent operational data.
- **Network partition between PoP and Central Collector:** Local Edge telemetry buffers persist logs until WAN links recover, avoiding telemetry holes.

## MVP scope vs later
### MVP
- OpenTelemetry Collector pipeline routing to single/replicated ClickHouse instance.
- Structured schemas for session logs, SWG web access logs, FWaaS drops, DLP incidents, and audit logs.
- Configurable per-tenant retention period (e.g., 7, 30, 90 days) via ClickHouse TTL policies.
- Prometheus metrics endpoint on all OpenSASE components.
- SIEM export support for Syslog (RFC 5424 over TLS) and AWS S3 / MinIO JSON streaming.
- Basic API query interface for the Admin Portal log explorer.

### Later
- Splunk HTTP Event Collector (HEC) and Azure Sentinel native integration.
- Distributed tracing across Client, Edge, and Connector microtunnels.
- Digital Experience Monitoring (DEM) with synthetic probes, path tracing (hop-by-hop latency), and DNS resolution timing from Clients.
- Real-time streaming anomaly detection and threshold-based alerting engine.
- Pre-built Grafana and Admin Portal executive dashboards for bandwidth, threat trends, and posture compliance.
- Cold tier storage archiving to cloud object stores for multi-year regulatory compliance.

## Open questions
- What is the most cost-effective ClickHouse partitioning key (e.g., `(tenant_id, toYYYYMMDD(timestamp))`) for balancing multi-tenant query speed and disk merging overhead?
- Should SIEM streaming happen directly out of the ingestion pipeline (OTel Collector / Kafka) or via Change Data Capture (CDC) / scheduled batches from ClickHouse?
- How much local disk buffer must be allocated on resource-constrained Private Edge appliances to survive prolonged WAN disconnects?
- How frequently should posture telemetry be pushed by Clients to balance diagnostic fidelity against battery and bandwidth consumption?

## Effort drivers
- Designing an optimized ClickHouse columnar schema that supports high-speed aggregation over billions of daily network flows while minimizing disk consumption.
- Implementing robust, resilient SIEM export pipelines that handle downstream rate limits, network outages, and varied external schema specifications.
- Managing backpressure and buffer memory in the Edge data plane so telemetry collection never impairs network packet forwarding performance.
- Achieving fine-grained, performant multi-tenant query isolation in shared ClickHouse clusters without maintenance overhead for thousands of tenants.
- Handling out-of-order log arrival and clock drift across globally distributed edge nodes and client endpoints.
