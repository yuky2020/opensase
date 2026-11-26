# Metrics reference

This page documents every Prometheus metric exposed by the OpenSASE Control Plane and Edge services,
derived directly from `internal/controlplane/observe.go` and `internal/edge/observe.go`.

For setup, scraping configurations, and alert rules, see [Monitoring](../operations/monitoring.md).

## Operational listener

Both `controlplane` and `edge` expose plain-HTTP operational endpoints on a dedicated address configured
via `-ops-listen` (for example `127.0.0.1:9090` for the Control Plane and `127.0.0.1:9091` for an Edge).
Keep this address internal to your cluster or host network.

| Endpoint | Method | Output | Description |
|---|---|---|---|
| `/metrics` | `GET` | `text/plain; version=0.0.4` | Prometheus exposition format. |
| `/healthz` | `GET` | `text/plain` | Liveness check; returns HTTP 200 `ok` while the process is running. |
| `/readyz` | `GET` | `text/plain` | Readiness check; returns HTTP 200 `ready` when dependencies are accessible, or HTTP 503 if not ready. |

### Readiness criteria

- **Control Plane (`controlplane`):** Verifies that the database (`store.Ping`) is reachable and responsive, and that the web category list is loaded if `-categories-url` is configured.
- **Edge (`edge`):** Verifies that the Edge has received a peer feed from the Control Plane or loaded its signed local cache from `-state-dir`.

---

## Control Plane metrics

All Control Plane metric names use the prefix `opensase_cp_`.

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `opensase_cp_http_requests_total` | Counter | `class` (`"2xx"`, `"3xx"`, `"4xx"`, `"5xx"`) | Total HTTP requests handled by the Control Plane, grouped by HTTP response status class. |
| `opensase_cp_enroll_failures_total` | Counter | *(none)* | Total count of failed device and Connector enrollment attempts. |
| `opensase_cp_snapshot_failures_total` | Counter | *(none)* | Total count of policy snapshots that could not be compiled or cryptographically signed. |
| `opensase_cp_leader` | Gauge | *(none)* | Leadership status for multi-replica deployments ([ADR-0033](../adr/0033-postgresql-and-replicas.md)): `1` if this replica executes singleton background jobs, `0` otherwise. |
| `opensase_cp_devices` | Gauge | *(none)* | Number of currently enrolled, non-revoked client devices. Returns `-1` if the database query fails. |
| `opensase_cp_edge_sessions` | Gauge | `edge` | Active client sessions per Edge identifier, computed from the session reports received within the last 5 minutes. |
| `opensase_cp_category_list_age_seconds` | Gauge | *(none)* | Age in seconds of the active web category database loaded into memory. Returns `-1` if no category archive is loaded. |
| `opensase_cp_audit_chain_ok` | Gauge | *(none)* | Integrity status of the administrative audit hash chain ([ADR-0028](../adr/0028-audit-hash-chain.md)): `1` if valid, `0` if broken, `-1` before the initial check completes. |
| `opensase_cp_certificate_expiry_seconds` | Gauge | `cert` (`"controlplane"`, `"root"`) | Seconds remaining until expiration of the Control Plane TLS server certificate and the provider root CA certificate. |

### Example exposition

```prometheus
# HELP opensase_cp_audit_chain_ok 1 if the last audit chain check passed, 0 if it failed, -1 before the first check.
# TYPE opensase_cp_audit_chain_ok gauge
opensase_cp_audit_chain_ok 1
# HELP opensase_cp_category_list_age_seconds Age of the loaded web category list; -1 if none.
# TYPE opensase_cp_category_list_age_seconds gauge
opensase_cp_category_list_age_seconds 14205.81
# HELP opensase_cp_certificate_expiry_seconds Seconds until the Control Plane certificates expire.
# TYPE opensase_cp_certificate_expiry_seconds gauge
opensase_cp_certificate_expiry_seconds{cert="controlplane"} 7775982.1
opensase_cp_certificate_expiry_seconds{cert="root"} 315359982.1
# HELP opensase_cp_devices Enrolled, non-revoked devices.
# TYPE opensase_cp_devices gauge
opensase_cp_devices 12
# HELP opensase_cp_edge_sessions Devices with a live session, per Edge, from the Edges' last reports.
# TYPE opensase_cp_edge_sessions gauge
opensase_cp_edge_sessions{edge="edge-1"} 4
# HELP opensase_cp_enroll_failures_total Failed device and Connector enrolments.
# TYPE opensase_cp_enroll_failures_total counter
opensase_cp_enroll_failures_total 0
# HELP opensase_cp_http_requests_total HTTP requests by status class.
# TYPE opensase_cp_http_requests_total counter
opensase_cp_http_requests_total{class="2xx"} 452
opensase_cp_http_requests_total{class="3xx"} 12
opensase_cp_http_requests_total{class="4xx"} 2
opensase_cp_http_requests_total{class="5xx"} 0
# HELP opensase_cp_leader 1 if this replica runs the singleton jobs (ADR-0033).
# TYPE opensase_cp_leader gauge
opensase_cp_leader 1
# HELP opensase_cp_snapshot_failures_total Policy snapshots that could not be compiled or signed.
# TYPE opensase_cp_snapshot_failures_total counter
opensase_cp_snapshot_failures_total 0
```

---

## Edge metrics

All Edge metric names use the prefix `opensase_edge_`.

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `opensase_edge_dns_queries_total` | Counter | *(none)* | Total count of DNS queries answered by the Edge internal DNS resolver. |
| `opensase_edge_blocks_total` | Counter | `layer` | Total count of blocked flows and DNS queries, labeled by the enforcing policy layer (`"dns"`, `"tenant"`, `"user"`, `"app"`, `"lockdown"`, `"ztna"`, `"default"`, `"cloud"`). |
| `opensase_edge_peer_sync_failures_total` | Counter | *(none)* | Total count of failed peer sync or trust refresh requests made to the Control Plane. |
| `opensase_edge_sessions` | Gauge | *(none)* | Number of client devices with active, live WireGuard tunnels on this Edge. |
| `opensase_edge_devices` | Gauge | *(none)* | Total number of authorized devices delivered in the latest Control Plane peer feed. |
| `opensase_edge_peer_sync_age_seconds` | Gauge | *(none)* | Seconds elapsed since the last successful peer sync with the Control Plane. Returns `-1` before the first sync. |
| `opensase_edge_flow_backlog` | Gauge | *(none)* | Number of evaluated flow records currently queued in memory awaiting upload to the Control Plane. |
| `opensase_edge_certificate_expiry_seconds` | Gauge | *(none)* | Seconds remaining until the Edge TLS serving certificate expires. Returns `-1` if unavailable. |

### Example exposition

```prometheus
# HELP opensase_edge_blocks_total Blocked flows and queries, by enforcement layer.
# TYPE opensase_edge_blocks_total counter
opensase_edge_blocks_total{layer="dns"} 18
opensase_edge_blocks_total{layer="tenant"} 4
# HELP opensase_edge_certificate_expiry_seconds Seconds until the Edge certificate expires.
# TYPE opensase_edge_certificate_expiry_seconds gauge
opensase_edge_certificate_expiry_seconds 7775890.4
# HELP opensase_edge_devices Devices in the last peer feed.
# TYPE opensase_edge_devices gauge
opensase_edge_devices 12
# HELP opensase_edge_dns_queries_total DNS queries answered by the Edge resolver.
# TYPE opensase_edge_dns_queries_total counter
opensase_edge_dns_queries_total 1284
# HELP opensase_edge_flow_backlog Flow records waiting for upload to the Control Plane.
# TYPE opensase_edge_flow_backlog gauge
opensase_edge_flow_backlog 0
# HELP opensase_edge_peer_sync_age_seconds Seconds since the last successful peer sync; -1 before the first.
# TYPE opensase_edge_peer_sync_age_seconds gauge
opensase_edge_peer_sync_age_seconds 4.2
# HELP opensase_edge_peer_sync_failures_total Failed peer and trust syncs with the Control Plane.
# TYPE opensase_edge_peer_sync_failures_total counter
opensase_edge_peer_sync_failures_total 0
# HELP opensase_edge_sessions Devices with a live tunnel session on this Edge.
# TYPE opensase_edge_sessions gauge
opensase_edge_sessions 4
```
