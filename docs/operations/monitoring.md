# Monitoring

The Control Plane and each Edge can serve three plain-HTTP endpoints on a separate address
(`-ops-listen`). Keep that address reachable only by your monitoring, for example
`127.0.0.1:9090` or a cluster-internal port.

| Endpoint | Answers |
|---|---|
| `/healthz` | 200 while the process runs (liveness) |
| `/readyz` | 200 when it can serve: Control Plane database reachable and category list loaded (if configured); Edge has a peer feed or its cached state |
| `/metrics` | Prometheus text format |

```bash
controlplane ... -ops-listen 127.0.0.1:9090
edge ... -ops-listen 127.0.0.1:9091
```

Without an external stack, the admin portal's status page shows the same health:

- Edges and their last report;
- Connectors online;
- devices enrolled and online;
- certificate expiry dates;
- the audit chain.

It reads `GET /v1/admin/status` (super-admin).

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `opensase_cp_devices` | gauge | Enrolled, non-revoked devices |
| `opensase_cp_edge_sessions{edge}` | gauge | Live sessions per Edge, from the Edges' last reports |
| `opensase_cp_leader` | gauge | 1 on the replica that runs the singleton jobs |
| `opensase_cp_category_list_age_seconds` | gauge | Age of the web category list (-1: none) |
| `opensase_cp_audit_chain_ok` | gauge | 1 ok, 0 broken, -1 not checked yet |
| `opensase_cp_certificate_expiry_seconds{cert}` | gauge | Time left on the root and Control Plane certificates |
| `opensase_cp_http_requests_total{class}` | counter | Requests by status class |
| `opensase_cp_enroll_failures_total` | counter | Rejected enrolments |
| `opensase_cp_snapshot_failures_total` | counter | Snapshots that failed to compile or sign |
| `opensase_edge_sessions` | gauge | Devices with a live tunnel on this Edge |
| `opensase_edge_devices` | gauge | Devices in the last peer feed |
| `opensase_edge_peer_sync_age_seconds` | gauge | Time since the last successful sync (-1: never) |
| `opensase_edge_flow_backlog` | gauge | Flow records waiting for upload |
| `opensase_edge_certificate_expiry_seconds` | gauge | Time left on the Edge certificate |
| `opensase_edge_dns_queries_total` | counter | DNS queries answered |
| `opensase_edge_blocks_total{layer}` | counter | Blocked flows and queries by policy layer |
| `opensase_edge_peer_sync_failures_total` | counter | Failed syncs with the Control Plane |

## Digital experience

Devices report lightweight digital experience probes with their flow batches (`POST /v1/flows`).
Each sample measures:

- `rttMs`: round-trip time in milliseconds to the Edge session endpoint (median of answered probes);
- `lossPct`: probe packet loss percentage (0–100%);
- `dnsMs`: DNS resolution latency through the Edge tunnel resolver;
- `network`: active network type (`wifi`, `cellular`, `roaming`, `ethernet`, `unknown`).

Administrators query aggregated metrics by tenant, Edge, and device:

```
GET /v1/admin/tenants/{tenant}/experience?since=<unix-seconds>&device=<device-id>
```

- `since`: defaults to 24 hours ago (maximum retention query window: 30 days).
- `device`: optional device ID filter.

The endpoint returns aggregates per `(deviceId, edgeId)` sorted by device then Edge:
sample count, `rttP50Ms` and `rttP95Ms` (nearest-rank percentiles over samples with RTT > 0),
mean `lossPct`, `dnsP50Ms` (over samples with DNS latency > 0), and the timestamp of the latest sample (`last`).
Old experience samples are purged automatically following the configured flow retention policy.

## Alerts

[`deploy/observability/alerts.yml`](https://github.com/yuky2020/opensase/blob/main/deploy/observability/alerts.yml)
has example rules for:

- an Edge that stopped syncing or answering;
- a Control Plane that is down;
- certificates that expire in under 14 days;
- a category list older than 3 days;
- snapshot signing failures;
- a broken audit chain;
- a spike of failed enrolments;
- a flow upload backlog;
- no leader replica.

Name the scrape jobs `opensase-controlplane` and `opensase-edge`.

## Logs

Both components log structured JSON with `log/slog`. Secrets (keys, PSKs, tokens,
provisioning keys) are never logged.
