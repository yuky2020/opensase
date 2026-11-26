CREATE TABLE experience_samples (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    edge_id   TEXT NOT NULL,
    at        INTEGER NOT NULL,
    rtt_ms    REAL NOT NULL,
    loss_pct  REAL NOT NULL,
    dns_ms    REAL NOT NULL,
    network   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX experience_samples_tenant ON experience_samples(tenant_id, at);
CREATE INDEX experience_samples_device ON experience_samples(device_id, at);
