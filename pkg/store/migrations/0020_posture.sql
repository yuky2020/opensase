CREATE TABLE device_posture (
    device_id   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL,
    report      TEXT NOT NULL,
    failing     TEXT NOT NULL,
    reported_at INTEGER NOT NULL
);
CREATE INDEX device_posture_tenant ON device_posture(tenant_id);
