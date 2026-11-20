CREATE TABLE tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE users (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (tenant_id, email)
);

CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    platform    TEXT NOT NULL,
    cert_serial TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX devices_tenant ON devices(tenant_id, user_id);

-- Only the SHA-256 of a provisioning key is stored.
CREATE TABLE provisioning_keys (
    key_hash   BLOB PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    max_uses   INTEGER NOT NULL,
    uses       INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE tenant_policy (
    tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    policy     TEXT NOT NULL, -- JSON api.TenantPolicy
    updated_at INTEGER NOT NULL
);

CREATE TABLE user_rules (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rules      TEXT NOT NULL, -- JSON api.UserRules
    updated_at INTEGER NOT NULL
);

-- version is global and strictly increasing (AUTOINCREMENT never reuses values).
CREATE TABLE snapshot_versions (
    version    INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    envelope   BLOB,           -- JSON policy.Envelope
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX snapshot_versions_device ON snapshot_versions(device_id, version);

CREATE TABLE flows (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    where_    TEXT NOT NULL,
    start     INTEGER NOT NULL,
    record    TEXT NOT NULL -- JSON api.FlowRecord
);
CREATE INDEX flows_tenant ON flows(tenant_id, id);
