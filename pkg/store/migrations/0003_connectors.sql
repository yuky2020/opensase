-- Connectors (ADR-0013). A connector is created by an admin together with a single-use
-- provisioning key; cert_serial stays '' until it enrolls. Renewal mirrors devices (0002):
-- prev_cert_serial is the serial replaced by the last renewal, valid only to retry
-- POST /v1/connector/renew after a lost response.
CREATE TABLE connectors (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    grp              TEXT NOT NULL,
    cert_serial      TEXT NOT NULL DEFAULT '',
    prev_cert_serial TEXT NOT NULL DEFAULT '',
    revoked          INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    last_seen        INTEGER NOT NULL DEFAULT 0, -- last Edge report of a live broker connection
    -- ConnectorConfig versioning: the version increases whenever the served config changes
    -- (config_hash covers the tenant policy version, the edges and the group's apps).
    config_version   INTEGER NOT NULL DEFAULT 0,
    config_hash      BLOB
);
CREATE INDEX connectors_tenant ON connectors(tenant_id, created_at);

-- Connector provisioning keys: single use, 24h. Only the SHA-256 of the key is stored.
CREATE TABLE connector_provisioning_keys (
    key_hash     BLOB PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    used         INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX connector_provisioning_keys_connector ON connector_provisioning_keys(connector_id);

-- Tenant policy version: incremented on every PUT, so derived state (ConnectorConfig.Version)
-- can tell that the policy changed even within one second.
ALTER TABLE tenant_policy ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
