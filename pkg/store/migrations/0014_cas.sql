-- Tenant and inspection CAs in the database (issue #66). Several Control Plane replicas
-- must issue and trust the same CA for a tenant; files in each replica's PKI directory
-- cannot guarantee that. Private keys are sealed (AES-256-GCM) with the CA key encryption
-- key before they are stored; the database never holds them in clear.
CREATE TABLE cas (
    tenant_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    cert_pem   BLOB NOT NULL,
    sealed_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, kind)
);
