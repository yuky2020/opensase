-- DLP datasets (ADR-0029, issue #15): exact data match values and document fingerprints.
-- Only keyed hashes are stored: hkey is the random HMAC key of the dataset, hashes the
-- sorted 64-bit truncated HMACs (8 bytes each, big-endian). The values and documents
-- themselves are never stored.
CREATE TABLE dlp_datasets (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL,
    hkey       BLOB NOT NULL,
    hashes     BLOB NOT NULL,
    count      INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, name)
);
