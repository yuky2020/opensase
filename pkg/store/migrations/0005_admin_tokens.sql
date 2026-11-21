-- Tenant-scoped admin credentials (security finding ST-03). The configured admin token stays
-- the super-admin; these tokens administer one tenant only. Only the SHA-256 of the token is
-- stored.
CREATE TABLE admin_tokens (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  BLOB NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    last_used   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX admin_tokens_tenant ON admin_tokens(tenant_id, created_at);
