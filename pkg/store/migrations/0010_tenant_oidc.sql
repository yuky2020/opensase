-- Tenant OpenID Connect configuration (issue #17, slice B, ADR-0031).
-- Allows tenant admins to sign in to the portal via an external identity provider.
CREATE TABLE tenant_oidc (
    tenant_id     TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '',
    group_roles   TEXT NOT NULL, -- JSON object group -> role
    updated_at    INTEGER NOT NULL
);
