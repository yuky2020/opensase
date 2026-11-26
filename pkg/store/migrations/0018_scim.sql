-- SCIM 2.0 provisioning (issue #68). Users get the identity provider's external ID and an
-- active flag (deactivating a user revokes their devices); groups are named sets of users,
-- whose names are what user_groups and policy rules use; each tenant has one SCIM token.
ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN active BIGINT NOT NULL DEFAULT 1;
CREATE TABLE scim_groups (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    external_id  TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, display_name)
);
CREATE TABLE scim_tokens (
    tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at BIGINT NOT NULL
);
