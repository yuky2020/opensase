-- Device enrolment through the identity provider (issue #68). A pending sign-in is either an
-- admin portal sign-in or a device enrolment, which returns to the client's loopback or app
-- URL; user_groups keeps the groups the identity provider (ID token or SCIM) reports.
ALTER TABLE oidc_pending ADD COLUMN purpose TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE oidc_pending ADD COLUMN return_to TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_pending ADD COLUMN client_state TEXT NOT NULL DEFAULT '';
CREATE TABLE user_groups (
    tenant_id TEXT NOT NULL,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grp       TEXT NOT NULL,
    PRIMARY KEY (user_id, grp)
);
CREATE INDEX user_groups_tenant ON user_groups(tenant_id, grp);
