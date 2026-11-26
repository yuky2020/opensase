-- Pending OpenID Connect sign-ins (issue #66, ADR-0031). The state, PKCE verifier and nonce
-- of a sign-in started on one Control Plane replica must be found by the replica that
-- receives the callback, so they live in the database instead of process memory. Rows live
-- 10 minutes and are taken (deleted) once.
CREATE TABLE oidc_pending (
    state      TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    verifier   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX oidc_pending_expires ON oidc_pending(expires_at);
