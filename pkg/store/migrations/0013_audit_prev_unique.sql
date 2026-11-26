-- Audit chain uniqueness (issue #66, ADR-0028). With several Control Plane replicas, two
-- appends could read the same chain head and both chain to it, forking the chain. With this
-- index the second insert fails and AddAudit retries it on the new head.
-- Existing data satisfies it: every prev_hash is the hash of the entry before it (or of the
-- retention anchor, or 32 zero bytes for the first entry), and distinct entries have
-- distinct hashes, so no two rows of a valid chain share a prev_hash.
CREATE UNIQUE INDEX admin_audit_prev_hash ON admin_audit(prev_hash) WHERE prev_hash IS NOT NULL;
