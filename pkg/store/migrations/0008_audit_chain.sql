-- Hash-chained admin audit (issue #18, ADR-0028). Each entry stores the hash of the previous
-- one and its own; audit_anchor keeps the hash of the last entry removed by retention, so
-- the oldest remaining entry still verifies. Rows written before this migration are chained
-- in place by the Control Plane at start.
ALTER TABLE admin_audit ADD COLUMN prev_hash BLOB;
ALTER TABLE admin_audit ADD COLUMN hash BLOB;
CREATE TABLE audit_anchor (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    last_id INTEGER NOT NULL,
    hash    BLOB NOT NULL
);
