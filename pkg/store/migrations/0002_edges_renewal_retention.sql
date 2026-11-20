-- Edge registry (security review #9): an edge certificate is only accepted while its
-- ID is registered here and not revoked.
CREATE TABLE edges (
    id         TEXT PRIMARY KEY,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- Devices with a live tunnel session on an edge, as reported by that edge
-- (POST /v1/edge/sessions). An edge may decide for, and report flows of, only these devices.
CREATE TABLE edge_sessions (
    edge_id    TEXT NOT NULL REFERENCES edges(id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (edge_id, device_id)
);

-- Flow retention deletes by start time.
CREATE INDEX flows_start ON flows(start);

-- Certificate renewal (security review #4): the serial replaced by the last renewal. A device
-- may use that superseded certificate only to retry POST /v1/renew (lost response), never for
-- any other route.
ALTER TABLE devices ADD COLUMN prev_cert_serial TEXT NOT NULL DEFAULT '';
