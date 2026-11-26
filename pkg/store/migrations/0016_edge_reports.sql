-- Last session report per Edge (issue #73), for the portal status page and alerts: an Edge
-- that stops reporting is down or cut off from the Control Plane. No foreign key: Edges
-- listed only in edges.json are not in the edges table.
CREATE TABLE edge_reports (
    edge_id     TEXT PRIMARY KEY,
    reported_at BIGINT NOT NULL
);
