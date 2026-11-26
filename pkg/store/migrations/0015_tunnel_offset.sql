-- Stable tunnel addresses (issue #70). The Control Plane gives each device a host offset in
-- the tunnel prefixes (pkg/tunneladdr) and every Edge uses it, so a device keeps its tunnel
-- addresses when it fails over to another Edge. 0: not assigned yet (assigned at start).
-- Offsets of revoked devices are never reused.
ALTER TABLE devices ADD COLUMN tunnel_offset BIGINT NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX devices_tunnel_offset ON devices(tunnel_offset) WHERE tunnel_offset > 0;
