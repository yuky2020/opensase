-- Authorised CIDRs for Workload Gateways in routed mode (issue #21, slice B).
-- In routed mode, traffic from these workload subnets enters the Edge un-NATed
-- and is attributed to the gateway device.
CREATE TABLE device_routes (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    cidr      TEXT NOT NULL,
    PRIMARY KEY (device_id, cidr)
);
CREATE INDEX device_routes_tenant ON device_routes(tenant_id, device_id);
