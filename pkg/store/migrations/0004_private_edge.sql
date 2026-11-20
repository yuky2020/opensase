-- Private Edge (ADR-0014): a registered edge bound to one tenant. NULL = public multi-tenant edge.
ALTER TABLE edges ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE;
