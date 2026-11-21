-- Admin audit log (ADR-0016): every admin write, with the acting principal. tenant_id is the
-- {t} of the route ("" for tenant creation and the Edge registry). No foreign key, so the
-- trail outlives what it describes.
CREATE TABLE admin_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    actor      TEXT NOT NULL,
    tenant_id  TEXT NOT NULL DEFAULT '',
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    status     INTEGER NOT NULL
);
CREATE INDEX admin_audit_tenant ON admin_audit(tenant_id, id);
CREATE INDEX admin_audit_at ON admin_audit(at);
