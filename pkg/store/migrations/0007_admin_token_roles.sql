-- Roles of tenant admin tokens (ADR-0027, issue #16): admin (everything in the tenant),
-- policy-editor (read, and write the tenant policy), viewer (read only). Existing tokens keep
-- their full rights.
ALTER TABLE admin_tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
