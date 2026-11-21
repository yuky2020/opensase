# ADR-0016: Tenant-scoped admin credentials

Status: accepted (2026-11-21)

## Context

Security finding ST-03 (`docs/security/sectest-2026-11-20.md`): the Control Plane had a single
admin token, and that token administered every tenant. In a multi-tenant service, one leaked
customer credential would compromise every customer. OIDC with tenant claims is the long-term
answer (`docs/components/control-plane.md`), but the API needs a tenant boundary now, and
automation needs non-interactive credentials anyway.

## Decision

- **Two kinds of admin:**
  - **Super-admin:** the token configured on the Control Plane (`$OPENSASE_ADMIN_TOKEN`), compared in
    constant time. It administers every tenant. It alone can create tenants and manage the Edge
    registry (`POST /v1/admin/tenants`, `/v1/admin/edges*`).
  - **Tenant admin:** a token minted per tenant (`POST /v1/admin/tenants/{t}/admin-tokens`) by
    the super-admin or by an admin of the same tenant.
- **Tenant admin tokens:**
  - The format is `osa_` followed by 32 random bytes (base64url).
  - Only the SHA-256 is stored (`admin_tokens`, migration 0005), as with provisioning keys.
  - The token is shown once.
  - Validity is 90 days by default, at most 365.
  - A token can be revoked at once (`.../admin-tokens/{id}/revoke`), and `last_used` is tracked
    to the minute.
- **Enforcement is one middleware on the `/v1/admin/tenants/{t}` subtree** (`requireTenantScope`),
  not a check in each handler, so a new tenant route is scoped by default.
  - For a tenant admin, another tenant answers **404**, the same answer as a tenant that does not
    exist, so tenant IDs cannot be probed.
  - Super-admin routes answer **403**.
  - `GET /v1/admin/tenants` lists only the caller's tenant.
- `GET /v1/admin/whoami` returns the role, so the portal can hide what a tenant admin cannot use
  (tenant creation, Edges). It is the same check `opensasectl whoami` makes.
- Token creation and revocation are logged with the actor (`by=super` or `by=token:<id>`), never
  with the token itself.

## Consequences

- A leaked tenant admin token exposes one tenant only, for at most its validity.
- A tenant admin can mint more tokens for its own tenant. This is no escalation, and revocation
  handles a compromise. A token cannot be minted for another tenant (404).
- Still to come:
  - an audit log of every admin write per actor (today only token writes record the actor);
  - roles inside a tenant (read-only, policy editor);
  - OIDC or SAML sign-in for the portal, mapping IdP groups to these scopes.
