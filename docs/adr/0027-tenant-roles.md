# ADR-0027: Roles inside a tenant

Status: accepted (2026-11-22)

## Context

ADR-0016 gives every tenant admin token full control of its tenant:
- users and provisioning keys;
- devices, connectors and tokens;
- the policy.

Teams need least privilege (issue #16):
- auditors and helpdesk staff who only look;
- security operators who change the policy but must not enroll devices, mint credentials or
  create other admins.

## Decision

- Each tenant admin token has a **role**. Migration 0007 adds `admin_tokens.role`, with
  existing tokens defaulting to `admin`.

  | Role | May |
  |---|---|
  | `admin` | everything on the tenant's routes (as before) |
  | `policy-editor` | every read, and `PUT /v1/admin/tenants/{t}/policy` |
  | `viewer` | every read (`GET`/`HEAD`) |

- The role is chosen at creation: `AdminTokenRequest.role`, `opensasectl admin-token add
  -role`, or the portal dialog. Unknown roles are refused with 400. Creating tokens is itself a
  write, so only an `admin` (or the super-admin) can mint tokens of any role. A viewer or policy
  editor cannot escalate.
- **One middleware enforces it.** `requireTenantRole` runs on the `/tenants/{t}` routes right
  after the tenant scope check. It matches on the method and the exact cleaned path, not on
  route patterns, because it runs before the sub-router matches. A refusal answers 403. It is
  audited like every admin write, with the token as actor.
- `GET /v1/admin/whoami` reports `tenantRole`. The portal shows the role in the token list and
  asks for it when creating a token.
- The super-admin (the configured token) has no role and is not limited.

## Consequences

- Global admin routes (`/whoami`, `/tenants`, catalogues) are reads and stay open to every
  tenant token. Super-admin routes stay super-admin only.
- Policy editors replace the whole tenant policy. That includes the web, DLP, category and
  SafeSearch sections, but not users, devices, connectors, keys or tokens. A finer split, for
  example a DLP-only editor, would need per-section policy endpoints.
- The portal does not yet hide write actions from viewers: the server refuses them and the
  portal shows the error. Hiding them is a portal refinement.
- Checks:
  - `TestTenantRoles`: a route-by-role matrix, a cross-tenant 404 and audited refusals;
  - SEC-TEN-027 on the live stack.
