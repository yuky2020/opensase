# Admin guide

The OpenSASE admin portal is a web application served directly by the Control Plane at `/admin/`
when started with `-portal-dir` (or `OPENSASE_PORTAL_DIR`). It provides administrative management
for multi-tenant zero-trust access, policy enforcement, network security, and infrastructure monitoring.

For CLI management, OpenSASE provides `opensasectl`. See [Getting started](../getting-started.md)
for instructions on running the dev stack.

## Administrative roles

OpenSASE enforces role-based access control across global infrastructure and individual tenants
([ADR-0027](../adr/0027-tenant-roles.md)).

### Super-admin

The super-admin uses the token configured on the Control Plane process via the `OPENSASE_ADMIN_TOKEN`
environment variable. The super-admin has unrestricted access across all tenants and is the only
role permitted to:

- Create new tenants (`POST /v1/admin/tenants`).
- Register and revoke Edges (`POST /v1/admin/edges`, `POST /v1/admin/edges/{e}/revoke`).
- View deployment-wide health and telemetry on the Status page (`GET /v1/admin/status`).
- Inspect global audit logs across all tenants and verify the audit hash chain (`GET /v1/admin/audit/verify`).

### Tenant roles

Tenant admin tokens (prefixed with `osa_`) are scoped to a single tenant (`ST-03`). Requests to
other tenants return `404 Not Found` as if the tenant did not exist. Requests to super-admin routes
return `403 Forbidden`.

Each tenant token is assigned one of three roles at creation:

| Role | Permissions |
|---|---|
| `admin` | Full control over the tenant: users, provisioning keys, devices, connectors, admin tokens, OIDC settings, DNS, and policy. |
| `policy-editor` | Read access to all tenant resources (`GET`/`HEAD`), and write access to the tenant policy (`PUT /v1/admin/tenants/{t}/policy`). Cannot manage users, devices, connectors, or tokens. |
| `viewer` | Read-only access (`GET`/`HEAD`) across all tenant resources. Cannot modify any configuration. |

Tenant admin tokens can be created in the portal under **Admin tokens** or with the CLI:

```bash
opensasectl admin-token add -tenant <tenant> -name "Security operator" -role policy-editor -valid-for 720h -token-out operator.token
```

## Portal sections

The portal navigation includes the following sections based on the active role and tenant:

### Management

- **Overview:** Summary of the active tenant, active sessions, and security posture.
- **Get started:** The first-run onboarding wizard ([Onboarding](onboarding.md)) covering tenant setup, OIDC, baseline policy, DNS, Connectors, and device enrollment.
- **Tenants:** Tenant selection and management. Super-admins can create new tenants here.
- **Users:** Directory of tenant users, user creation, and device provisioning key issuance (including QR codes and deep links).
- **Devices:** Inventory of enrolled client devices, platform details, certificate serials, and device revocation.
- **Admin tokens:** Token creation, role assignment (`admin`, `policy-editor`, `viewer`), and token revocation.
- **Sign-in (SSO):** Configuration of OpenID Connect (OIDC) identity providers for administrative sign-in and IdP group-to-role mappings ([ADR-0031](../adr/0031-portal-oidc-sign-in.md)).

### Security and policy

- **Policy:** Visual firewall rule builder, default fallback action, user rule permissions, lockdown toggle, and raw JSON editor ([Policy](policy.md)).
- **DNS:** Internal DNS resolver configuration, domain blocking responses, query redirection, query logging, custom and built-in blocklists, and domain overrides ([DNS](dns.md)).
- **Private apps:** Zero-trust network access (ZTNA) definitions, application domain names, allowed TCP ports, connector group assignments, and user entitlements ([Private apps](private-apps.md)).
- **SaaS apps:** Catalog-based SaaS application and category blocking with discovery from recent traffic flows ([ADR-0017](../adr/0017-web-saas-control-sni.md)).
- **Categories:** Domain and URL category filtering using the UT1 public category list, and forced SafeSearch mode ([ADR-0022](../adr/0022-web-categories-ut1.md), [ADR-0025](../adr/0025-safesearch.md)).
- **Web inspection:** TLS interception at the Edge, domain bypass lists, URL path/method rules, request header injection, DLP inspection rules, and malware scanning ([ADR-0018](../adr/0018-tls-inspection.md), [ADR-0019](../adr/0019-dlp-request-bodies.md), [ADR-0020](../adr/0020-malware-scanning.md)).

### Infrastructure and observability

- **Connectors:** Deployment and status tracking of outbound-only ZTNA Connectors ([ADR-0013](../adr/0013-ztna-connector.md)).
- **Edges:** Edge node inventory, multi-tenant vs Private Edge bindings, and revocation (super-admin only).
- **Status:** Real-time health metrics across Edges, Connectors, devices, certificate expiries, leader election, and audit integrity ([Status](status.md), super-admin only).
- **Activity:** Real-time and historical flow records with filtering by decision, protocol, source device, destination, and application.
- **Security events:** Aggregated view of blocked traffic flows categorized by detection layer (DLP, malware, URL rules, web categories, SafeSearch, and SaaS control).
- **Audit:** Immutable append-only log of administrative mutations secured by a cryptographic hash chain ([ADR-0028](../adr/0028-audit-hash-chain.md)).
