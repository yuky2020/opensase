# Admin and device API reference

This page documents the HTTP API endpoints exposed by the OpenSASE Control Plane and Edge services,
derived directly from `pkg/api/types.go`.

## Authentication and transport

### Transport security

- **TLS version:** TLS 1.3 only.
- **Key exchange:** Restricted to post-quantum hybrid `X25519MLKEM768` ([ADR-0002](../adr/0002-client-tunnel-wireguard-pq-psk.md)).
- **Identity validation:** Clients verify server certificates by checking the SPIFFE ID in the Subject Alternative Name:
  - Control Plane: `spiffe://opensase/controlplane`
  - Edge: `spiffe://opensase/edge/<EdgeInfo.ID>`
- **Trust bootstrap:** Devices pin the SHA-256 fingerprint of the provider root CA certificate provided in the control URL fragment (`#sha256=<hex>`).

### Administrative authentication

Administrative endpoints under `/v1/admin/` require a Bearer token in the HTTP `Authorization` header:

```http
Authorization: Bearer <admin-token>
```

Administrative tokens operate under two distinct scopes:

1. **Super-admin:**
   - Configured via the `OPENSASE_ADMIN_TOKEN` environment variable on the Control Plane.
   - Grants global administrative access across all tenants, Edge registration, tenant provisioning, and global audit verification.
2. **Tenant admin tokens:**
   - Created per tenant with the `osa_` prefix ([ADR-0016](../adr/0016-tenant-admin-tokens.md), [ADR-0027](../adr/0027-tenant-roles.md)).
   - Strictly scoped to a single tenant; attempts to access other tenants return `404 Not Found`.
   - Access to super-admin routes returns `403 Forbidden`.
   - Operates under three permission roles:
     - `admin`: Full administrative control over all tenant-level resources.
     - `policy-editor`: Read access to tenant resources, plus permission to update the tenant policy (`PUT /v1/admin/tenants/{t}/policy`).
     - `viewer`: Read-only (`GET` and `HEAD`) access to tenant resources.

### Client and device authentication

Device, Edge, and Connector endpoints use mutual TLS (mTLS) with certificates issued by the tenant CA:

- **Device certificates:** Issued during enrollment (`POST /v1/enroll`), valid for 24 hours, and renewed at 50% of their lifetime.
- **Edge certificates:** Issued during PKI setup (`spiffe://opensase/edge/<id>`), validated against the Control Plane Edge registry.
- **Connector certificates:** Issued during connector enrollment (`spiffe://opensase/tenant/<t>/connector/<id>`), valid for 24 hours.

---

## Device and client endpoints

These endpoints handle device enrollment, policy snapshot distribution, and client flow logging.

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/enroll` | Public | Enrolls a device using a provisioning key and CSR; returns device certificates and trust bundle. |
| `GET` | `/v1/enroll/oidc/{tenant}/start` | Public | Initiates OIDC sign-in with the tenant identity provider; redirects with a single-use provisioning key. |
| `GET` | `/v1/auth/oidc/{tenant}/login` | Public | Redirects browser to the tenant identity provider authorization URL for portal sign-in. |
| `GET` | `/v1/auth/oidc/callback` | Public | Receives the identity provider OAuth authorization code and redirects to the portal with an admin session. |
| `GET` | `/v1/snapshot` | Device | Fetches the compiled and signed policy snapshot envelope; supports `ETag` and `If-None-Match`. |
| `GET` | `/v1/snapshot?wait=30` | Device | Long-polls for snapshot updates; returns immediately on new versions or `304 Not Modified` after timeout. |
| `POST` | `/v1/renew` | Device / Renewal | Renews the 24-hour device certificate using a fresh key and CSR; accepts just-superseded certificate on retry. |
| `GET` | `/v1/self/rules` | Device | Retrieves user-defined firewall rules and per-app policies stored on the Control Plane. |
| `PUT` | `/v1/self/rules` | Device | Updates user-defined firewall rules and triggers a snapshot recompile; returns `403` if disabled by tenant. |
| `POST` | `/v1/decide` | Device / Edge | Requests a cloud policy decision for deferred ("ask") flows; supports Edge proxying with `?device=<id>`. |
| `POST` | `/v1/flows` | Device / Edge | Submits a batch of logged flow records with policy decisions and byte counters. |
| `GET` | `/v1/edges` | Device | Retrieves the list of available Edges ordered by priority for tunnel selection. |
| `GET` | `/v1/pki/ca` | Public | Exports the public PEM certificate bundle of tenant CAs and snapshot signing public keys. |

---

## Edge session endpoints

These endpoints run on the Edge session-setup listener (`:8443`) and manage WireGuard tunnel establishment ([ADR-0002](../adr/0002-client-tunnel-wireguard-pq-psk.md)).

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/session` | Device | Establishes a WireGuard session, allocates tunnel IP addresses, and derives the post-quantum PSK. |
| `GET` | `/v1/session/{sessionId}` | Device | Verifies whether the specified session identifier is actively live on this Edge (returns `204` or `404`). |

---

## Edge coordination endpoints

These endpoints run on the Control Plane and are called by Edges using mTLS edge certificates.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/v1/edge/peers` | Edge | Synchronizes accepted device snapshots and active connectors; Private Edges receive only their tenant. |
| `POST` | `/v1/edge/sessions` | Edge | Reports active device and connector sessions live on the Edge; transmitted every 10 seconds. |
| `GET` | `/v1/edge/categories` | Edge | Downloads compiled binary web category data matching the requested category names; supports `ETag`. |
| `POST` | `/v1/edge/inspection-ca` | Edge | Retrieves the tenant web inspection CA certificate and private key for TLS decryption ([ADR-0018](../adr/0018-tls-inspection.md)). |
| `GET` | `/v1/edge/dlp-datasets` | Edge | Downloads keyed hashes for tenant exact data match DLP inspection datasets ([ADR-0029](../adr/0029-dlp-exact-data-match.md)). |

---

## Connector endpoints

These endpoints manage private application Connectors and the ZTNA broker channel ([ADR-0013](../adr/0013-ztna-connector.md)).

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/connector/enroll` | Public | Enrolls a Connector using a one-time provisioning key and CSR; returns connector identity certificate. |
| `GET` | `/v1/connector/config` | Connector | Long-polls for assigned private applications and routing configuration; supports `ETag`. |
| `POST` | `/v1/connector/renew` | Connector / Renewal | Renews the 24-hour Connector certificate using a fresh key and CSR. |
| `POST` | `/v1/dial` | Broker (Edge) | Sent by Edge to Connector over the reverse HTTP/2 broker channel to proxy TCP streams to private apps. |

---

## Admin endpoints: global and infrastructure

These endpoints require Bearer authentication with the super-admin token (`OPENSASE_ADMIN_TOKEN`), except where noted.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/v1/admin/whoami` | Any Admin | Returns the authenticated identity, tenant scope, token ID, and role. |
| `GET` | `/v1/admin/info` | Any Admin | Returns the pinned Control Plane URL (with root SHA-256 fingerprint), server version, and feature list. |
| `GET` | `/v1/admin/saas/catalog` | Any Admin | Lists built-in SaaS applications and domain definitions ([ADR-0017](../adr/0017-web-saas-control-sni.md)). |
| `GET` | `/v1/admin/categories` | Any Admin | Lists loaded web categories, licence metadata, and domain counts from the UT1 catalog ([ADR-0022](../adr/0022-web-categories-ut1.md)). |
| `GET` | `/v1/admin/blocklists` | Any Admin | Lists available built-in threat intelligence blocklists. |
| `GET` | `/v1/admin/status` | Super-admin | Reports deployment health, reporting Edges, live sessions, connectors, and certificate expirations. |
| `GET` | `/v1/admin/tenants` | Any Admin | Lists tenants; super-admins see all tenants, tenant admins see only their own. |
| `POST` | `/v1/admin/tenants` | Super-admin | Creates a new tenant and initializes its dedicated certificate authority. |
| `GET` | `/v1/admin/edges` | Super-admin | Lists all registered public and private Edges. |
| `POST` | `/v1/admin/edges` | Super-admin | Registers an Edge identifier; setting `tenantId` binds it as a Private Edge ([ADR-0014](../adr/0014-private-edge.md)). |
| `POST` | `/v1/admin/edges/{e}/revoke` | Super-admin | Revokes an Edge registration and invalidates its certificate acceptance. |
| `GET` | `/v1/admin/audit` | Super-admin | Queries administrative audit log entries across all tenants. |
| `GET` | `/v1/admin/audit/verify` | Super-admin | Verifies cryptographic integrity of the admin audit hash chain ([ADR-0028](../adr/0028-audit-hash-chain.md)). |

---

## Admin endpoints: tenant management

These endpoints administer resources within a specific tenant (`/v1/admin/tenants/{t}/...`).
They are accessible to the super-admin and to tenant admin tokens matching `{t}`.

| Method | Path | Minimum role | Description |
|---|---|---|---|
| `GET` | `/v1/admin/tenants/{t}/users` | `viewer` | Lists users registered in the tenant directory. |
| `POST` | `/v1/admin/tenants/{t}/users` | `admin` | Adds a new user to the tenant directory. |
| `POST` | `/v1/admin/tenants/{t}/provisioning-keys` | `admin` | Generates a single- or multi-use device provisioning key for a user. |
| `GET` | `/v1/admin/tenants/{t}/policy` | `viewer` | Retrieves the active tenant security policy JSON; sets `ETag`. |
| `PUT` | `/v1/admin/tenants/{t}/policy` | `policy-editor` | Replaces the tenant policy and recompiles device snapshots; verifies `If-Match`. |
| `GET` | `/v1/admin/tenants/{t}/devices` | `viewer` | Lists all enrolled client devices belonging to the tenant. |
| `POST` | `/v1/admin/tenants/{t}/devices/{d}/revoke` | `admin` | Revokes a device certificate and drops active tunnel sessions. |
| `GET` | `/v1/admin/tenants/{t}/devices/{d}/routes` | `admin` | Retrieves authorized routed CIDRs for a Workload Gateway device. |
| `PUT` | `/v1/admin/tenants/{t}/devices/{d}/routes` | `admin` | Sets authorized routed CIDRs for a Workload Gateway device. |
| `GET` | `/v1/admin/tenants/{t}/flows` | `viewer` | Queries recent flow records and policy decisions for the tenant. |
| `GET` | `/v1/admin/tenants/{t}/connectors` | `viewer` | Lists all ZTNA Connectors configured for the tenant. |
| `POST` | `/v1/admin/tenants/{t}/connectors` | `admin` | Creates a new Connector and returns a single-use provisioning key. |
| `POST` | `/v1/admin/tenants/{t}/connectors/{c}/revoke` | `admin` | Revokes a Connector registration. |
| `GET` | `/v1/admin/tenants/{t}/admin-tokens` | `viewer` | Lists scoped admin tokens created for the tenant. |
| `POST` | `/v1/admin/tenants/{t}/admin-tokens` | `admin` | Creates a new scoped tenant admin token with role `admin`, `policy-editor`, or `viewer`. |
| `POST` | `/v1/admin/tenants/{t}/admin-tokens/{id}/revoke` | `admin` | Revokes a tenant admin token. |
| `GET` | `/v1/admin/tenants/{t}/audit` | `viewer` | Retrieves the immutable audit log of administrative actions for the tenant. |
| `GET` | `/v1/admin/tenants/{t}/inspection-ca` | `viewer` | Downloads the tenant TLS inspection root CA certificate in PEM format ([ADR-0018](../adr/0018-tls-inspection.md)). |
| `GET` | `/v1/admin/tenants/{t}/dlp-datasets` | `viewer` | Lists exact data match DLP datasets configured for the tenant ([ADR-0029](../adr/0029-dlp-exact-data-match.md)). |
| `PUT` | `/v1/admin/tenants/{t}/dlp-datasets/{name}` | `admin` | Uploads values or documents for exact data match DLP inspection; stores keyed hashes only. |
| `DELETE` | `/v1/admin/tenants/{t}/dlp-datasets/{name}` | `admin` | Deletes a DLP exact data match dataset. |
| `GET` | `/v1/admin/tenants/{t}/oidc` | `viewer` | Retrieves the tenant OIDC identity provider configuration and role mappings ([ADR-0031](../adr/0031-portal-oidc-sign-in.md)). |
| `PUT` | `/v1/admin/tenants/{t}/oidc` | `admin` | Configures or updates the tenant OIDC identity provider and group role mappings. |
| `DELETE` | `/v1/admin/tenants/{t}/oidc` | `admin` | Deletes the tenant OIDC identity provider configuration. |
