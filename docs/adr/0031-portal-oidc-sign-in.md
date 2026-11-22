# ADR-0031: Portal OIDC sign-in

Status: accepted (2026-11-22)

## Context

Tenant administrators previously authenticated using static, long-lived tokens (`osa_`, ADR-0016)
configured and created manually. For enterprise deployments and least-privilege operations (ADR-0027),
tenants require their administrators to authenticate against their existing identity providers (issue #17).

Centralising authentication with an external identity provider ensures:
- Single sign-on for portal administrators;
- Centralised credential lifecycle and multi-factor authentication enforcement;
- Role assignment derived directly from identity provider group memberships;
- Account revocation at the identity provider immediately terminating portal access upon token expiry.

## Decision

The Control Plane integrates the relying party implementation (`pkg/oidc`) to provide authorization code flow
with PKCE for tenant admin portal sign-in.

### Configuration API

Tenant administrators configure their identity provider integration via the Admin API:
- `GET /v1/admin/tenants/{tenant}/oidc`
- `PUT /v1/admin/tenants/{tenant}/oidc`
- `DELETE /v1/admin/tenants/{tenant}/oidc`

Access is restricted to the `admin` tenant role and enforced by `requireTenantRole`. PUT validates that:
- The issuer URL uses HTTPS (or HTTP on localhost/127.0.0.1 for local testing);
- The client ID is non-empty;
- At least one group role mapping is defined;
- Every role in the mapping is a valid tenant role (`admin`, `policy-editor`, `viewer`).

Client secrets are write-only: GET never returns the secret (only `hasSecret: true/false`), and PUT with an
empty client secret preserves the stored secret. GET provides `redirectUrl` (`<ControlURL>/v1/auth/oidc/callback`).

### Authentication Flow

1. **Login Initiation (`GET /v1/auth/oidc/{tenant}/login`)**:
   - The Control Plane loads the tenant's OIDC configuration (404 if not configured).
   - The provider metadata is retrieved from an in-memory cache on the server (10-minute TTL, keyed by issuer and client ID).
   - An authorization code URL is generated with PKCE (S256), a cryptographically random state parameter, and a mandatory nonce.
   - Pending login state `{tenant, verifier, nonce, expiresAt}` is stored in memory, keyed by state, with a 10-minute expiry.
   - The map is capped at 10,000 entries (expired entries are purged first; 503 is returned if still full).
   - The server responds with `302 Found` to the authorize URL with `Cache-Control: no-store`.

2. **Callback Handling (`GET /v1/auth/oidc/callback?state=&code=`)**:
   - The pending login entry is looked up and deleted immediately (single-use state). Unknown or expired states answer `400 Bad Request` with a generic error page.
   - The authorization code and PKCE verifier are exchanged for an ID token using a 15-second context deadline.
   - The ID token is validated against the provider's JWKS: algorithm must be RS256 or ES256, signature valid, issuer matching, audience containing client ID, and nonce matching.

3. **Role Mapping and Access Decision**:
   - Roles are resolved from the ID token's `groups` claim using the tenant's `groupRoles` mapping.
   - Precedence is strictly ordered: `admin > policy-editor > viewer`.
   - If no groups match a mapped role, access is denied with `403 Forbidden` and recorded in the audit log as `oidc.login.denied` with the user subject and email.

4. **Token Minting**:
   - Upon successful verification, a scoped tenant admin token (`osa_...`) is minted with 1-hour validity.
   - The token is labelled `oidc:` followed by email (or subject if email is absent).
   - The token hash is stored in the database identically to existing tenant admin tokens.
   - A tamper-evident audit entry `oidc.login` is appended with tenant, subject, email, and mapped role. Audit entries never contain token text.

5. **Portal Redirect**:
   - The server responds with `303 See Other` redirecting to `/admin/#/oidc-signin?token=` with the URL-encoded token in the URI fragment.
   - Response headers include `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

### Security Properties

- **PKCE (S256)**: Protects authorization code exchange from interception.
- **Single-use state**: Prevents CSRF and login replay attacks.
- **Mandatory nonce**: Validates that the received ID token corresponds to the active sign-in request.
- **Exact issuer verification**: Prevents token substitution across different identity providers.
- **Asymmetric signatures only (RS256/ES256)**: Rejects insecure or symmetric signing algorithms.
- **Token in URL fragment**: Browsers do not send URI fragments to servers in HTTP requests or `Referer` headers, preventing token exposure in intermediate proxy or access logs.
- **1-hour sessions**: Short token lifespan limits the exposure window.
- **Directory group mapping**: Enforces least privilege based on identity provider directory groups.
- **Auditing with identity**: Captures user subject and email for traceability while strictly preventing token logging.

## Consequences

- The portal continues to support pasted static admin tokens for automation, testing, and break-glass scenarios.
- No refresh tokens are stored or issued; when the 1-hour session expires, administrators re-authenticate through their identity provider.
- Sign-out is achieved by token expiration or explicit revocation in the Admin Tokens screen.
