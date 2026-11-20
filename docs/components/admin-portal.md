# Admin Portal

## Purpose
The OpenSASE Admin Portal is a single-page web application (SPA) providing an administrative interface and self-service user portal over the Control Plane Public API. It enables tenant administrators to manage identity providers, configure and simulate granular security Policies, inspect node fleets, and analyze real-time telemetry. It also serves as the end-user portal for Client device enrollment and authorized Application Segment discovery, while treating the CLI and Terraform provider as first-class API consumers.

## Responsibilities
- Deliver an interactive, responsive administrative user interface built with React and TypeScript.
- Authenticate administrators and end users against configured OIDC/SAML Identity Providers, supporting role-based access control (RBAC) with fine-grained scoping.
- Provide a guided tenant onboarding wizard covering IdP integration, SCIM setup, root CA download, and initial connector deployment.
- Provide visual policy authoring tools for Access (ZTNA), Internet (SWG), Firewall, CASB, and DLP Rules with drag-and-drop rule ordering and conflict detection.
- Provide a Policy simulation and rule-testing engine to preview traffic decisions against mock user context, posture attributes, and destination targets before deployment.
- Maintain real-time inventory and lifecycle monitoring of data-plane nodes (Edges, Connectors, Workload Gateways, Clients).
- Host a rich log explorer with multi-field filtering, live tailing, and incident drill-down powered by the Observability API.
- Provide an end-user self-service portal displaying registered devices, enrollment status, posture health, and a catalog of accessible private applications.
- Maintain full parity between UI capabilities, the official command-line interface (`opensase-cli`), and the OpenSASE Terraform provider.
- Manage Provisioning Keys and certificate rotation schedules for enrolled connectors and client endpoints.
- Provide audit logging visualization detailing all administrative mutations, user session timelines, and policy deployments.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Admin / End User Browser | HTTPS (HTML5/JS/WASM) | Inbound to SPA | User and administrator interaction via modern web browser |
| Control Plane (Public API) | HTTPS / REST / gRPC-Web | Outbound from SPA | Admin and user operations, configuration management, telemetry queries |
| External IdP (OIDC/SAML) | HTTPS / OAuth 2.0 / SAML | Outbound from Browser/API | Authenticate administrators and end users with single sign-on (SSO) |
| CLI (`opensase-cli`) | HTTPS / REST / gRPC | Inbound to Public API | First-class programmatic terminal management and automation |
| Terraform Provider | HTTPS / REST | Inbound to Public API | Infrastructure-as-code management of OpenSASE tenants, policies, and nodes |

## Key design decisions
- **Proposed:** Single-Page Application (SPA) built with React, TypeScript, and Vite, served statically from object storage / CDN and communicating exclusively via OpenAPI-documented REST/JSON and gRPC-Web endpoints.
  *Alternative:* Server-Side Rendered (SSR) framework (e.g., Next.js or Go templates), which adds server hosting complexity without significant benefits for behind-login administrative portals.
- **Proposed:** Policy simulation executed in the Control Plane via a dry-run evaluation endpoint that reuses the exact same policy compiler engine used to generate Policy Snapshots for data-plane nodes.
  *Alternative:* Client-side JavaScript policy evaluation engine, which risks drift and discrepancies between browser simulation and actual Edge runtime behavior.
- **Proposed:** Code-generated API client bindings and TypeScript interfaces generated directly from OpenAPI 3.1 specifications and protobuf definitions to guarantee strict contract parity with CLI and Terraform.
  *Alternative:* Manually written API client libraries and manual TypeScript types, which leads to endpoint divergence, typing errors, and maintenance lag.
- **Proposed:** Scoped RBAC model supporting built-in and custom roles (e.g., Super Admin, Security Admin, Read-Only Auditor, Helpdesk) with tenant and tag-based resource scoping.
  *Alternative:* Simple binary permissions (read/write admin vs regular user), which fails compliance requirements for large enterprises with separated network and security teams.
- **Proposed:** Declarative UI state synchronizing with URL query parameters for filterable views (log explorer, node inventory) to permit shareable deep links among administrators.
  *Alternative:* Storing active filter states in ephemeral client memory or session storage, preventing direct URL bookmarking and collaboration.

## Security considerations
- Protect session tokens using secure, HttpOnly, SameSite cookies with short expiration and refresh token rotation; prevent token storage in browser localStorage.
- Enforce strict Content Security Policy (CSP), Cross-Origin Resource Sharing (CORS), and subresource integrity (SRI) headers on the static hosting layer.
- Ensure all administrative mutations create tamper-evident, attribution-rich audit log entries capturing user ID, IP address, user agent, and previous/new state diffs.
- Prevent Cross-Site Request Forgery (CSRF) on state-modifying requests through anti-CSRF token validation or custom request header requirements.
- Mask sensitive configuration values (client secrets, private keys, API tokens) in API responses and frontend views with explicit reveal actions governed by RBAC.
- Implement automated session timeout locking after periods of administrative inactivity.

## Failure modes & HA
- **Control Plane API unavailability:** The SPA displays informative degraded-mode banners, caches non-sensitive catalog data locally, and disables mutation actions until connectivity is restored.
- **Static asset distribution:** Hosting SPA bundles on global redundant CDN / multi-region object storage ensures high availability and resilience against origin outages.
- **Token expiration / IdP failure:** Expired sessions redirect cleanly to the tenant's IdP login flow; in the event of third-party IdP downtime, emergency break-glass local administrator accounts can be accessed if enabled.
- **Rate limiting:** The UI handles HTTP 429 (Too Many Requests) gracefully with user-friendly retry-after countdowns to protect the Public API from abusive polling.
- **Outdated frontend assets:** SPA service worker or bundle versioning triggers automated background cache invalidation and non-intrusive reload prompts upon new release deployments.
- **Corrupt local browser cache:** Invalidation endpoints allow administrators to force-reset local storage cache without losing active credentials.

## MVP scope vs later
### MVP
- React + TypeScript SPA with responsive layout and dark/light themes.
- Tenant onboarding wizard: IdP configuration (OIDC), Provisioning Key generation, and initial Connector setup guide.
- Policy editor for Access Rules (ZTNA), Internet Rules (SWG), and Firewall Rules with basic validation and ordering.
- Node inventory dashboard displaying status, version, and connectivity of Edges and Connectors.
- Log explorer with time-range filtering, text search, and pagination over ClickHouse logs.
- User self-service portal for Provisioning Key enrollment and listing reachable Application Segments.
- Core CLI tool and Terraform provider covering tenant, policy, and connector resources.

### Later
- Visual Policy simulation workbench showing flow evaluation traces against mock context.
- Advanced CASB and DLP incident remediation workflows (assign, comment, dismiss, quarantine).
- Granular custom role builder for admin RBAC with attribute-based access controls (ABAC).
- Live interactive topology map visualizing Clients, Edges, and Connectors.
- Multi-tenant MSP (Managed Service Provider) hierarchy and cross-tenant switching.
- SCIM directory sync visualization and attribute mapping inspector.

## Open questions
- Should the User Portal and Admin Portal remain in a unified SPA binary with role-based routing or split into separate web applications to minimize bundle size and attack surface?
- How should large policy tables (e.g., thousands of firewall rules) be rendered efficiently without browser UI thread stuttering (e.g., virtualized lists vs server-side pagination)?
- Should gRPC-Web be used directly from the browser for streaming telemetry updates, or should standard Server-Sent Events (SSE) / WebSockets over REST be preferred?
- What offline caching capabilities should be made available in the end-user portal when client endpoints lose internet access?

## Effort drivers
- Building an intuitive, high-performance rule authoring UX that represents complex ordered rules, condition groups, and posture logic without overwhelming the administrator.
- Ensuring perfect synchronization, schema validation, and test coverage across the Public API, React SPA, CLI, and Terraform provider.
- Implementing an accurate policy simulation engine that precisely reflects Edge decision logic, edge cases, and precedence rules.
- Delivering a fast, interactive log explorer experience capable of querying millions of events with arbitrary filters without timing out.
- Handling complex asynchronous error feedback across multi-step wizard workflows and bulk policy modifications.
