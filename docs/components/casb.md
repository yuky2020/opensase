# Cloud Access Security Broker (CASB)

## Purpose
The Cloud Access Security Broker (CASB) protects enterprise data and enforces governance across cloud software-as-a-service (SaaS) applications. It operates in dual complementary modes: CASB inline within the SWG data path for real-time traffic inspection and CASB API out-of-band for deep cloud tenant management. CASB inline delivers shadow IT discovery, application identification, tenant restriction header injection, and granular activity controls over uploads, downloads, and sharing. CASB API connects directly to SaaS provider APIs to audit data-at-rest, detect overshared or public resources, and execute automated policy remediation.

## Current implementation

The first slice is in place (ADR-0017): inline app-level control and discovery, without
decryption.
- **Catalog:** `pkg/saas` lists well-known SaaS apps with their domains and categories.
- **Policy:** `TenantPolicy.saas` blocks apps or whole categories, with exemptions. It is
  enforced on DNS by devices and Edges, and on the TLS SNI or HTTP Host of every Edge flow.
- **Discovery:** the Control Plane tags each flow record with its SaaS app, and with its web
  categories (ADR-0022). The portal's "SaaS apps" and "Web categories" pages show what was seen
  and have the block switches.

With TLS inspection (ADR-0018) a tenant can also:
- restrict SaaS logins to its own account, with request headers the Edge sets on every request
  to the app's domains (`web.headers`);
- block activities that map to a path or a method, such as uploads (`web.rules`).

Not built yet: API-mode CASB (OAuth connectors to SaaS tenants) and app-aware activity controls
(share, download) beyond paths and methods.

## Responsibilities
- Maintain an open, community-driven SaaS application catalog indexing signatures, domains, risk profiles, and compliance certifications.
- Identify cloud applications in real-time within the SWG data path using SNI, URL patterns, and HTTP request headers.
- Discover shadow IT usage by analyzing web transaction logs to generate risk-weighted application usage reports.
- Enforce tenant restrictions by dynamically injecting enterprise headers into authorized SaaS requests (e.g., Microsoft Entra `Restrict-Access-To-Tenants`, Google Workspace `X-GoogApps-Allowed-Domains`).
- Intercept and enforce granular inline user activity controls (such as blocking file uploads, preventing external sharing, and restricting copy-paste actions).
- Execute out-of-band data-at-rest scanning across cloud platforms (Microsoft 365, Google Workspace, Slack, Box, GitHub) via vendor REST APIs.
- Audit file sharing permissions, discover exposed sensitive data, and trigger remediation actions (revoke links, quarantine files, alert administrators).
- Track SaaS risk scoring metrics covering data encryption standards, compliance certifications (SOC2, ISO 27001), and vulnerability history.
- Normalize out-of-band audit event logs from heterogeneous SaaS providers into a unified OpenTelemetry security schema.
- Coordinate with the Policy Engine to apply DLP inspection profiles to both inline file transfers and out-of-band cloud repositories.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Secure Web Gateway (SWG) | In-process Go interface | Inbound / Outbound | Intercept HTTP/S sessions, match SaaS catalog signatures, inject headers, and enforce activity blocks |
| Policy Engine (in-process) | Go function call | Inbound | Query CASB policy rules for application permissions, tenant restrictions, and DLP inspection profiles |
| SaaS APIs (M365, Google, Slack, Box, GitHub) | HTTPS / REST / Webhooks | Outbound / Inbound | Query data-at-rest, poll event audit logs, receive change webhooks, and trigger remediation actions |
| Control Plane (Policy & Config Bus) | gRPC / NATS | Inbound | Receive catalog updates, API connector credentials, and out-of-band scan configurations |
| Telemetry & Log Analytics (ClickHouse) | gRPC / OTel | Outbound | Export shadow IT metrics, SaaS usage logs, risk scores, and API compliance violation events |
| Community Catalog Repository | HTTPS / Git / REST | Inbound | Ingest crowd-sourced SaaS application risk scores, domain mappings, and signature updates |
| Secret Store / Vault | HTTPS / REST | Outbound | Retrieve encrypted OAuth tokens and API client secrets for out-of-band cloud connections |

## Key design decisions
- **Dual-mode architecture**: Proposed: Decouple CASB into an inline filter module embedded inside the SWG proxy and an asynchronous worker service for API-mode connectors. Alternative: Unify inline and API scanning into a monolithic edge service.
- **Tenant restriction enforcement**: Proposed: Inline HTTP header injection during TLS inspection based on tenant identity policy and target domain classification. Alternative: DNS-level redirection to dedicated single-tenant SaaS vanity URLs.
- **Application catalog data model**: Proposed: Community-maintained, open-source Git repository containing YAML/JSON signatures and risk ratings, compiled into binary lookups. Alternative: Closed proprietary commercial signature subscription feed.
- **API scanning orchestration**: Proposed: Event-driven webhook ingestion combined with periodic incremental polling workers orchestrated by the Control Plane. Alternative: Purely periodic scheduled batch crawl of all cloud repositories.
- **Activity control parsing engine**: Proposed: Deterministic URL path and HTTP verb pattern matchers paired with lightweight JSON body inspection. Alternative: Full JavaScript emulation and browser DOM sandboxing for dynamic web applications.
- **Remediation execution model**: Proposed: Asynchronous remediation dispatch queue with dry-run verification and administrative confirmation workflows. Alternative: Immediate hard inline blocking and file deletion via synchronous API calls.

## Security considerations
- Secure storage, rotation, and encryption of OAuth2 tokens and service account secrets required for SaaS API connectors.
- Multi-tenant isolation within API workers to ensure customer credentials and scanned metadata never cross tenant boundaries.
- Preventing information disclosure or credential leakage during header injection and HTTP payload inspection.
- Protecting the community-driven application catalog against malicious or poisoned signature contributions via review workflows and cryptographic signing.
- Rate-limiting SaaS API requests to avoid triggering provider throttling, account lockout, or service disruption.
- Safeguarding downloaded data-at-rest file fragments during scanning by keeping them strictly in ephemeral encrypted memory.
- Ensuring compliance with SaaS provider terms of service regarding automated scanning and API access policies.

## Failure modes & HA
- **SaaS API rate limiting or outage**: Out-of-band workers implement exponential backoff, jitter, and checkpointed cursors; data plane inline traffic remains unaffected.
- **Inline signature match timeout**: SWG falls back to standard URL categorization without delaying the flow; anomaly logged for catalog tuning.
- **OAuth token expiration or revocation**: API connector flags the tenant integration as degraded, alerts administrators, and halts scanning until re-authenticated.
- **Worker crash during file scanning**: Job queues backed by persistent state (PostgreSQL / NATS) allow worker replicas to resume interrupted scans from last checkpoint.
- **Header injection failure or corruption**: Edge proxy fails closed for managed tenants requiring strict data boundary enforcement, logging a security alert.
- **SaaS API schema drift**: Connector catches parsing errors, isolates the affected resource, and triggers an alert for signature and parser updates.

## MVP scope vs later
### MVP
- Inline SaaS application identification for top 50 popular cloud services (M365, Google Workspace, Salesforce, Slack, GitHub, Box, Dropbox).
- Tenant restriction header injection for Microsoft 365 and Google Workspace.
- Basic inline activity controls (read-only enforcement via HTTP POST / PUT blocking on specific SaaS endpoints).
- Shadow IT reporting generated from SWG log telemetry using an initial open application risk catalog.
- API-mode connector for Google Workspace and Microsoft 365 scanning public file shares and orphaned links.
- Community catalog schema defined in YAML with baseline risk ratings.

### Later
- Full SaaS Security Posture Management (SSPM) evaluating misconfigurations across cloud tenants against CIS benchmarks.
- Broadened API connector ecosystem covering Slack, Box, GitHub, Zoom, Jira, and AWS IAM.
- Real-time automated remediation workflows (auto-quarantine, legal hold, DLP payload redaction).
- Advanced inline activity decoding for single-page applications (WebSocket messages, asynchronous AJAX requests).
- Crowd-sourced web portal for community submission, peer review, and automated testing of SaaS app signatures.
- Contextual step-up authentication triggering IdP re-authentication upon detecting risky SaaS activities.

## Open questions
- Balancing the frequency of API polling against SaaS provider API quotas and operational rate limits across thousands of customer tenants.
- Mechanism for reliably detecting evasive or newly changed SaaS endpoints before community catalog signatures are updated.
- Best architectural pattern for handling very large file downloads during API-mode data-at-rest DLP scans without exhausting worker storage.
- Extent to which SSPM capabilities should be prioritized over expanding API connectors for niche cloud services.
- Strategy for handling enterprise SaaS tenants spanning multiple geo-distributed regions and data sovereignty requirements.
- Legal implications and disclaimer frameworks for publishing open-source SaaS application risk ratings.

## Effort drivers
- Keeping pace with rapid, unannounced UI and API changes across major commercial SaaS platforms that break signatures and header injection.
- Managing OAuth token lifecycles, permissions scopes, and enterprise consent flows across heterogeneous third-party identity providers.
- Building resilient, rate-limit-aware API crawling engines capable of scanning petabyte-scale cloud repositories.
- Reverse-engineering complex single-page application (SPA) network protocols to reliably distinguish file uploads and shares from normal navigation.
- Establishing and moderating a high-quality community-driven application risk scoring catalog.
- Handling data residency and regulatory compliance constraints when processing multi-tenant SaaS data across jurisdictions.
