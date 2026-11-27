# Threat Model: OpenSASE

## 1. System context

OpenSASE is an open-source, self-hosted, post-quantum SASE platform (Go monorepo with Flutter apps). Its central part has two components. The **Control Plane** handles tenants, users, the PKI, policy snapshots, enrolment, the hash-chained audit log, the admin API and the web admin portal. The **Edge** terminates client tunnels: WireGuard with a post-quantum PSK negotiated over TLS 1.3 with X25519MLKEM768 only. It enforces the tenant policy (firewall, DNS filter, web and category control, SafeSearch, ECH stripping, optional TLS inspection with DLP and malware scanning), brokers ZTNA traffic to **Connectors** in private networks, and records flows. A **Private Edge** can run offline from a signed cache.

The **clients** are:

- the Android app;
- the Windows and Linux desktop service `opensased`, with the Flutter app and the `opensase` CLI talking to it over a local API;
- the Linux `opensase-client`, which can also act as a Workload Gateway.

They enrol with a provisioning key and then authenticate with device certificates.

The primary deployment is one small company (10-200 people, one admin), self-hosted with Docker Compose (or the all-in-one quick start image) or Kubernetes. Edges and the Control Plane are exposed to the internet; Connectors dial out from private networks.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| root CA and tenant CA keys | Root CA key, per-tenant CA keys (created on demand) and the Control Plane server key; they sign device, Edge and Connector identities | critical |
| snapshot signing key | Ed25519 key that signs policy snapshots and offline caches; clients and Edges trust whatever it signs | critical |
| tunnel session keys | Per-session WireGuard keys and the PQ PSK exported from the TLS session | high |
| device and connector credentials | Device and Connector private keys and certificates, provisioning keys and enrolment URIs | high |
| admin credentials | Super-admin token, tenant admin tokens, OIDC client secrets and portal sessions | critical |
| tenant policy integrity | The policy each device and Edge enforces (rules, categories, DLP, private apps, lockdown) | high |
| user traffic confidentiality | Content and metadata of user traffic through the tunnel, including decrypted traffic when TLS inspection is on | high |
| TLS inspection CA key | Per-tenant inspection CA trusted by inspected devices | high |
| flow records and audit log | Per-device flow history (personal data) and the hash-chained admin audit log | medium |
| private application reachability | Internal services reachable through Connectors (ZTNA) | high |
| service availability | Control Plane, Edge and client connectivity for the company | medium |
| client host integrity | The user's device: routing, DNS, firewall state and the privileged desktop service | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Control Plane HTTPS API | TLS 1.3 PQ-only listener (9443) serving device, Edge, Connector and admin routes, with mTLS via certificates or Bearer admin tokens | internet → Control Plane process | root CA and tenant CA keys, snapshot signing key, tenant policy integrity, flow records and audit log, admin credentials, service availability |
| Enrolment endpoint | `/v1/enroll` and Connector enrolment with a provisioning key and a CSR | unauthenticated internet → device identity issuance | device and connector credentials, root CA and tenant CA keys |
| Admin portal and OIDC sign-in | Flutter web portal under `/admin/`, admin token sign-in and OIDC (PKCE, nonce) callbacks | browser and identity provider → admin session | admin credentials, tenant policy integrity |
| Edge session endpoint | TLS 1.3 PQ-only session setup (8443) with device mTLS; derives the WireGuard PSK | internet → Edge process | tunnel session keys, service availability |
| WireGuard tunnel | UDP 51820 handshakes and encrypted traffic from devices | internet → Edge userspace WireGuard | tunnel session keys, service availability |
| Edge data plane | Decrypted device traffic: DNS resolver, SNI/Host web control, HTTP, NAT egress, ZTNA redirect | enrolled device → Edge policy engine and egress network | tenant policy integrity, user traffic confidentiality, private application reachability, service availability |
| Content inspection | TLS inspection proxy, DLP extraction (PDF, Office, ZIP), malware scanning (clamd or ICAP) and the OCR service | attacker-controlled file content → parsers and helper services | user traffic confidentiality, TLS inspection CA key, service availability |
| Connector broker | Edge listener (8444) for Connectors with mTLS, plus the Connector's outbound dials into the private network | private network connector ↔ Edge | private application reachability, device and connector credentials |
| Desktop daemon local API | Unix socket (group `opensase`) or named pipe of `opensased`, used by the app and the CLI | local unprivileged user → privileged system service | client host integrity, device and connector credentials |
| Client host network stack | Routes, DNS settings and firewall state configured by the client on Android, Windows and Linux | client process ↔ operating system networking | user traffic confidentiality, client host integrity |
| Private Edge offline cache | Signed snapshot cache loaded by an Edge without the Control Plane | file on disk → Edge enforcement | tenant policy integrity |
| Category list download | UT1 web category archive fetched by the Control Plane from a third-party URL and distributed to Edges | third-party server → Control Plane → Edges | tenant policy integrity, service availability |
| PKI files and secrets at rest | PKI directory, SQLite database, admin token files, quick start `/data` volume, Kubernetes Secrets | host or cluster operator access → key material | root CA and tenant CA keys, snapshot signing key, admin credentials, flow records and audit log |
| Build and release pipeline | Go modules, Flutter packages, GitHub Actions, Wintun download, container images, MSI/deb/rpm/Arch/APK artifacts | third-party code and CI → shipped binaries | client host integrity, root CA and tenant CA keys, user traffic confidentiality |
| Deployment configuration | Docker Compose files, the all-in-one quick start image, the Edge entrypoint (iptables, capabilities) and the planned Helm charts | operator configuration → runtime privileges | root CA and tenant CA keys, service availability, private application reachability |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Theft of the CA or snapshot signing keys from the central host lets an attacker mint identities and sign policy for every device | insider | PKI files and secrets at rest; Deployment configuration | root CA and tenant CA keys, snapshot signing key | existential | possible | partially_mitigated | Edge mounts only `pki/edge`; key files 0600; Control Plane runs non-root with cap_drop and read-only root; no HSM and no encryption at rest | review-2026-11-19 #2, ST-09 |
| T2 | Takeover of the admin API or portal through stolen tokens or a flawed sign-in flow gives control of a tenant's policy and devices | remote_unauth | Admin portal and OIDC sign-in; Control Plane HTTPS API | admin credentials, tenant policy integrity | critical | possible | partially_mitigated | Tenant-scoped admin tokens with roles and expiry; OIDC with PKCE S256 and mandatory nonce; audit log per actor; no MFA of its own; super-admin token is long-lived | ST-03, c31e61a |
| T3 | Code execution or memory exhaustion in content-inspection helpers through attacker-supplied files | remote_unauth | Content inspection | user traffic confidentiality, TLS inspection CA key, service availability | critical | possible | partially_mitigated | Go parsers with size caps; malware scanner and OCR run as separate containers; fuzz targets on DLP parsers; native scanners and OCR libraries are third-party C code |  |
| T4 | Impersonation of the Control Plane or an Edge to deliver attacker policy or capture sessions | adjacent_network | Control Plane HTTPS API; Edge session endpoint | snapshot signing key, tenant policy integrity, tunnel session keys | critical | rare | mitigated | Distinct SANs and SPIFFE URI checks per server role; pinned root CA fingerprint in enrolment URIs; signed snapshots; PQ TLS checked before any request | review-2026-11-19 #1, #12 |
| T5 | Cross-tenant access: an identity of one tenant reads or changes another tenant's data or decides for its devices | remote_auth | Control Plane HTTPS API; Connector broker | tenant policy integrity, flow records and audit log, private application reachability | critical | rare | mitigated | Tenant-scoped tokens and certificates; Edge registry scoping; tenant checks in handlers; sectest tenant cases | ST-03, review-2026-11-19 #9 |
| T6 | Supply-chain compromise of a dependency, CI action or release artifact ships a backdoored client or server | supply_chain | Build and release pipeline | client host integrity, root CA and tenant CA keys, user traffic confidentiality | critical | rare | partially_mitigated | go.sum; Wintun pinned by SHA-256; SHA256SUMS; release gate on green CI; actions pinned by major version only; MSI unsigned; APK debug-signed; images unsigned |  |
| T7 | Downgrade of the post-quantum key exchange to classical cryptography, exposing recorded traffic to future decryption | adjacent_network | Control Plane HTTPS API; Edge session endpoint; WireGuard tunnel | tunnel session keys, user traffic confidentiality | critical | very_rare | mitigated | `pqsession.Harden` restricts TLS 1.3 to X25519MLKEM768 on every listener and client; PSK bound to the TLS exporter; sectest 10-tls |  |
| T8 | Device traffic or DNS leaks outside the tunnel (Windows without a kill switch, IPv6, daemon crash, captive networks), bypassing policy and exposing users | local_user | Client host network stack | user traffic confidentiality, tenant policy integrity | high | likely | partially_mitigated | Split default routes; DNS set on the tunnel; Android always-on VPN; Windows dynamic WFP kill switch (fails open during daemon restart window, ADR-0049); IPv6 default route kept when the tunnel has no IPv6 | ADR-0032, #38, #49 |
| T9 | Policy bypass on the Edge data plane: reaching blocked destinations through alternative resolvers, encrypted DNS, ECH, IP literals, encodings or name variants | remote_auth | Edge data plane | tenant policy integrity | high | likely | partially_mitigated | Edge forces DNS to its resolver and blocks DoT/DoH; ECH stripping; SNI and Host checks; category name variants; URL normalisation under inspection; sectest SEC-DP cases | review-2026-11-19 #6, ST-10 |
| T10 | Device impersonation or takeover with a stolen, superseded or replayed credential | remote_unauth | Enrolment endpoint; Edge session endpoint | device and connector credentials, tunnel session keys | high | possible | mitigated | Certificate serial checks on the Edge and the broker; superseded certificates cannot renew; tunnels bounded after renewal; provisioning keys never on argv; enrolment rate limit | ST-01, ST-02, ST-04, ST-05, ST-10, review-2026-11-19 #13 |
| T11 | Tunnel clients use the Edge as a pivot into infrastructure (cloud metadata, Control Plane, host, container networks) | remote_auth | Edge data plane | service availability, root CA and tenant CA keys, private application reachability | high | possible | mitigated | Built-in deny list (18 prefixes) before tenant policy; FORWARD default DROP; allow-private off by default | review-2026-11-19 #3 |
| T12 | Local privilege escalation or credential theft through the desktop service's local API | local_user | Desktop daemon local API | client host integrity, device and connector credentials | high | possible | mitigated | Unix socket group check with SO_PEERCRED (unreadable credentials refused); named pipe DACL; enrol and unenrol admin-only via token impersonation, no PID fallback; Host header check; body and stream limits; state files with private ACLs | 9d2eced, 77c45f3 |
| T13 | A compromised or malicious Connector exposes or tampers with private applications or pivots into the Edge | remote_auth | Connector broker | private application reachability, device and connector credentials | high | possible | partially_mitigated | Per-Connector certificates with serial checks; revocation; outbound-only Connector; private apps scoped per tenant; no per-app posture yet | ST-04 |
| T14 | Weak runtime isolation in a deployment (privileged Edge next to CA keys, the all-in-one quick start, permissive Kubernetes namespaces) turns an Edge compromise into a CA compromise | remote_unauth | Deployment configuration | root CA and tenant CA keys, service availability | high | possible | partially_mitigated | Compose separates Control Plane and Edge with least privilege; quick start documented as trials only; Helm plan separates namespaces | review-2026-11-19 #2, ST-08 |
| T15 | Misuse or theft of the TLS inspection CA lets an attacker intercept inspected users' HTTPS traffic | insider | Content inspection; PKI files and secrets at rest | TLS inspection CA key, user traffic confidentiality | high | rare | partially_mitigated | Inspection is opt-in per tenant and per rule; upstream certificates verified (no silent MITM); CA key stored with the Edge state |  |
| T16 | Tampering with the Private Edge offline cache changes the policy enforced while offline | local_admin | Private Edge offline cache | tenant policy integrity | high | rare | mitigated | Signed cache verified against trusted keys, not keys inside the cache; cache re-scoped to its tenant on load | ST-06, ST-07 |
| T17 | Denial of service against the Control Plane or Edge through enrolment floods, long-polls, flow uploads, peer-sync amplification or tunnel handshakes | remote_unauth | Control Plane HTTPS API; Enrolment endpoint; WireGuard tunnel; Edge session endpoint | service availability | medium | likely | partially_mitigated | Per-route deadlines; long-poll and flow rate limits; enrolment rate limit; singleflight peer sync; WireGuard cookie mechanism; single Control Plane replica | review-2026-11-19 #7, #8, #10, ST-05 |
| T18 | Over-collection or insider misuse of flow records reveals individual users' browsing and application use | insider | Control Plane HTTPS API; Edge data plane | flow records and audit log | medium | likely | partially_mitigated | Flow retention (7 days default); admin actions audited; tenant scoping; no per-user export or deletion workflow yet | review-2026-11-19 #10 |
| T19 | Poisoned or oversized web category data changes blocking decisions or exhausts Control Plane and Edge resources | remote_unauth | Category list download | tenant policy integrity, service availability | medium | rare | partially_mitigated | HTTPS download; archive parsing with limits; last good list kept on failure; no signature on the third-party archive |  |
| T20 | Admin actions are denied or the audit trail is silently rewritten | insider | Control Plane HTTPS API; PKI files and secrets at rest | flow records and audit log | medium | rare | mitigated | Hash-chained audit log with verification and published heads (ADR-0028); actor recorded per request | 88ca638 |

## 5. Deprioritized

| threat | reason |
|---|---|
| Memory-corruption RCE in the Go services from network input | Go is memory-safe and there is no cgo in the services; the native-code risk is captured in T6 for the third-party inspection helpers |
| SQL injection in the Control Plane store | All queries use parameters through database/sql; no query is built from input strings |
| Nation-state compromise of the X25519MLKEM768 primitives | Out of scope: the hybrid exchange stays as strong as X25519 if ML-KEM fails; tracked by following standards |
| Physical theft of an unlocked client device | Out of scope for the platform; handled by OS disk encryption and device revocation (posture checks planned) |
| Repudiation by end users of their own traffic | Flow records are operational telemetry, not legal evidence; T19 covers their privacy side |

## 6. Open questions

- Where will customers run the Control Plane: a dedicated host, or shared with other services? T1 and T15 depend on it.
- Should the root CA key stay online in the Control Plane at all, or be kept offline with an intermediate CA online?
- Is MFA expected for the super-admin token and portal sign-in, or is the identity provider's MFA (via OIDC) enough?
- Is the TLS inspection CA key expected to live in an HSM or a separate key store for production tenants?
- What is the accepted fail mode for clients when the daemon crashes: fail open (today) or fail closed (persistent filters)? See the Windows kill switch decision.
- What retention and per-user deletion rules do customers need for flow records (data protection)?
- Is a third-party category feed acceptable without a signature, or should OpenSASE mirror and sign it?
- How are the malware scanner and OCR containers isolated in Kubernetes (network policies, seccomp)?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-25
- target: https://github.com/yuky2020/opensase @ 042e6b4
- inputs: git history, docs/security/review-2026-11-19.md, docs/security/sectest-2026-11-20.md, docs/adr, docs/architecture.md, test/security
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Keep the root CA offline and issue from an online intermediate; encrypt tenant CA and signing keys at rest with a key outside the database and PKI volume | T1,T14 | partial | M |
| Sign every release artifact (MSI, binaries, APK release key, cosign for images and checksums) and pin CI actions by commit SHA | T6 | partial | M |
| Ship fail-closed client networking on every platform (WFP filters on Windows, nftables on Linux, always-on VPN on Android) including IPv6 | T8 | yes | M |
| Run third-party content parsers (malware scanner, OCR) in isolated containers with no network access other than the Edge and with seccomp profiles; keep fuzzing the Go extractors | T3 | partial | M |
| Require MFA through the identity provider for admins and make the super-admin token short-lived or break-glass only | T2 | partial | S |
| Add per-user export and deletion of flow records and a documented retention policy | T18 | partial | S |
| Verify a signature or pinned digest for the category archive (mirror and sign it) | T19 | yes | S |
| Keep the security test suite and the e2e bypass cases as release gates (already enforced) | T9,T10,T11,T16,T20 | partial | S |
