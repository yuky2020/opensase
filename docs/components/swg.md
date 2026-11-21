# Secure Web Gateway (SWG)

## Purpose
The Secure Web Gateway (SWG) inspects, filters, and secures outbound internet traffic originating from enterprise users and cloud workloads. Operating inside the Edge, it supports both explicit forward proxying via PAC files and transparent proxying for tunneled flows from Client and Workload Gateways. It enforces acceptable use policies, protects against web-based malware, decrypts TLS traffic using tenant-specific intermediate certificates, and applies selective inspection bypasses for privacy-sensitive and certificate-pinned applications. It delivers deep application visibility, content filtering, and protocol sanitization across HTTP, HTTP/2, and HTTP/3.

## Current implementation

Two slices are in place.

- **Hostname control without decryption (ADR-0017).**
  - The Edge reads the hostname of every allowed TCP flow from the TLS SNI or the HTTP Host.
  - It re-applies the DNS policy, the SaaS lists and the firewall domain rules to that hostname,
    so names reached without the Edge resolver are still enforced.
  - Blocks are recorded with layer `web`.
- **Opt-in TLS inspection (ADR-0018).**
  - A tenant turns on `web.inspect`; its devices trust the tenant's inspection root.
  - The Edge terminates TLS with leaves from a 7-day per-Edge intermediate and proxies HTTP/1.1.
  - Per request it applies URL rules (host, normalized path prefix, method) and sets request
    headers, for example to restrict a SaaS login to the company's own account.
  - Bypassed domains are spliced untouched. QUIC and IPv6 web traffic of inspected devices are
    refused, so browsers use the inspected path.
  - The upstream certificate is verified, and the Edge fails closed without an intermediate.

- **Malware scanning (ADR-0020)** of uploads and file downloads with ClamAV, and **DLP on
  uploads (ADR-0019)**.

Not built yet: URL categories beyond the DNS blocklists, DLP on downloads, SafeSearch,
HTTP/2 on the inspected path, PAC and explicit proxy mode.

## Responsibilities
- Terminate and process outbound web sessions via explicit HTTP/HTTPS proxying (CONNECT method, PAC script distribution) and transparent proxy redirection.
- Intercept and inspect TLS connections using tenant-specific intermediate CAs, dynamically synthesizing server certificates on the fly.
- Enforce automated TLS bypass lists for privacy-regulated domains (financial, healthcare), client-certificate authenticated sites, and pinned mobile/desktop apps.
- Categorize domains and URLs against localized open-source databases (e.g., UT1 Toulouse) and pluggable commercial threat intelligence feeds.
- Block QUIC (UDP 443) traffic to force endpoints to fall back to HTTP/1.1 or HTTP/2 over TCP for full TLS inspection.
- Integrate with anti-malware engines (ClamAV, external ICAP servers) to inspect outbound uploads and inbound web downloads for malicious payloads.
- Enforce web hygiene controls including search engine SafeSearch enforcement, MIME/file type blocking, HTTP header sanitization, and per-tenant/per-user bandwidth shaping.
- Serve dynamic Proxy Auto-Configuration (PAC) scripts tailored to client location, identity, and steering rules.
- Validate upstream TLS certificates against public trust roots, inspecting expiration, revocation status (CRL/OCSP), and cryptographic parameters.
- Provide real-time protocol conversion and stream handling across HTTP/1.1 and HTTP/2 client-server sessions.
- Enforce tenant-level and user-level bandwidth rate limiting using token bucket traffic shaping.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Client | TCP / WireGuard / MASQUE | Inbound | Ingest tunneled web flows for transparent proxying or serve explicit PAC file requests |
| Workload Gateway | TCP / WireGuard / GENEVE | Inbound | Ingest workload egress web flows for transparent corporate security inspection |
| Client Endpoint Applications | HTTP / HTTPS (TLS) | Inbound | Terminate forward proxy requests, negotiate TLS, and intercept HTTP requests/responses |
| Target Internet Web Servers | HTTP / HTTPS (TLS) | Outbound | Forward sanitized and inspected requests to destination web servers and receive responses |
| Policy Engine (in-process) | Go function call | Inbound / Outbound | Query active Policy Snapshot for URL category matching, bypass rules, and action decisions |
| ICAP Server / ClamAV Daemon | ICAP (RFC 3507) / TCP | Outbound | Offload HTTP request/response payloads for asynchronous virus and malware scanning |
| Telemetry Collector | gRPC / OTel | Outbound | Stream web transaction logs, blocked domains, TLS inspection metrics, and security events |
| Threat Intelligence Feed | HTTPS / REST / Flat files | Inbound | Ingest updated domain categorization databases, malware signatures, and reputation lists |

## Key design decisions
- **Proxy core architecture**: Proposed: Custom Go forward proxy utilizing an optimized HTTP/1.1 and HTTP/2 pipeline with connection pooling and dynamic certificate generation. Alternative: Integrating Envoy proxy as a sidecar process using `ext_authz` and Lua/Wasm filters.
- **TLS inspection architecture**: Proposed: Dynamic on-the-fly leaf certificate generation signed by the tenant intermediate CA, backed by an LRU certificate cache. Alternative: Upstream TLS termination with out-of-band passive mirror decryption.
- **QUIC / HTTP/3 mitigation**: Proposed: Dropping or rejecting UDP port 443 traffic to force browser fallback to standard TCP-based TLS inspection. Alternative: Implementing a full user-space QUIC MITM proxy terminating and re-originating QUIC connections.
- **Malware scanning integration**: Proposed: Standard ICAP (RFC 3507) client communicating with co-located ClamAV daemons or external enterprise antivirus engines. Alternative: Embedding an antivirus scanning library (libclamav) directly into the proxy memory space.
- **URL categorization data storage**: Proposed: In-memory compact trie structure populated from local flat database files (UT1 Toulouse) with async periodic reloading. Alternative: External key-value store (Redis) queried over the network per HTTP request.
- **Bandwidth throttling implementation**: Proposed: Token bucket traffic shaping implemented directly on TCP socket read/write loops per active session. Alternative: Operating system kernel traffic control (tc / eBPF) queues applied per interface.

## Security considerations
- Strict protection and memory-only storage of tenant intermediate CA private keys within the Edge process.
- Rigorous validation of upstream server certificates (expiration, revocation via CRL/OCSP, trust chain) prior to synthesizing downstream certificates to prevent MITM vulnerabilities.
- Guaranteed bypass without decryption for sensitive categories (health, banking) to adhere to privacy regulations (HIPAA, GDPR).
- Prevention of proxy loop vulnerabilities and request smuggling across HTTP/1.1 and HTTP/2 protocol boundaries.
- Resource constraints on payload buffering to prevent denial-of-service through memory exhaustion during large file scans.
- Sanitization of sensitive user headers (e.g., stripping internal authentication tokens) before egressing to external web servers.
- Safe handling of decompressed archive bombs during inline payload and file type verification.

## Failure modes & HA
- **ICAP / Antivirus scanner unavailability**: Configurable fail-open or fail-close policy mode per tenant; fail-open logs security warnings while preserving business continuity.
- **Upstream destination TLS failure**: Proxy terminates downstream connection with a standardized descriptive HTTP 502/504 error page explaining the trust or connectivity issue.
- **Local URL cache miss or lookup failure**: Query falls back to secondary memory cache or default uncategorized domain policy with asynchronous background re-resolution.
- **Edge worker crash or saturation**: Redundant Edges in the PoP take over client connections via Anycast BGP or client tunnel failover.
- **Tenant CA expiration or revocation**: Edge immediately refuses dynamic certificate synthesis, logs critical errors, and blocks inspected sessions until refreshed.
- **Downstream client certificate pinning failure**: Automatic detection of repeated TLS handshake aborts with telemetry alerts to suggest addition to tenant bypass list.

## MVP scope vs later
### MVP
- Transparent and explicit forward HTTP/HTTPS proxying supporting HTTP/1.1 and HTTP/2.
- TLS MITM inspection with tenant intermediate CA and static domain bypass lists.
- URL categorization using local offline database (UT1 Toulouse) with exact and wildcard domain matching.
- QUIC/UDP 443 blocking to enforce TCP fallback.
- ClamAV integration over ICAP for inbound payload scanning.
- SafeSearch enforcement for Google, Bing, and YouTube, alongside basic MIME type blocking.
- PAC file generation and delivery for explicit browser steering.

### Later
- Dynamic commercial threat feed integration with cloud-assisted real-time URL reputation lookups.
- Full HTTP/3 (QUIC) transparent inspection proxying without forcing TCP fallback.
- Advanced streaming file inspection with archive recursion (ZIP, TAR, 7z) and sandboxing hooks.
- Granular per-user, per-group bandwidth throttling and QoS queuing.
- Comprehensive PAC file management portal with dynamic geo-routing logic.
- Client-certificate passthrough authentication for mutual TLS authenticated upstream web services.
- Real-time optical character recognition (OCR) and document preview extraction for inline DLP integration.

## Open questions
- Memory and CPU overhead of Go runtime garbage collection under sustained high-throughput TLS inspection per Edge.
- How to efficiently maintain and update large-scale URL categorization databases on edge nodes without causing latency spikes or memory bloat.
- Legal and technical trade-offs of providing default pre-packaged bypass lists for certificate-pinned mobile and desktop applications.
- Optimal strategy for streaming large file downloads through ICAP without triggering client browser download timeouts.
- Approach for handling custom corporate internal CAs when accessing internal web servers via transparent proxying.
- Scalability of on-the-fly certificate generation during sudden traffic surges from thousands of newly connecting endpoints.

## Effort drivers
- Tuning high-concurrency TLS handshakes, certificate caching, and crypto performance in Go to minimize latency overhead.
- Handling edge cases in HTTP/1.1, HTTP/2, and WebSockets (pipelining, chunked transfer, connection upgrades, request smuggling).
- Maintaining reliable, up-to-date URL categorization datasets and high-speed prefix/trie lookups under high request volume.
- Reliable ICAP streaming protocol implementation that handles backpressure, timeouts, and partial file delivery gracefully.
- Preventing false positives on TLS inspection bypass for applications employing proprietary certificate pinning.
- Mitigating memory fragmentation and GC pauses caused by continuous dynamic certificate generation and payload buffering.
