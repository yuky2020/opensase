# Data Loss Prevention (DLP)

## Purpose
OpenSASE Data Loss Prevention (DLP) is a shared content inspection engine that detects, classifies, and controls sensitive data in transit and at rest. It provides deep payload inspection for inline HTTP/HTTPS flows intercepted by the Edge SWG and out-of-band SaaS assets monitored by CASB API. The engine evaluates pattern matching, dictionary lookups, algorithmic validators, and compound document text extraction against Policy Rules to prevent unauthorized data exposure.

## Current implementation

The first slice is in place (ADR-0019). It scans request bodies on the Edge's inspected path
(ADR-0018).
- **Detectors** (`pkg/dlp`): `credit-card` (Luhn), `iban` (mod-97), `private-key`,
  `it-tax-code` (check character), `email`, plus tenant RE2 patterns.
- **Policy:** `web.dlp` rules with domains, a match threshold and `block` or `allow` (record only).
  `blockUnscanned` also blocks bodies larger than 8 MiB or with a Content-Encoding.
- **Privacy:** only match counts are computed, and records hold the rule, never the data.

Not built yet: document and archive parsing, downloads, exact data match, OCR, API-mode DLP.

## Responsibilities
- Evaluate extracted plain text and file metadata from HTTP request/response payloads (POST/PUT uploads, file downloads) and SaaS storage objects against DLP Policy Rules.
- Parse multipart/form-data and chunked transfer encodings in streaming HTTP sessions to isolate discrete file attachments and form parameters.
- Perform high-speed regular expression matching and keyword dictionary scanning with tokenization, proximity thresholds, and match counting.
- Execute checksum and algorithmic validation for structured identifiers, including credit card numbers (Luhn algorithm), international bank account numbers (IBAN), and Italian personal tax codes (codice fiscale).
- Extract plain text, embedded objects, and metadata from archive formats and compound documents (ZIP, TAR, GZ, Microsoft Office OpenXML, PDF) within bounded size and recursion limits.
- Enforce configured Rule actions across data-plane and control-plane flows: allow, block, alert, and quarantine (CASB API).
- Generate structured DLP incident records containing match metadata, masked snippets, tenant ID, and user identity for the Observability pipeline.
- Maintain an incident remediation workflow in the Control Plane with status tracking, reviewer assignment, and false-positive flagging.
- Enforce strict inspection latency budgets and file size limits to prevent denial-of-service and latency degradation in the Edge data plane.
- Coordinate with SWG to deliver real-time user notification pages when file uploads or data posts are blocked due to policy violations.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| SWG (Edge) | In-process Go API / ICAP | Inbound to DLP | Submit decrypted HTTP payloads and file streams for inline inspection |
| CASB API (Control Plane) | In-process Go API / gRPC | Inbound to DLP | Submit SaaS files and documents for asynchronous content scanning |
| Control Plane (Policy Compiler) | gRPC / Policy Snapshot | Inbound to DLP | Receive compiled DLP rulesets, dictionary hashes, and regex definitions |
| Observability (OTel Collector) | OTLP (gRPC) | Outbound from DLP | Export DLP violation alerts, structured incident payloads, and inspection metrics |
| S3-compatible Object Storage | HTTPS | Outbound from DLP | Store quarantined files or forensic evidence blobs with client-side encryption |
| Admin Portal (via Public API) | HTTPS / REST | Inbound via API | Query incident queues, triage matches, and update remediation workflow state |

## Key design decisions
- **Proposed:** Embedded Go inspection library executed in-process within Edge for SWG inline flows, compiled natively with Hyperscan/Vectorscan C bindings for high-throughput regex matching.
  *Alternative:* Out-of-process ICAP daemon cluster, which isolates memory faults but incurs cross-process serialization overhead and additional network hops.
- **Proposed:** Deterministic extraction engine using pure Go parsers for ZIP, PDF, and OpenXML with bounded streaming buffers and hard CPU timeout limits per flow.
  *Alternative:* Apache Tika over HTTP/RPC, which supports more file formats but introduces high JVM memory footprints and latency jitter.
- **Proposed:** Incident evidence handling stores salted cryptographic hashes and masked snippets (e.g., last 4 digits of credit card) by default, requiring explicit tenant admin role for masked retrieval.
  *Alternative:* Full raw payload capture stored in tenant object storage, which increases compliance liabilities (GDPR/PCI-DSS) and storage costs.
- **Proposed:** Fail-closed vs fail-open operational mode configurable per Rule or per Tenant when payloads exceed inspection size thresholds or latency budgets.
  *Alternative:* Global static fail-open on timeout or size exceedance, which risks intentional evasion via padding.
- **Proposed:** Windowed streaming inspection for large file uploads where regex evaluation begins on initial byte buffers without waiting for complete transmission.
  *Alternative:* Full-payload spooling to disk before initiating inspection, which causes substantial upload latency and high local storage IOPS.

## Security considerations
- Archive bomb mitigation: enforce strict recursion depth caps (e.g., maximum 3 nested archives), maximum decompressed ratio (e.g., 20x), and hard decompressed byte limits (e.g., 32 MB).
- Masking sensitive match strings in logs and memory; prevent unencrypted storage of cleartext PII/PCI data in telemetry or incident databases.
- Protection against parser vulnerabilities in untrusted binary documents (PDF, Office) through memory-safe parsers and isolated worker routines.
- Strict tenant isolation ensuring dictionary structures, exact match tables, and incident states are partitioned by tenant ID to prevent cross-tenant data leakage.
- Protection against regex denial-of-service (ReDoS) by pre-compiling and analyzing rule expressions for catastrophic backtracking before deploying Policy Snapshots.
- Cryptographic verification of DLP engine configuration signatures during distribution via Policy Snapshots.

## Failure modes & HA
- **Inspection timeout:** When content evaluation exceeds the configured latency budget (e.g., 50ms for streaming, 500ms for files), the engine triggers the configured fallback policy (block or bypass with alert).
- **Edge crash recovery:** In-process DLP runs statelessly; worker crashes terminate the underlying flow safely without leaking uninspected traffic.
- **Out-of-band CASB queue backlog:** CASB API scanning uses durable task queues (e.g., NATS JetStream); worker failures or load spikes result in delayed scanning rather than dropped inspection tasks.
- **High memory pressure:** When Edge buffers exceed allocated memory thresholds, large file inspection dynamically drops to header-only validation or bypass with high-priority telemetry alerts.
- **Partial stream truncation:** Network disconnections during multi-part uploads result in immediate discard of partial inspection states without generating false incident records.
- **Corrupt rule compilation:** If a newly compiled Policy Snapshot contains unparseable regexes or invalid validator parameters, the node rejects the snapshot and retains the last-known good snapshot.

## MVP scope vs later
### MVP
- Regex matching engine with keyword dictionary support and token count thresholds.
- Algorithmic checksum validators: Credit Card (Luhn), IBAN, Italian codice fiscale.
- File extraction for standard formats: ZIP archives, unencrypted PDF, Microsoft Office OpenXML (DOCX, XLSX, PPTX).
- Actions: allow, block, alert for SWG inline; alert for CASB API.
- Strict size limits (10 MB stream buffer) and inspection timeout budget.
- Incident generation with masked snippets sent to ClickHouse via OpenTelemetry.
- Basic incident listing and status update workflow in Control Plane.

### Later
- Exact Data Match (EDM) using cryptographic hashes of structured database extracts.
- Optical Character Recognition (OCR) for scanned documents and image files (PNG, JPEG, TIFF).
- Automated quarantine workflows with user justification and manager override in CASB API.
- Support for encrypted archive handling with credential prompts or enterprise key escrow.
- Machine learning classifiers for unstructured document categorization (source code, financial statements).
- Fingerprinting of proprietary design documents and sensitive intellectual property blueprints.

## Open questions
- Should inline SWG inspection support standard ICAP protocol to permit integration with legacy DLP appliances alongside the native engine?
- What is the acceptable false-positive trade-off for short regex tokens in streaming multi-part HTTP uploads?
- Can pure-Go PDF parsing handle malformed or incremental update streams without resorting to external C/C++ libraries like Poppler?
- How should file quarantine in CASB API handle collaborative files with simultaneous active multi-user editors?

## Effort drivers
- Implementing resilient, memory-bounded file format parsers that resist zip bombs, malformed PDFs, and parser exploits without crashing.
- Achieving low-latency multi-pattern regex matching at multi-gigabit line rates without stalling interactive SWG web sessions.
- Accurately tokenizing and validating international PII formats without generating excessive false positives across disparate document encodings.
- Managing secure storage, encryption keys, and role-based access for forensic incident evidence across multi-tenant deployments.
- Handling streaming multipart MIME decoding and boundary extraction at wire speed without accumulating unbounded memory buffers.
