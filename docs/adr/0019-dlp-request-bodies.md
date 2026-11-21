# ADR-0019: Data loss prevention on the inspected path (first slice)

Status: accepted (2026-11-21)

## Context

`docs/components/dlp.md` describes full DLP:
- content inspection of uploads and downloads;
- document formats (Office, PDF, archives);
- exact data match and fingerprints;
- OCR;
- endpoint and API-mode coverage.

TLS inspection (ADR-0018) now gives the Edge the decrypted request of every inspected
connection. The first useful step is to stop well-known sensitive data from leaving in uploads,
with few false positives, and to record what happened without copying the data anywhere.

## Decision

### Detectors (`pkg/dlp`)

| Detector | What it matches | Validation |
|---|---|---|
| `credit-card` | 13–19 digits, optionally grouped by single spaces or dashes | Luhn checksum, known issuer prefix and length, not all the same digit |
| `iban` | an IBAN, compact or printed in groups of four | ISO 7064 mod-97, and the country's length for common countries |
| `private-key` | a PEM `-----BEGIN … PRIVATE KEY-----` block | — |
| `it-tax-code` | Italian codice fiscale | check character |
| `email` | e-mail addresses | meant for bulk thresholds (`minMatches`) |

Tenants can add **patterns**: up to 20 RE2 regular expressions per rule, matched
case-insensitively. RE2 runs in linear time, so a pattern cannot be used to slow the Edge down.
Patterns that match the empty string are refused.

A `Matcher` returns only the number of matches per detector, never the matched bytes. So no code
path can put the data into logs or flow records.

### Policy: `web.dlp`

```json
"dlp": [
  {"id": "pci", "detectors": ["credit-card", "iban"], "action": "block", "blockUnscanned": true},
  {"id": "bulk-mail", "domains": ["*.share.example"], "detectors": ["email"], "minMatches": 50, "action": "allow"},
  {"id": "codenames", "patterns": ["project\\s+falcon"], "action": "block"}
]
```

- `domains` empty means every host on the inspected path.
- `minMatches` sets how many matches, across the rule's detectors and patterns, trigger it
  (default 1).
- `action` is `block` (the request gets a 403 page) or `allow` (the request goes through and is
  recorded).
- Rules run in order after the URL rules allowed the request. The first blocking match stops.
  Every `allow` match is recorded.
- `policy.Compile` validates the section: IDs, actions, known detectors and valid patterns.

### Scanning

DLP runs in the Edge's inspection proxy (ADR-0018): on decrypted HTTPS of inspecting tenants,
and on plain HTTP when the tenant has web rules. For each request with a body:

- The Edge reads the body up to **8 MiB** and scans it. The scanned bytes and the rest of the
  body are then forwarded unchanged.
- `application/x-www-form-urlencoded` bodies are URL-decoded before scanning. Otherwise
  `4111+1111+…` would hide a card number. JSON, plain text and multipart bodies are scanned as
  sent; text files inside a multipart upload are scanned as they are.
- Chunked bodies are scanned after de-chunking, like any other body.
- **Unscannable bodies** are bodies longer than the limit, or with a `Content-Encoding` (gzip,
  br…). A rule with `blockUnscanned` treats them as a match, recorded as
  `dlp:<id>:unscanned`. Otherwise they pass that rule unscanned. A tenant that cares about
  exfiltration sets `blockUnscanned` on its blocking rules. A tenant that cannot afford to
  block large uploads accepts the gap knowingly.
- Records have layer `web`, rule `dlp:<id>` and action `block` or `allow`. They hold the host and
  device, never the content or the match.

## Consequences

- Only request bodies are scanned: uploads, form posts and API calls. ADR-0021 adds downloads,
  text extraction from documents and archives, and decoding of compressed bodies.
- Formats are not parsed: text inside PDF, Office or ZIP files is not seen, so their compressed
  content passes unscanned. With `blockUnscanned` only a `Content-Encoding` counts as
  unscannable, not a compressed file format; document parsing is the next step.
- Base64 or other re-encodings chosen by the client hide the data from the built-in detectors.
  DLP stops accidental and casual leaks, not a determined insider. The same holds for any
  network DLP.
- The 8 MiB buffer is per request. With the listener's limit of 4096 connections the worst case
  is bounded but large; the limit is a constant for now.
- Not covered yet:
  - malware scanning (ICAP or a scanning engine);
  - exact data match and fingerprints;
  - OCR;
  - DLP on downloads;
  - per-user incident workflow in the portal (blocks are visible in the activity view).
