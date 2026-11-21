# ADR-0021: DLP inside documents and on downloads

Status: accepted (2026-11-21)

## Context

The first DLP slice (ADR-0019) scans upload bodies as they are sent. Sensitive data usually
travels inside files, which that scan cannot read:
- an Office document is a ZIP of XML;
- a PDF keeps its page text in compressed streams;
- an archive may hold other archives;
- `Content-Encoding: gzip` hides everything.

Those bodies were also counted as "unscanned", so `blockUnscanned` had to block every
compressed upload. Data also leaves through downloads: a user pulling a customer export from a
SaaS app.

## Decision

### Text extraction (`pkg/dlp.Extract`, `pkg/dlp.Decode`)

- **Content-Encoding** `gzip`, `x-gzip` and `deflate` (zlib or raw) are decoded before scanning.
  `br` and `zstd` were added later (issue #14), with `github.com/andybalholm/brotli` and
  `github.com/klauspost/compress/zstd` (window capped at 8 MiB). The same 32 MiB output bound
  applies.
- **Containers are recognised by their magic bytes**, not by the declared type:
  - **ZIP** (and so `.docx`, `.xlsx`, `.pptx`, `.odt`, `.jar`): every entry is read. XML parts
    are reduced to their text. Other entries are extracted again if they are containers
    themselves, else scanned as they are.
  - **gzip** files: decompressed and extracted again.
  - **PDF**:
    - FlateDecode streams are inflated;
    - the literal strings of the text operators are kept;
    - strings in one `TJ` array are joined, so `[(4111)-30(1111)…]` reads as one number.
  - **XML**: tags are replaced by spaces, so that adjacent spreadsheet cells do not glue into
    one number. Whitespace is then collapsed.
- **Bounds** keep a small hostile file from expanding without limit:
  - 32 MiB of extracted output per input;
  - three levels of nesting;
  - 1000 ZIP entries, 2000 PDF streams, 4 MiB per inflated PDF stream.

  The declared ZIP sizes are not trusted: every read is bounded by what is left of the budget.
- Hitting a bound marks the extraction incomplete, and so does an encrypted ZIP entry or a
  damaged container. So do containers nested deeper than three levels, which are scanned as
  raw bytes. A rule with `blockUnscanned` blocks incomplete content that did not already match.
- A container is scanned through what was extracted from it, not as raw bytes too, so a match
  is not counted twice towards `minMatches`. For the same reason a multipart body that parses
  is scanned part by part.
- The card detector now finds two numbers separated by a single space: within a run of
  digit groups, consecutive groups of 13–19 digits are tried in turn.

### Downloads

- A DLP rule with `"downloads": true` also applies to file downloads. These are the same
  responses the malware scan holds back (ADR-0020): attachments, and types that are not page
  content or streamed media.
- Uploads are always scanned.
- A blocked download is replaced by a 403 page and recorded as `dlp:<id>`.
- A partial (`206`) response cannot be judged alone. It is unscanned, and so blocked by a
  `blockUnscanned` rule.

## Consequences

- PDF extraction is best effort. Text drawn with custom-encoded fonts (CID fonts, common in
  generated PDFs) shows glyph IDs, not characters, and is missed. Scanned documents need OCR.
  ADR-0024 and ADR-0026 add both.
- Legacy Office formats (`.doc`, `.xls`, OLE2) were not parsed by this slice. Their text is
  often stored as UTF-16. ADR-0024 adds them.
- Download scanning holds file downloads until they are read (up to the larger of the DLP and
  malware limits) and adds the extraction time.
- Not covered by this slice: OCR, OLE2 and RTF (ADR-0024), exact data match and fingerprints,
  archive passwords.
