# ADR-0024: DLP on legacy Office, RTF and images (OCR)

Status: accepted (2026-11-21)

## Context

ADR-0021 reads modern Office files, PDF and archives. Three common carriers of sensitive data
were still blind spots:
- **legacy Office files** (`.doc`, `.xls`, `.ppt`, and Outlook `.msg`), which are Compound File
  Binary (OLE2) containers with text often stored as UTF-16LE;
- **RTF** documents;
- **images**: scans, photos of documents, screenshots.

## Decision

### Legacy Office: read the streams, not the formats

`pkg/dlp` parses the Compound File Binary format:
- the header;
- the DIFAT and FAT;
- the directory;
- the mini stream and the mini FAT.

It then reads every stream. Each format (Word piece tables, Excel BIFF records, PowerPoint
atoms) stores text differently. Rather than interpreting them, the extractor keeps the runs of
printable text, at least 4 characters long, in three readings:
- 8-bit;
- UTF-16LE at offset 0;
- UTF-16LE at offset 1.

That finds identifiers in Word, Excel and PowerPoint files and in Outlook messages. It was
checked against the Apache POI sample files, which were not committed.

Robustness:
- sector chains are followed with a visited set, so a FAT loop is detected, not followed until
  a size limit;
- every sector index and offset is range-checked;
- FAT, DIFAT and mini FAT sizes are capped;
- the extraction budget of ADR-0021 bounds the output;
- a damaged container is reported incomplete, so `blockUnscanned` applies;
- the parser is fuzzed (`FuzzOLE2`).

### RTF and UTF-16 text

- RTF documents are reduced to their text: control words and groups are dropped, `\'hh`
  escapes are decoded, and `\par`, `\line`, `\tab` and `\cell` become spaces.
- Text with a UTF-16LE byte order mark is decoded.

### Images: an OCR service

- Images (PNG, JPEG, GIF, TIFF, BMP, WebP) go to **`ocrd`**, a small HTTP service in this
  repository (`cmd/ocrd`). Its `POST /v1/ocr` returns the image's text, read by Tesseract 5
  (English and Italian). The Edge gets the service with `-ocr URL` (`EDGE_OCR` in the dev
  compose).
- Images are found wherever extraction reaches them: uploads, downloads, and inside ZIP
  archives and Office documents (embedded pictures).
- **Isolation.** Image decoders are a classic attack surface, so OCR does not run in the Edge:
  - ocrd runs in its own container: read-only root filesystem, no capabilities,
    `no-new-privileges`, an unprivileged user, 1 GiB of memory, 64 processes;
  - it is reachable on the internal network only;
  - it accepts only content with an image signature, up to 10 MiB, with 2 concurrent jobs and
    30 seconds per job;
  - it stores nothing.
- **Bounds on the Edge:** at most 20 images per extraction and 35 seconds per call.
- **Failure:**
  - without an OCR service, images are treated as carrying no text, so profile pictures and
    the like are not counted as unscanned;
  - with one configured, an OCR error or timeout marks the content incomplete, so
    `blockUnscanned` blocks it.

## Consequences

- OCR is slow, about a second per page-sized image. It only runs for content that a DLP rule
  applies to.
- OCR quality is Tesseract's. Clean printed text is read well. Handwriting, low resolution and
  heavy noise are not.
- Images embedded in PDF files were not extracted by this slice; ADR-0026 adds them.
- The OLE2 approach reads text runs, not document structure. Text split across Word's piece
  table fragments can be split in the output. Card numbers still match because of the
  group-tolerant detector, but a pattern spanning a fragment boundary may not.
- Checks:
  - unit tests and fuzzing in `pkg/dlp`;
  - `cmd/ocrd` tests;
  - Edge tests (images with and without OCR, an image in a ZIP, an OCR outage, RTF);
  - the e2e and SEC-DP-125/129 with `test/security/fixtures/card.doc` and `card.png`.
