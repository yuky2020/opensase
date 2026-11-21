# ADR-0026: PDF structure for DLP: CID fonts and images

Status: accepted (2026-11-21)

## Context

The first PDF extraction (ADR-0021) inflated streams and kept literal strings. Two common kinds
of PDF escaped it:
- **Generated documents with Type0/CID fonts** (issue #13), as many office suites and report
  engines produce. Their strings are glyph codes, often in hex, so the text is only readable
  through the font's `ToUnicode` CMap. In modern files the font dictionaries usually sit in
  compressed **object streams** (PDF 1.5+).
- **Scanned documents** (issue #12): pages that are images, which need OCR (ADR-0024).

## Decision

`pkg/dlp` reads the PDF structure, within fixed bounds:

- **Objects.**
  - `N G obj … endobj` objects are indexed, at most 100,000.
  - Object streams (`/Type /ObjStm`) are decompressed and their objects added, from the `N` and
    `First` header.
  - FlateDecode streams are inflated with the existing 4 MiB per-stream bound.
  - PNG row predictors (`/Predictor` ≥ 10, common on object and image streams) are undone.
- **Fonts.**
  - `/Font` resource dictionaries, inline or referenced, give font names → font objects.
  - A font's `/ToUnicode` stream is parsed as a CMap: the code length from
    `begincodespacerange`, then `bfchar` and `bfrange`, including the array form.
  - At most 65,536 entries per CMap.
- **Content streams.** A small interpreter follows the text operators:
  - `Tf` selects the font;
  - `Tj`, `TJ`, `'` and `"` show strings;
  - literal and hex strings are decoded through the current font's CMap when it has one, as
    bytes otherwise;
  - the strings of one `TJ` array are joined, which reassembles kerned or positioned words.
- **Images.** With an OCR service configured, image XObjects go to OCR (ADR-0024):
  - DCTDecode images as the JPEG they are;
  - FlateDecode 8-bit DeviceGray or DeviceRGB pixels re-encoded as PNG.

  Images over 20,000 pixels a side, over 25 million pixels, or in other formats (JPX, CCITT,
  indexed colour) cannot be handed over. They mark the extraction incomplete, so
  `blockUnscanned` applies.
- **Fallback.** A file that does not parse as objects falls back to the stream scan of
  ADR-0021.

## Consequences

- Text extraction covers the PDFs of common office suites and generators, including fonts in
  object streams. Fonts without a `ToUnicode` CMap, which embed only glyph shapes, still yield
  codes, not text.
- Font names are resolved globally, not per page. Two pages using the same resource name for
  different fonts use the first font found, which can garble the other page's text.
- Every image of a scanned PDF counts towards the 20 images per extraction (ADR-0024). Longer
  scans are incomplete and fall under `blockUnscanned`.
- Checks:
  - `pkg/dlp` tests: CID text with and without an object stream, unmapped codes not read as
    text, JPEG and Flate images to OCR, oversized images, PNG predictors;
  - `FuzzPDF`;
  - real PDFs from the system documentation, extracted in milliseconds;
  - fixtures `card-cid.pdf` and `card-scan.pdf` in the e2e, SEC-DP-125 and SEC-DP-129.
