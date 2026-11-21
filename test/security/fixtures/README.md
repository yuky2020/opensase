# Security test fixtures

Small documents used by `50-dataplane.sh` (SEC-DP-125 and SEC-DP-129, ADR-0021 and ADR-0024) to check that DLP reads
inside containers. Each one holds the public test card number 4111 1111 1111 1111 only:

- `card.docx`: a Word document, the number split across two text runs;
- `card.pdf`: a PDF whose compressed page content draws the number as a TJ array;
- `card-nested.zip`: a ZIP inside a ZIP;
- `card.doc`: a legacy Compound File (OLE2) document, the number stored as UTF-16LE
  (regenerate with `OPENSASE_WRITE_FIXTURES=$PWD/test/security/fixtures go test -run TestWriteLegacyFixture ./pkg/dlp`);
- `card.png`: the number drawn as an image, for OCR (ADR-0024);
- `card-cid.pdf`: the number drawn with a CID font through its ToUnicode CMap, the font
  dictionary in a compressed object stream (issue #13);
- `card-scan.pdf`: a "scanned" page, `card.png` as a JPEG image XObject, for OCR (issue #12).
  Regenerate both with `OPENSASE_WRITE_FIXTURES=$PWD/test/security/fixtures go test -run TestWritePDFFixtures ./pkg/dlp`.
