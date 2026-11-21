# Security test fixtures

Small documents used by `50-dataplane.sh` (SEC-DP-125, ADR-0021) to check that DLP reads
inside containers. Each one holds the public test card number 4111 1111 1111 1111 only:

- `card.docx`: a Word document, the number split across two text runs;
- `card.pdf`: a PDF whose compressed page content draws the number as a TJ array;
- `card-nested.zip`: a ZIP inside a ZIP.
