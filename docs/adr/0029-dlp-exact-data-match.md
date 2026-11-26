# ADR-0029: DLP exact data match and document fingerprints

Status: accepted (2026-11-22)

## Context

The detectors of ADR-0019 find kinds of data: card numbers, IBANs, tax codes. A tenant also
needs to protect specific data (issue #15):
- **records**, such as its customer list, account IDs or employee e-mail addresses;
- **documents**, such as a contract draft or the board pack, even when only a paragraph is
  pasted elsewhere.

The data must not be copied into policies or spread to every device.

## Decision

### Datasets, hashed at the Control Plane

`PUT /v1/admin/tenants/{t}/dlp-datasets/{name}` (admin role; `opensasectl dlp-dataset put`)
creates or replaces a dataset of one of two kinds:

- **values**:
  - each value is normalized: lowercase tokens of letters and digits, keeping the inner `. _
    - @ +` of identifiers and addresses;
  - it may have 1 to 4 tokens (`Mario Rossi`, `ACCT-1234`, `mario.rossi@acme.example`);
  - longer values are skipped.
- **document**: files (text, Office, PDF, archives, read as in ADR-0021) are cut into
  **shingles** of 8 consecutive tokens.

The Control Plane:
- draws a random 32-byte key for the dataset;
- stores the **truncated HMAC-SHA-256** (64 bits) of every value or shingle;
- discards the content.

Listing (`GET .../dlp-datasets`) shows names, kinds and entry counts only. Limits: 32 MiB per
upload, 500,000 entries per dataset.

### Matching at the Edge

- A DLP rule names datasets (`web.dlp[].datasets`), possibly with no detector.
- The Edge fetches the datasets of the tenants it serves from `GET /v1/edge/dlp-datasets` (edge
  mTLS; a Private Edge only for its tenant). It refreshes them every 5 minutes, and when the
  names in its devices' policies change.
- On the scanned text (ADR-0019, ADR-0021, ADR-0024), the Edge computes the HMAC:
  - of every sequence of 1 to 4 tokens, for values;
  - of every shingle, for documents.

  Each value found, and each distinct shingle found, counts towards the rule's `minMatches`.
  So `minMatches: 3` on a document dataset means "a few sentences of it".
- Matching is case-, spacing- and punctuation-insensitive, so a record retyped in another
  format still matches.
- A dataset the Edge has not loaded makes the rule incomplete: `blockUnscanned` blocks, and
  otherwise the rule passes.
- Work is bounded to 4 million candidates per scanned text.

## Consequences

- **What protects the data.** The keyed hashes are useless without the key. The key lives on
  the Control Plane and on the Edges of the tenant, never on devices or in snapshots. An
  attacker who obtains a dataset together with its key can still test guesses, so low-entropy
  values (short numbers) are only as safe as the Edges themselves.
- **False positives.** 64-bit hashes make random collisions negligible. Common words are the
  real risk: a value dataset of single common words would match everywhere, so datasets should
  hold distinctive records.
- **Granularity.** Fingerprints catch copied passages of 8 words or more, in any format the
  extractor reads. A rewritten paraphrase is not caught.
- **Not built yet:** portal upload of datasets (the CLI is used); per-column structured EDM
  (for example name and account together in one record).
- Checks:
  - `pkg/dlp` tests and `FuzzTokens`;
  - `TestDLPDatasets`: only hashes stored and sent, tenant scope;
  - `TestInspectionDLPDatasets`: value, document excerpt, unrelated text;
  - SEC-DP-131 on the live stack.

## Update: records datasets (issue #75)

A third kind, `records`, protects rows of structured data such as a customer table:

- The admin uploads rows of fields (`opensasectl dlp-dataset put -kind records -file customers.csv`).
- The Control Plane keeps, under the dataset key, one hash per normalized field and one per
  unordered pair of fields of the same row. Field and pair hashes are domain separated, so
  they share the existing sorted hash list and wire format.
- The Edge collects the fields found in a text (at most 512 distinct ones) and counts the
  pairs that belong to one row. A single common value (a first name, a city) never matches;
  two fields of the same row do.
- Rows with fewer than two usable fields add nothing; fields beyond the 16th are ignored.

DLP rules use the count as for the other kinds.
