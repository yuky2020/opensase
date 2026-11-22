# ADR-0028: Tamper-evident admin audit log

Status: accepted (2026-11-22)

## Context

The admin audit log (ADR-0016) lives in the Control Plane database. An attacker with write
access to that database can rewrite it without leaving a trace: remove the entries of their
own actions, alter one, or forge some (issue #18).

## Decision

### Hash chain

Each entry stores the hash of the previous entry and its own hash:

```
hash = SHA-256(prev_hash ‖ id ‖ at ‖ actor ‖ tenant_id ‖ method ‖ path ‖ status)
```

- Every field is length-prefixed and numbers are fixed-width, so different entries cannot
  produce the same input.
- The first entry chains to 32 zero bytes.
- Appends are serialised, by a mutex plus the single-writer SQLite transaction, so the chain
  never forks.
- Entries written before this change are chained in place when the Control Plane starts
  (migration 0008).

### Retention keeps it verifiable

- Retention (365 days) deletes a **prefix** of the chain: the entries up to the newest one older
  than the limit.
- The hash of the last deleted entry is stored as the **anchor** (`audit_anchor`), and the
  oldest remaining entry must chain to it.
- Deleting entries in the middle, or rewriting the anchor, breaks the chain.

### Verification

- `GET /v1/admin/audit/verify` (super-admin only) and `opensasectl audit verify` recompute the
  whole chain. They report the number of entries, the head (newest entry and its hash) and the
  first entry that does not verify, with the reason:
  - a changed entry;
  - an entry removed or inserted before it;
  - an entry older than the anchor.
- The portal's Audit page shows the result to the super-admin, with the head to keep.

### Pinning the history outside the database

A chain only proves consistency. An attacker who controls the database can recompute every
hash after a change. Two mechanisms keep a copy of the head outside:

- The Control Plane logs `audit chain head` (entry and hash) every 10 minutes, so log shipping
  keeps a witness. A broken chain is logged at error level.
- A head written down earlier can be checked later:
  `opensasectl audit verify -id N -hash H`, or `?id=N&hash=H`. It answers match, mismatch,
  missing, or removed by retention. A mismatch means the history up to N was rewritten.

## Consequences

- Detection, not prevention: the database can still be changed, but not silently once a head
  has been published.
- Verification reads the whole log: one year of admin writes, a few thousand rows in practice.
  It runs on demand and every 10 minutes.
- A dedicated append-only sink (object storage with a retention lock, a remote syslog) is still
  possible. The log line with the head is the minimal one, and works with any log pipeline.
- Checks:
  - `TestAuditChain`: changed, removed and forged entries, a rewritten anchor, retention,
    legacy rows;
  - `TestAuditVerify`: pinning and super-admin only;
  - SEC-TEN-028 on the live stack.
