# ADR-0035: Device posture

Status: accepted (2026-11-26)

## Context

Decision #42 (issue #69) asks for basic device posture in v1.0:

- signals: OS name and version, client version, disk encryption, screen lock, firewall
  (Windows), managed device, last boot;
- minimum OS and client versions at enrolment;
- a restricted policy for failing devices;
- a `posture` condition in rules and private apps;
- the portal shows the last posture, and the app shows what to fix.

## Decision

### Signals and trust

- The client core collects `api.Posture` through the platform bridge, using only APIs that
  need no extra permission. A signal the platform cannot report is left unset (`null`).
- The client sends it with `POST /v1/posture` over its mutual TLS channel: at connect, then
  every 15 minutes and whenever a signal changes.
- The report is bound to the device key by the TLS channel. It is advisory evidence, not
  attestation: a modified client can report anything. Hardware attestation is a 1.x item.

### Checks

The tenant policy has a `posture` section (`api.PosturePolicy`). A device fails a check
when:

- its OS version is below `minOsVersion[os]`, or its client version is below
  `minClientVersion`; versions compare as dotted numbers;
- a check in `require` (`diskEncryption`, `screenLock`, `firewall` on Windows only,
  `managed`) is false or unknown.

A device without any report is treated as failing every required check, except that
enrolled devices get 10 minutes after enrolment before restriction applies, so that the
first report can arrive.

### Enforcement

All enforcement goes through the device's signed snapshot, which both the client and the
Edge already enforce. No new enforcement point is added.

- **At enrolment:** `POST /v1/enroll` with a posture below the minimum OS or client
  version is refused with 403, naming the minimum.
- **Restricted snapshot:** with `posture.restrict`, a failing device gets a snapshot whose
  firewall:
  - blocks by default;
  - allows DNS, the Control Plane and `remediationDomains`;
  - carries no private apps.
  `Snapshot.PostureFailing` lists the failed checks so the app can show them.
- **Rules and private apps:** `posture: compliant | noncompliant` keeps a tenant rule, or
  a private app, only in the snapshots of matching devices. It is resolved at compile time,
  like `users` and `groups`, and cleared in the snapshot.
- When a report changes the result, the Control Plane issues a new snapshot and wakes the
  device's long poll.

### Visibility

- The portal shows each device's last posture and failing checks
  (`GET /v1/admin/tenants/{t}/devices/{d}/posture`).
- The app shows `PostureFailing` with a short hint for each check.

## Consequences

- Posture can raise the bar for honest devices and show users what to fix. It does not stop
  an attacker who controls the client; the threat model records this.
- Enforcement stays where it already is (the signed snapshot), so the Edge needs no change.
- Checks:
  - unit tests for version comparison and the check evaluation;
  - Control Plane tests for enrolment refusal, the restricted snapshot, the rule and private
    app filters, and the grace period;
  - client tests for the report loop.
