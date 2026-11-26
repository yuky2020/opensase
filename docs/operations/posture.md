# Device posture

Tenant policies can inspect device posture signals to enforce baseline security standards, restrict non-compliant endpoints, and scope network access (ADR-0035).

```json
"posture": {
  "minOsVersion": {
    "android": "14.0",
    "windows": "10.0.19045",
    "linux": "6.1",
    "macos": "14.0",
    "ios": "17.0"
  },
  "minClientVersion": "1.0.0",
  "require": [
    "diskEncryption",
    "screenLock",
    "firewall",
    "managed"
  ],
  "restrict": true,
  "remediationDomains": [
    "remediation.example.com"
  ]
}
```

## Signals collected

The client core queries platform interfaces to gather advisory health signals without requiring elevated privileges:

- **Operating system and version (`os`, `osVersion`)**: The platform name and release version.
- **Client version (`clientVersion`)**: The installed software version.
- **Disk encryption (`diskEncryption`)**: Whether full disk encryption is active on the system volume.
- **Screen lock (`screenLock`)**: Whether a device PIN, password, or biometric lock screen is configured.
- **Host firewall (`firewall`)**: Whether the operating system host firewall is active (evaluated on Windows only).
- **Device management (`managed`)**: Whether the device is enrolled in enterprise or mobile device management.
- **Boot time (`bootTime`)**: System boot timestamp.

The client sends these signals to `POST /v1/posture` over its mutual TLS session at connection time, every 15 minutes thereafter, and whenever a local signal changes. Signals that cannot be determined on a platform are reported as `null`.

## Checks

The Control Plane compares incoming reports against the tenant's `posture` policy:

1. **Operating system version (`minOsVersion`)**: Fails if the platform appears in `minOsVersion` and the reported version is lower than the minimum according to dotted numeric comparison.
2. **Client software version (`minClientVersion`)**: Fails if `minClientVersion` is configured and the reported client version is lower.
3. **Required signals (`require`)**: Any check listed in `require` (`diskEncryption`, `screenLock`, `firewall`, `managed`) fails if the corresponding signal is false or `null`. The `firewall` requirement applies only to Windows platforms.

Failed check names are tracked in deterministic order: `osVersion`, `clientVersion`, `diskEncryption`, `screenLock`, `firewall`, `managed`.

### Enrolment enforcement

When a client provides posture signals during enrolment (`POST /v1/enroll`), the Control Plane verifies the versions against `minOsVersion` and `minClientVersion`. Enrolment is refused with status `403 Forbidden` if either version is below the mandated minimum:

- `"posture: OS version below the minimum <v>"`
- `"posture: client version below the minimum <v>"`

If enrolment is refused due to posture, the provisioning key is not consumed and may be used once the device is upgraded. Older clients that omit posture during enrolment proceed normally.

## Grace period

Newly enrolled devices are granted a 10-minute grace period from the moment of device creation before the absence of a posture report triggers non-compliance.

During this window, a device that has not yet submitted a posture report is treated as compliant, ensuring that initial network connectivity is established so the client can submit its initial report. If 10 minutes elapse without a report arriving, the device is evaluated as failing every required check.

## Restricted snapshot

When `posture.restrict` is set to `true`, devices failing one or more checks receive a restricted policy snapshot rather than the normal tenant rules:

- **Default firewall action**: Evaluates to `block`.
- **Allowed traffic**:
  1. DNS traffic (UDP and TCP port 53) to the tunnel resolver addresses (`100.64.0.1` and `fd7a:5a5e::1`).
  2. TCP port 443 traffic to the Control Plane address, allowing devices to poll and receive policy updates.
  3. Traffic to configured remediation domains (`remediationDomains`), allowing users to reach self-service help desks, update repositories, or device management portals.
- **Private applications**: All private application routes and entitlements are removed.
- **Mesh traffic**: All device-to-device mesh grants are removed.
- **Diagnostics**: `Snapshot.PostureFailing` contains the list of failing check names so the client application can inform the user what requires remediation.

When a device submits an updated report that satisfies all checks, the Control Plane recompiles and stores a new snapshot, restoring normal access and waking the device's long poll.

## Posture conditions on rules and private apps

Tenant rules and private applications can specify a `posture` condition:

- `"posture": "compliant"`: Rule or private application is included only in snapshots compiled for compliant devices.
- `"posture": "noncompliant"`: Rule or private application is included only in snapshots compiled for non-compliant devices.

The posture condition is resolved during snapshot compilation and stripped from the issued snapshot, preserving compatibility with client and Edge evaluators.

## Advisory evidence, not hardware attestation

Device posture reports are advisory signals reported by the client application over mutual TLS. The report is authenticated to the device key, but it does not represent cryptographically verifiable hardware attestation (such as TPM or secure enclave cryptographic measurements).

A modified operating system kernel or client binary can report arbitrary posture values. Posture checks serve as operational guardrails to prevent accidental access from misconfigured devices, not as a boundary against determined attackers controlling the client host.
