# Release quality bar (v1.0)

This document defines the release quality bar for OpenSASE v1.0. It is written for maintainers preparing releases and for users deciding whether a release is production-ready. The quality criteria record the decisions taken in planning issue #37 of the [roadmap map](https://github.com/yuky2020/opensase/issues/36).

!!! note "Production readiness baseline"
    This quality bar defines the stability, security, test, and packaging guarantees for OpenSASE v1.0. Pre-releases in the 0.x series do not yet meet all of these criteria.

## Stable contracts

Starting at 1.0, OpenSASE commits to semantic versioning. Any breaking change to a stable public contract requires a major release (2.0).

Stable public contracts under semantic versioning:

- **Tenant policy**: The tenant policy JSON and its JSON Schema (`docs/schema/tenant-policy.schema.json`).
- **Data-plane and control APIs**: The client, Edge, and Connector APIs under `/v1`.
- **Enrolment format**: The enrolment URI scheme and QR code format.
- **Administrative tooling**: The admin API and the `opensasectl` CLI.

Internal implementation details (may change across any release):

- **Database and state formats**: The database schema and on-disk state files are internal and may change between releases.
- **Automatic migrations**: State and database migrations are forward-only and run automatically at startup.

## Upgrade path

- **In-place upgrade to 1.0**: Upgrades to 1.0 proceed in place from the last 0.x release (0.9) without re-enrolling devices and without losing policy configuration or PKI state.
- **Automated verification in CI**: An automated upgrade test in CI proves this path: install 0.9, enrol a device, upgrade to 1.0, and verify the device keeps working without intervention.
- **Early releases**: There is no upgrade compatibility promise from early releases 0.1 through 0.8.

## Security assurance

The following security assurance gates are required for 1.0:

- **Security test suite**: The automated security test suite (`test/security`) must pass completely.
- **Fuzzing**: Continuous fuzz testing across input parsers and protocol handlers.
- **Threat model**: A published threat model documenting trust boundaries and attack surfaces.

An independent community review is planned for 2.0 and is not a gate for 1.0.

## Test matrix

Every release must satisfy both automated continuous integration and a manual platform checklist.

### Automated in CI

- End-to-end (`e2e`) tests and the security test suite running on the Compose stack.
- A Helm install test against a local cluster.
- Builds of the Android, Windows, and Linux client applications.

### Manual checklist

A manual checklist executed by the maintainer on one machine prior to release:

- **Test environments**:
    - Debian in a virtual machine
    - Fedora in a virtual machine
    - Windows in a virtual machine
    - Arch Linux natively
    - Android on the emulator
- **Verification steps** (executed on each environment):
    1. **Install**: Install the platform package.
    2. **Enrol**: Enrol the device against the Control Plane.
    3. **Tunnel up**: Bring the tunnel up and verify traffic flow.
    4. **Kill switch**: Trigger the kill switch and verify that non-tunnel traffic is blocked.
    5. **Uninstall**: Uninstall the package cleanly.

## Known limits to resolve before 1.0

The following known limitations must be resolved before tagging 1.0:

- **Windows installer signing**: Replace the unsigned Windows MSI with a code-signed MSI.
- **Android APK signing**: Replace the debug-signed Android APK with a signed release APK.
- **Windows kill switch**: Implement the kill switch for the Windows client.
- **Real install testing**: The client has never been installed and run end to end on Windows, Debian or Fedora; the manual checklist above must pass on every listed platform.
- **Linux display driver defect**: Resolve the Linux app drawing only part of the window on the NVIDIA EGL driver.
- **Edge high availability**: Deploy at least two Edges with client failover (multi-region support comes later).
- **Single Control Plane**: A single Control Plane running on SQLite is acceptable for 1.0 when documented, with backup and restore tested.

## Packages for 1.0

The 1.0 release produces the following packages:

- **Linux client**: Packaged as `.deb`, `.rpm`, and an Arch Linux package.
- **Windows client**: Code-signed Windows MSI.
- **Android client**: Signed Android release APK.
- **Container images**: Container images for the central components and the all-in-one quick start.

## Required documentation

The following documentation must be published and current for 1.0:

- **Installation guides**: Install guides for Compose and Helm.
- **Admin guide**: Operational documentation for tenant, PKI, and policy administration.
- **User guides**: A user guide per client platform (Android, Linux, and Windows).
- **Upgrade notes**: Upgrade notes published with every release.
- **API and policy reference**: Complete reference documentation for `/v1` APIs and `docs/schema/tenant-policy.schema.json`.
- **Public threat model**: Published threat model document.
- **Security policy**: Up-to-date vulnerability reporting instructions in `SECURITY.md`.

## Release rules

Every release must adhere to the following release rules:

- **No open vulnerabilities**: No open High or Critical security issue.
- **No disabled tests**: No disabled e2e or security test.
- **Transparent limitations**: Every remaining known limit must be listed in the release notes.

## Release gate

The release gate verifies commit integrity before publication:

- The release workflow publishes artifacts only when the CI and e2e workflows (where e2e includes the security suite) have succeeded on the tagged commit.
- This gate is already enforced and applies to all releases, not only 1.0.

## Version sequence

The roadmap to 1.0 follows this version sequence:

1. **`0.x` feature releases**: Incremental pre-releases delivering features and platform support.
2. **`0.9` feature freeze**: Complete feature freeze establishing the upgrade baseline.
3. **`1.0.0-rc.N`**: Release candidates dedicated to testing and stabilization.
4. **`1.0.0`**: Final release meeting all quality bar criteria.
