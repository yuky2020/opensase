# OpenSASE (working name)

Open-source SASE platform: Client, Connector, Workload Gateway, Edge
(public and private), and a multi-tenant Control Plane with ZTNA, SWG, FWaaS, CASB and DLP.

Status: **pre-alpha**. Working end to end in the dev stack: the Android client (Flutter, on-device
firewall, all traffic captured), the Control Plane, the post-quantum Edge, ZTNA private app access
through the Connector (ADR-0013) and the admin portal (Flutter web, served at `/admin/`).

Licence: [Apache-2.0](LICENSE).

- `CONTEXT.md` — domain glossary (use these terms)
- `docs/architecture.md` — overview, principles, flows, technology baseline
- `docs/components/` — per-component specs
- `docs/adr/` — architecture decisions (proposed)
- `docs/effort-estimate.md` — sizing and phases

## Repository layout

- `cmd/` — command-line entrypoints and daemons (`controlplane`, `edge`, `opensasectl`)
- `pkg/` — public Go packages and core libraries (`policy`, `api`, `pki`, `store`, `firewall`, `dnsfilter`, `pqsession`)
- `internal/` — private internal application logic (`controlplane`, `edge`)
- `mobile/` — Go mobile library bridge (`gomobile` bindings for client applications)
- `clients/mobile` — Flutter client app (Dart UI; native Android VpnService + Go core .aar)
- `clients/admin` — admin portal (Flutter web; `make portal`, served by the Control Plane at `/admin/`)
- `cmd/connector`, `internal/connector` — Connector for private app access (outbound only)
- `deploy/dev` — local development environment configs, Docker Compose stacks, and test harnesses
- `docs/` — architecture documentation, component specifications, and Architecture Decision Records (ADRs)

## Quick start (dev)

1. Start the local development stack:
   ```bash
   make dev-up
   ```

2. Bootstrap the development environment:
   ```bash
   deploy/dev/bootstrap.sh
   ```

3. Build the Android client APK (builds Go core `.aar` and assembles debug APK):
   ```bash
   make apk
   ```

4. Install on the emulator:
   ```bash
   adb install clients/mobile/build/app/outputs/flutter-apk/app-debug.apk
   ```

5. Run end-to-end integration tests:
   ```bash
   make e2e
   ```

## Security

> [!NOTE]
> All tunnels and APIs use TLS 1.3 with X25519MLKEM768 only (see `docs/adr/0002`).

## Licence

Copyright 2026 The OpenSASE Authors. Licensed under the Apache License, Version 2.0; see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Contributions are accepted under the same licence
(inbound = outbound, Apache-2.0 section 5); no CLA is required.
