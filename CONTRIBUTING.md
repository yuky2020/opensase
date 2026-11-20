# Contributing to OpenSASE

Thanks for helping. OpenSASE is pre-alpha, so design discussion is as welcome as code.

## Where to start

- Read `CONTEXT.md` (glossary), `docs/architecture.md` and the ADRs in `docs/adr/`.
- Look for issues labelled `good first issue` or `help wanted`, or open a Discussion for ideas.
- For larger changes, open an issue or Discussion first; changes to contract files
  (`pkg/api/types.go`, `pkg/policy/types.go`, `mobile/api.go`, `pkg/pqsession/`) need an ADR or
  an agreed design note because the client, Control Plane and Edge share them.

## Development

```bash
go test -race ./...          # Go: Control Plane, Edge, Connector, client core
make portal-test             # admin portal (Flutter web)
make app-test                # Android client (Flutter)
make dev-up && deploy/dev/bootstrap.sh && deploy/dev/e2e.sh   # full stack in docker
```

Requirements: Go 1.27+, Flutter 3.50+, Docker; Android SDK/NDK for the mobile client.

## Rules

- Go: `gofmt`, `go vet` clean, table-driven tests, `-race` clean, `log/slog`, contexts for
  anything that blocks. Never log keys, PSKs, tokens or provisioning keys.
- Crypto: standard library and `golang.zx2c4.com/wireguard` only, no custom primitives. All TLS
  goes through `pqsession.Harden` (TLS 1.3, X25519MLKEM768 only, no classic fallback).
- Dart: `flutter analyze` with zero issues, tests for new logic.
- One logical change per pull request, with tests. Conventional Commit messages
  (`feat:`, `fix:`, `docs:` ...).

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0
(inbound = outbound, section 5 of the licence). No CLA is required. Sign off your commits
(`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
