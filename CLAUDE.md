# OpenSASE — working rules for agents

Read first: `CONTEXT.md` (glossary), `docs/architecture.md`, `docs/adr/0002-*.md` (PQ tunnel),
`docs/adr/0012-*.md` (Android-first slice).

## Contract files (do not change without the lead's approval)

- `pkg/policy/types.go` — Policy Snapshot schema and evaluator signatures
- `pkg/api/types.go` — HTTP API wire types and endpoint list
- `mobile/api.go` — gomobile API between the Go core and Android
- `pkg/pqsession/` — PQ session channel (TLS restricted to X25519MLKEM768 + PSK exporter)

If a contract is wrong or missing something, add a `// CONTRACT-CHANGE-REQUEST:` comment next to
your code and describe it in your final report. Never silently fork the types.

## Ownership (parallel agents: stay in your directories)

| Area | Directories |
|---|---|
| policy | `pkg/policy` (except types.go), `pkg/packet` |
| client core | `pkg/firewall`, `pkg/dnsfilter`, `mobile` (except api.go), `docs/mobile-client.md` |
| cloud | `pkg/pki`, `pkg/store`, `cmd/controlplane`, `cmd/edge`, `cmd/opensasectl`, `internal/controlplane`, `internal/edge`, `deploy/` |
| mobile app (Flutter) | `clients/mobile` (Dart UI + native Android VpnService/bridge in `android/`) |

`go.mod`/`go.sum`: you may `go get` a dependency. Do not run `go mod tidy` (the lead runs it).

## Environment

- Go 1.27 (`go`), JDK 21 at `~/opt/jdk21`, Android SDK at `~/Android/Sdk` (platform 36,
  build-tools 36.0.0, NDK 28.2.13676358), gomobile in `~/go/bin`, AVD `opensase` (API 35, x86_64).
- `export JAVA_HOME=~/opt/jdk21 ANDROID_HOME=~/Android/Sdk ANDROID_NDK_HOME=~/Android/Sdk/ndk/28.2.13676358 ANDROID_AVD_HOME=~/.config/.android/avd PATH=~/opt/jdk21/bin:~/go/bin:~/Android/Sdk/platform-tools:~/Android/Sdk/emulator:$PATH`
- Emulator: `emulator -avd opensase -no-window -no-audio -no-snapshot &` (KVM available). Host is reachable from the emulator as 10.0.2.2.
- Docker is available. No sudo.

## Antigravity (agy) — use it for mechanical work

Delegate boilerplate, docs, test tables, repetitive UI or config files to the Antigravity CLI.
Keep the design and the security-critical code (crypto, packet parsing, policy evaluation) yourself.
Review every file agy writes.

```
Write the prompt to a file under .agy/prompts/, then run (it falls back across models on 503 errors):
.agy/run.sh .agy/prompts/<name>.md /tmp/claude-1000/agy-<name>.log

Equivalent raw command (single model):
agy -p "<precise prompt with exact file paths and acceptance criteria>" \
  --model gemini-3.8-flash-medium --mode accept-edits --sandbox --settings .agy/settings.json
```

Prompt rules for agy: one simple command at a time; never chain with `||`, `&&`, `;` or pipes;
never run node/npm/npx/go/gradle; only create or edit the listed files. Its log may say
"no output produced" even when it wrote the files, so check the files.

## Code standards

- Go: `gofmt`, `go vet` clean, table-driven tests, `-race` clean, no global state, `context.Context`
  for anything that blocks, `log/slog` for logs. Never log keys, PSKs, tokens or provisioning keys.
- Crypto: only stdlib (`crypto/tls`, `crypto/ed25519`, `crypto/ecdsa`, `crypto/mlkem`) and
  `golang.zx2c4.com/wireguard`. No custom primitives. Wipe PSKs after use (`clear`).
- All TLS (Control Plane, Edge, clients) goes through `pqsession.Harden`. No classic fallback.
- Mobile: Flutter (Dart, Material 3, Riverpod, go_router) for all UI and logic; native Kotlin only for VpnService, platform bridge and the gomobile .aar (`clients/mobile/android/app/libs/opensase-core.aar`). minSdk 29, targetSdk 36. Flutter SDK at `~/opt/flutter`.
- Commit only if the lead asks; otherwise leave changes in the working tree.
