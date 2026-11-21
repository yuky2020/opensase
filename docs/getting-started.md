# Getting started

## Quick start (dev stack)

Requirements: Docker with Compose, Go (see `go.mod`), and OpenSSL ≥ 3.5 for the security suite.
To build the mobile client and the portal you also need Flutter, the Android SDK and NDK, and
`gomobile`.

```bash
# 1. PKI, admin token, Control Plane, Edge, a tenant, a user, a policy, a Connector
deploy/dev/bootstrap.sh

# 2. End-to-end checks: tunnel, DNS, policy, ZTNA, Workload Gateway, offline Edge, revocation
make e2e

# 3. Look around
docker compose -f deploy/dev/docker-compose.yml run --rm ctl flows -tenant acme
```

`bootstrap.sh` is idempotent: running it again keeps the PKI and the data and issues a fresh
provisioning key. Secrets stay in `deploy/dev/.env` (mode 0600) and are never printed.

!!! tip
    `e2e.sh` revokes the Connector at the end. Run `deploy/dev/bootstrap.sh` again before
    `make sectest`.

??? example "Android client on the emulator"

    ```bash
    CONTROL_HOST=10.0.2.2 EDGE_HOST=10.0.2.2 deploy/dev/bootstrap.sh
    make apk                                   # Go core .aar + debug APK
    adb install clients/mobile/build/app/outputs/flutter-apk/app-debug.apk
    ```

??? example "Admin portal"

    ```bash
    make portal          # Flutter web build, bundled (no CDN)
    # served by the Control Plane at https://<control-host>/admin/
    ```

??? example "Tenant admin tokens"

    ```bash
    # As the super-admin: give tenant acme its own admin (token written to a 0600 file)
    opensasectl admin-token add -tenant acme -name "acme ops" -valid-for 720h -token-out acme.token
    OPENSASE_ADMIN_TOKEN=$(cat acme.token) opensasectl whoami     # tenant admin of acme
    opensasectl admin-token list -tenant acme
    opensasectl audit -tenant acme                                # who changed what
    ```

??? example "Private Edge and Workload Gateway"

    ```bash
    # Bind an Edge to one tenant, then start it with an offline cache and a local flow log
    opensasectl edge add -id site-milan -tenant acme
    edge -tenant acme -state-dir /var/lib/opensase-edge -flow-log /var/log/opensase/flows.jsonl ...

    # Put a workload subnet behind the tunnel (service user's provisioning key)
    opensase-client -gateway 10.30.0.0/24 -enroll -control https://cp.example -key-file key ...
    ```

    The dev stack runs both: the `edge` service keeps its state in `deploy/dev/edge-state`, and the
    `gateway` and `workload` services form the `vpc` network (`10.30.0.0/24`).

## Testing

| Command | What it runs |
|---|---|
| `make test` | Go unit and integration tests with `-race` |
| `make lint` | `golangci-lint` |
| `make app-test` / `make portal-test` | Flutter analyze + tests (mobile app / admin portal) |
| `make e2e` | End-to-end checks against the dev stack |
| `make sectest` | Security suite: black-box scripts plus Go attacks against the dev stack |
| `make sectest-unit` | The Go security checks that need no stack (runs in CI) |

CI runs `go vet`, `go test -race`, `govulncheck`, `golangci-lint`, and the Flutter tests plus an
APK build on every push.

### Security suite

The [security-tester agent](security/security-tester-agent.md) attacks the stack the way a hostile
client, a compromised tenant, a stolen device or a network attacker would. Each attack is saved in
[`test/security/`](security/test-suite.md) and prints `PASS`, `FAIL`, `KNOWN-FAIL` or `SKIP` with
a stable ID such as `SEC-AUTH-003`. Every `PASS` has a positive control, so a broken test cannot
pass by accident.

```bash
make sectest                                   # full suite
test/security/run.sh 10-tls 70-deploy          # selected areas
SECTEST_DESTRUCTIVE=1 make sectest             # also floods (local docker network only)
SECTEST_SLOW=1 make sectest                    # also waits ~12 min for superseded tunnels to die
```

Coverage areas:
- authentication and role isolation;
- tenant isolation and Private Edge scoping;
- PQ-only TLS, SPIFFE IDs, foreign roots and expired certificates;
- input handling and rate limits;
- data-plane bypasses: DNS, IPv6, metadata, spoofing and ZTNA;
- the offline cache;
- container hardening.

Latest run ([report](security/sectest-2026-11-20.md)): **103 pass · 0 fail · 0 known
failures**. The run found 10 issues, ST-01 to ST-10, and all of them are fixed. The earlier review
is in [`docs/security/review-2026-11-19.md`](security/review-2026-11-19.md).

## Repository layout

```
cmd/            entrypoints: controlplane, edge, connector, opensase-client, opensasectl
internal/       private logic: controlplane, edge, connector
pkg/            shared libraries: api, policy, pki, store, firewall, dnsfilter, packet, pqsession, peek, saas
mobile/         gomobile bridge for the Android client
clients/mobile  Flutter Android app (VpnService + Go core .aar)
clients/admin   Flutter web admin portal
deploy/dev      Docker Compose dev stack, bootstrap.sh, e2e.sh
test/security   repeatable security suite (shell + Go)
docs/           architecture, component specs, ADRs, security reports
```
