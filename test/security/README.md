# OpenSASE security suite

Repeatable attacks against the local dev stack, run the way a hostile client, a compromised
tenant, a stolen device or a network attacker would. Each check prints one line:

```
PASS|FAIL|KNOWN-FAIL|SKIP <ID> <description> [-- detail]
```

- **PASS**: the attack was tried and refused. Every PASS has a positive control, so a broken
  test cannot pass. For example, the refused identity's own route still works, the tunnel
  carries a ping, or an RST from the Edge filter is required (silence is not enough).
- **FAIL**: the attack got through, or a control failed. The run exits non-zero.
- **KNOWN-FAIL `[ST-nn]`**: a reproduced finding from `docs/security/sectest-*.md`. It is kept in
  the suite and does not fail the run. When it stops reproducing, the check prints PASS with
  "known finding ... no longer reproduces", and the report should be updated.
- **SKIP**: a precondition is missing, for example no internet, no Connector or a destructive
  check without opt-in.

## Run

```sh
deploy/dev/bootstrap.sh          # once: the stack must be up (e2e.sh is fine too)
make sectest                     # shell areas + Go checks against the stack
make sectest-unit                # Go checks that need no stack (CI)

test/security/run.sh 10-tls 70-deploy          # only some shell areas
SECTEST_GO_RUN='TestAuth|TestPKI' make sectest  # subset of the Go checks
SECTEST_DESTRUCTIVE=1 make sectest              # also floods (loopback only)
SECTEST_SLOW=1 make sectest                     # also checks that superseded tunnels die (waits ~12 min)
OPENSASE_SECTEST=1 go test -v -run TestDataPlane ./test/security/go/
```

Requirements: docker, Go, curl and openssl with X25519MLKEM768 (OpenSSL >= 3.5).

In CI, `.github/workflows/e2e.yml` runs the suite after `e2e.sh` against a stack built from
the commit (see `deploy/dev/README.md`, "Offline and CI runs").

The results go to `$SECTEST_RESULTS` (a temp file by default). The Go log is next to it, at
`$SECTEST_RESULTS.go.log`.

## Layout

| File | Area | What it attacks |
|---|---|---|
| `run.sh` | | Entry point. Runs every `NN-*.sh`, then `go test ./test/security/go`, and prints a summary |
| `lib.sh` | | Helpers: result lines, PQ curl, admin calls with the token on stdin, `dc`/`cexec` |
| `10-tls.sh` | 3 | `openssl s_client`: classic groups and TLS 1.2 refused on 9443/8443/8444; `opensasectl pq-check` |
| `20-auth.sh` | 1, 4 | Admin token; mTLS routes without a certificate; public surface; portal path traversal; methods; no-store |
| `50-dataplane.sh` | 5 | Through the real client container: metadata, DNS/DoT/DoH bypass, IPv6 leak, port policy, ZTNA, the Edge tunnel address |
| `70-deploy.sh` | 6, 7 | Container uid, capabilities, no-new-privileges, mounts; modes of secrets, DB, state and flow logs |
| `go/auth_test.go` | 1 | Admin token variants and timing; role isolation matrix (device, connector and Edge certs on every route, the Edge session channel and the broker); revoked device, connector and Edge; superseded certificates |
| `go/tenant_test.go` | 2 | Snapshot, decide, flows, user rules and connector config across tenants; Private Edge feed, decide and flows |
| `go/tls_test.go` | 3 | Classic groups; forged SPIFFE URIs from a real tenant CA; foreign root; expired and not-yet-valid certs; chain shape; unknown serials at the Edge; broker ALPN |
| `go/input_test.go` | 4 | Oversized bodies and headers; malformed JSON; traversal and injection in IDs; policy validation; long-poll cap; flow rate limit; key expiry; flow clamping; JSON fuzz |
| `go/zz_ratelimit_test.go` | 4 | Enroll brute force (429 + Retry-After). It runs last because it spends this host's enroll budget for a minute |
| `go/dataplane_test.go` + `go/tunnel_test.go` | 5 | Hostile WireGuard client (real PQ session, raw packets): built-in deny, private ranges, Edge own ports, DNS bypass, port policy, stateless segments, spoofed sources, device-to-device, ZTNA cross-tenant, IPv6 |
| `go/offline_test.go` | 6 | Throwaway Edge container (`--network none`) started from crafted signed `state.json` caches. The control is the Edge's own cache; tampered variants are re-signed with `pki/edge/edge.key`, which models an attacker who holds the Edge key |
| `go/flood_test.go` | 4 | Destructive (opt-in): idle-connection flood |
| `go/unit_test.go` | 1, 3 | No stack: `pki.VerifyPeer`, `ValidID`/`ParseURI`, `ExpectServer`, `pqsession.Harden` and PSK binding |

## Rules the suite follows

- **Isolation.** Every Go run creates its own tenants `sectest-<run>-a` and `sectest-<run>-b`,
  with users, devices, connectors and two Edges (a public one, and a Private one bound to
  tenant A). At the end it revokes all of them.
  - The API cannot delete tenants, so empty `sectest-*` tenants remain in the dev database.
    Reset the stack to remove them.
  - Nothing of tenant `acme` is modified or revoked.
  - Checks do not depend on order.
- **Certificates.** The harness reads `deploy/dev/pki/root.key` and the sectest tenants' CA
  keys. It uses them to issue its own Edge certificates, as `opensasectl pki` would, and to
  forge certificates. It never prints them.
- **Secrets.** The admin token is read from `deploy/dev/.env` at runtime. It is passed to curl
  on stdin (`-H @-`), never on a command line, and never printed.
- **Targets.**
  - Only loopback and the local docker network.
  - Outbound probes go only to the e2e hosts (example.com, smtp.gmail.com:25/587). Probes to
    public resolvers and DoH endpoints only check that they are blocked.
  - Floods need `SECTEST_DESTRUCTIVE=1` and stay on loopback.
- **Enroll rate limit.**
  - The CP allows 30 failed enrollments per source IP per minute, and every host request
    shares the docker-proxy source IP.
  - `do()` waits out `Retry-After` and retries enrollment calls, so a 429 is never a result or a
    control. The brute-force check opts out of the retry.
  - Keep new failing-enrollment probes few, or the run slows down by a minute.
- **Product code is never edited.** A failing check stays in the suite as `KNOWN-FAIL <id>`.

## Adding a check

- **Shell:** compute a result, then call `pass ID "desc"`, `fail ID "desc" "detail" [ST-nn]` or
  `skip ...`. Start with a comment that says what is attacked and what result is expected.
- **Go:** use `check(t, "SEC-XXX-nnn", "desc", "" /* or "ST-nn" */, func(t *testing.T) error {...})`.
  - Return `nil` only when the attack was refused **and** a control proved that the test could
    have seen it succeed.
  - Return `skipf(...)` for a missing precondition.
  - Stack checks start with `f := stack(t)`.
