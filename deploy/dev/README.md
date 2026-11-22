# OpenSASE dev stack

The OpenSASE dev stack runs the Control Plane (https://localhost:9443) and Edge (session https://localhost:8443, WireGuard udp/51820, wg0 tunnel 100.64.0.0/10 with the Edge at 100.64.0.1, DNS resolver at 100.64.0.1:53, NAT to the internet), along with an optional headless Linux client (compose profile "e2e"). All TLS is TLS 1.3 restricted to X25519MLKEM768.

## Quick start

```sh
./bootstrap.sh
./e2e.sh
```

Checks performed by `e2e.sh`:
- Tunnel interface configuration: verifies tunnel address allocation on `osase0` within `100.64.0.0/10`, configures `nameserver 100.64.0.1` in `/etc/resolv.conf`, and validates default routing through the tunnel.
- Internet connectivity via Edge NAT: verifies `curl https://example.com` returns HTTP 2xx or 3xx through the Edge.
- DNS policy filtering: verifies `ads.doubleclick.net` returns `NXDOMAIN` via the Edge resolver (`100.64.0.1`) and fails on the system resolver, while `example.com` resolves successfully.
- Port blocking: verifies outbound TCP port 25 to `smtp.gmail.com` is blocked, and verifies TCP port 587 connects as a control.
- Flow telemetry: verifies flow records logged in the Control Plane via `opensasectl flows`, ensuring edge records (`"where": "edge"`), device records (`"where": "device"`), and the blocked port 25 rule (`"ruleId": "block-smtp"`) are present.
- Built-in Edge rules: verifies metadata 169.254.169.254 unreachable, `dig @8.8.8.8` fails, and DoT to 1.1.1.1:853 blocked.
- Certificate renewal: verifies the certificate renewal (device certificates with 24h lifetime are renewed with POST /v1/renew; the e2e client uses `-renew-now`).
- Deployment hardening: verifies the Edge runs as non-root and sees only its PKI files, and the Control Plane does not mount pki/edge.

### Offline and CI runs

The Control Plane downloads the UT1 category list (about 26 MB) on first start. For runs
without that download, write a small fixture archive and turn downloads off:

```sh
scripts/ci-categories-fixture.sh          # writes deploy/dev/data/categories.tar.gz
echo 'CATEGORIES_URL=' >>deploy/dev/.env  # keep the fixture
```

The fixture holds only the names the suites test (`0-casino.info` in `gambling`, and a URL
entry). The workflow `.github/workflows/e2e.yml` does this, builds every image, runs
`e2e.sh` and `make sectest` on each push to main, nightly and on demand, and uploads the
results and the compose logs as the artefact `e2e-sectest-results`.

## Files

| File / Directory | Description |
| --- | --- |
| `pki/` | Generated directory containing the root CA, server certificates, and private keys (keys mode `0600`, git-ignored). Edge material is only in `pki/edge/` (see PKI and certificates). |
| `data/` | Directory storing SQLite database files (`controlplane.db`). |
| `.env` | Environment file containing admin token (`OPENSASE_ADMIN_TOKEN`), provisioning key (`OPENSASE_PROVISIONING_KEY`), pinned control URL (`OPENSASE_CONTROL_URL`), and enroll URI (`OPENSASE_ENROLL_URI`) (mode `0600`). |
| `provisioning.key` | Provisioning key written by bootstrap (mode 0600), mounted into the client as the compose secret /run/secrets/provisioning_key and read with `-key-file`. The provisioning key is never on a command line. |
| `policy.example.json` | Example tenant policy defining firewall rules, DNS blocklists, and cloud decision defaults. |

## PKI and certificates

`opensasectl pki init` creates the dev PKI:
- PKI layout: `opensasectl pki init` writes Edge material only into `pki/edge/` (root.crt, edge.crt, edge.key, edge-wg.key). The Control Plane container mounts only root.crt, root.key, controlplane.crt, controlplane.key, snapshot.key, edges.json and tenants/ (never pki/edge). The Edge mounts only pki/edge at /pki (read-only).
- Server certificates have distinct SANs: flags `-cp-san` (default controlplane,localhost,127.0.0.1,::1,10.0.2.2) and `-edge-san` (default edge,localhost,127.0.0.1,::1,10.0.2.2).
- Server identity validation: Clients verify the SPIFFE URI of the server (spiffe://opensase/controlplane or spiffe://opensase/edge/<id>), not only the host name.

## Control Plane

Control Plane flags: `-max-conns` (4096), `-flow-retention` (168h), `-flow-rate` (1000 records per device per minute).

Device certificates (24h) are renewed with POST /v1/renew; the e2e client uses `-renew-now`.

## Edge

Edge container configuration and hardening:
- Container security: cap_drop ALL, cap_add NET_ADMIN, NET_BIND_SERVICE, SETUID, SETGID, no-new-privileges.
- Firewall setup: The entrypoint installs iptables rules as root (FORWARD default DROP; tunnel traffic to link-local 169.254.0.0/16, loopback, multicast and private ranges dropped; DNS 53 and DoT 853 to anything but the Edge resolver dropped; INPUT from wg0 only DNS and ICMP to 100.64.0.1) and then runs the edge as EDGE_UID (OPENSASE_UID) with setpriv and ambient NET_ADMIN + NET_BIND_SERVICE.
- Edge built-in rules applied before policy, logged with Layer "edge":
  - RuleID "builtin-deny" (link-local, loopback, multicast, the Edge's own addresses, private ranges unless `-allow-private` / EDGE_ALLOW_PRIVATE=1, extra `-deny-cidrs`).
  - RuleID "builtin-dns-bypass" (DNS/DoT to third parties, and HTTPS to well-known DoH endpoints unless `-allow-doh`).

## Admin CLI

Run `opensasectl` via the Docker Compose `ctl` service:

```sh
docker compose run --rm ctl <command>
```

Secrets management:
- Provisioning key: never on a command line. bootstrap writes deploy/dev/provisioning.key (mode 0600), mounted into the client as the compose secret /run/secrets/provisioning_key and read with `-key-file`.
- opensasectl reads the admin token from $OPENSASE_ADMIN_TOKEN or `-token-file`.

Edge registration:
Edges must be registered: `opensasectl edge add -id ID`, `edge list`, `edge revoke -id ID`. bootstrap registers edge-1. An unregistered or revoked edge certificate gets 403.

Examples for commands in the usage text:

- `pki export-ca`:
  ```sh
  docker compose run --rm ctl pki export-ca
  ```
- `bootstrap`:
  ```sh
  docker compose run --rm ctl bootstrap -tenant acme -user-id user-1 -email user@example.com
  ```
- `edge add`:
  ```sh
  docker compose run --rm ctl edge add -id edge-1
  ```
- `edge list`:
  ```sh
  docker compose run --rm ctl edge list
  ```
- `edge revoke`:
  ```sh
  docker compose run --rm ctl edge revoke -id edge-1
  ```
- `policy set`:
  ```sh
  docker compose run --rm ctl policy set -tenant acme -f /work/policy.example.json
  ```
- `policy get`:
  ```sh
  docker compose run --rm ctl policy get -tenant acme
  ```
- `flows`:
  ```sh
  docker compose run --rm ctl flows -tenant acme
  ```
- `devices`:
  ```sh
  docker compose run --rm ctl devices -tenant acme
  ```
- `revoke`:
  ```sh
  docker compose run --rm ctl revoke -tenant acme -device <device-id>
  ```
- `pq-check`:
  ```sh
  docker compose run --rm ctl pq-check
  ```

## Example policy

Explanation of `policy.example.json`:

- `block-smtp`: Firewall rule (priority 10) blocking outbound TCP traffic on port 25 with logging enabled to prevent spam and data exfiltration.
- `block-tracker-domains`: Firewall rule (priority 20) blocking network flows to IPs associated with tracker domains (`*.doubleclick.net`) learned through DNS snooping, with logging enabled.
- `ask-test-net-3`: Firewall rule (priority 30) for CIDR `203.0.113.0/24` with action `ask`, querying the cloud control plane (`POST /v1/decide`) to decide the action, with logging enabled.
- `ads` blocklist: DNS blocklist category named "Advertising" that blocks queries matching `*.doubleclick.net` and `*.googlesyndication.com` with `nxdomain`.
- `blockDomains`: Explicit list of tenant-blocked DNS domains (`blocked.opensase.test`).
- `decideBlockDomains`: Cloud decision blocklist of domains (`malware.opensase.test`) blocked when evaluated by `POST /v1/decide`.
- `decideBlockCidrs`: Cloud decision blocklist of CIDR ranges (`203.0.113.66/32`) blocked when evaluated by `POST /v1/decide`.
- `decideDefault`: Default fallback action (`allow`) for cloud decide requests when no block criteria match.
- `allowUserRules`: Policy flag (`true`) allowing client-side user rules in addition to tenant policy rules.
- `defaultAction`: Default fallback action (`allow`) for network flows that match no rules.

## Android emulator

On a fresh checkout (delete `pki/` and `data/` first if they exist), run:

```sh
CONTROL_HOST=10.0.2.2 EDGE_HOST=10.0.2.2 ./bootstrap.sh
```

This ensures `edges.json`, the Edge `-wg-endpoint`, and the pinned control URL use the emulator host alias (`10.0.2.2`). The server certificates generated during PKI setup always include `10.0.2.2`.

## Reset

To stop containers, remove volumes, and delete generated credentials and databases:

```sh
docker compose --profile e2e down -v
rm -rf pki data .env provisioning.key
```
