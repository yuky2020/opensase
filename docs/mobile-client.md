# Client core (Go, gomobile)

## Overview
- The Go core (package `mobile`, built with gomobile into `clients/mobile/android/app/libs/opensase-core.aar`) does everything except UI and VpnService: enrollment, session setup with the Edge (post-quantum PSK, ADR-0002), wireguard-go, the on-device firewall (`pkg/firewall`), DNS interception (`pkg/dnsfilter`), snapshot long-poll, flow log upload, PSK rotation.
- Packet path diagram:

```
[Forward path]
apps ---> VpnService TUN fd ---> FilteringTUN (classify flow, policy evaluate, DNS filter)
                                      |
                                      v
                                wireguard-go (WireGuard + PSK)
                                      |
                                      v
                               UDP (protected socket) ---> Edge

[Reverse path]
apps <--- VpnService TUN fd <--- FilteringTUN (stateful: allowed flows only, DNS snoop)
                                      ^
                                      |
                                wireguard-go
                                      ^
                                      |
                               Edge
```

## Build
```
export JAVA_HOME=~/opt/jdk21 ANDROID_HOME=~/Android/Sdk ANDROID_NDK_HOME=~/Android/Sdk/ndk/28.2.13676358 PATH=~/opt/jdk21/bin:~/go/bin:$PATH
gomobile init
gomobile bind -target=android/arm64,android/amd64 -androidapi 29 -javapkg eu.opensase.core -o clients/mobile/android/app/libs/opensase-core.aar ./mobile
```

### Java API (`eu.opensase.core.mobile`)

| Class / Interface | Member / Method | Description |
|---|---|---|
| `Mobile` | `newEngine(String stateDir, Platform p): Engine` | Creates engine instance; throws `Exception`. |
| `Mobile` | `StateStopped`, `StateConnecting`, `StateConnected`, `StateError` | State constants: `"stopped"`, `"connecting"`, `"connected"`, `"error"`. |
| `Engine` | `isEnrolled(): boolean` | Returns true if client has valid enrollment credentials. |
| `Engine` | `enroll(String controlUrl, String provisioningKey, String deviceName)` | Enrolls device with Control Plane; throws `Exception`. |
| `Engine` | `unenroll()` | Removes enrollment state; throws `Exception`. |
| `Engine` | `tunnelConfig(): String` | Performs session setup with Edge and returns JSON interface parameters; throws `Exception`. |
| `Engine` | `start(long tunFd, String networkType)` | Starts tunnel using adopted TUN fd and initial network type; throws `Exception`. |
| `Engine` | `stop()` | Uploads remaining flow records, wipes session keys, closes the TUN. Does not throw. |
| `Engine` | `setNetworkType(String)` | Updates active network type (`"wifi"`, `"cellular"`, etc.). |
| `Engine` | `snapshot(): String` | Returns signed Policy Snapshot payload JSON or `""`. |
| `Engine` | `setUserRules(String json)` | Submits `api.UserRules` JSON to Control Plane; throws `Exception`. |
| `Engine` | `setAppPolicy(String pkg, String wifi, String cellular, String roaming)` | Sets per-app network policy; throws `Exception`. |
| `Engine` | `recentFlows(long limit): String` | Returns JSON array of recent flow records. |
| `Engine` | `appStats(): String` | Returns JSON array of per-app traffic and flow statistics. |
| `Engine` | `status(): String` | Returns engine runtime status JSON. |
| `Engine` | `setPosture(String postureJson)` | Sets host-collected `api.Posture` JSON; throws `Exception`. |
| `Engine` | `postureFailing(): String` | Returns JSON array of failed posture checks from active snapshot, or `"[]"`. |
| `Platform` | `long connectionOwnerUID(long protocol, String srcIp, long srcPort, String dstIp, long dstPort)` | Callback returning Linux UID for connection tuple, or -1. |
| `Platform` | `String packagesForUID(long uid)` | Callback returning comma-separated package names for UID. |
| `Platform` | `boolean protect(long fd)` | Callback to bypass VPN routing via `VpnService.protect(fd)`. |
| `Platform` | `void onEvent(String kind, String payload)` | Async event notification callback (non-blocking). |

> **Note:** Go `int` maps to Java `long`, so Kotlin passes `Long` (e.g. `fd.toLong()`). Methods that return errors throw `java.lang.Exception`.

## Lifecycle (Kotlin side)
1. `newEngine(context.filesDir + "/opensase", platformBridge)` once per process.
2. If `!isEnrolled()`: `enroll(controlUrl, provisioningKey, deviceName)`. Enrollment trust: the control URL may end with `#sha256=<hex SHA-256 of the CA or server certificate DER>` to pin the server; otherwise a PEM bundle in `<stateDir>/bootstrap-ca.pem` is used; otherwise the system roots. After enrollment the tenant CA returned by the Control Plane is the only trust anchor. `enroll()` also fetches, verifies and stores the first Policy Snapshot (best effort), so `snapshot()` and the policy screens are filled before the first connect.
3. `tunnelConfig()` returns `{"ipv4":"100.64.0.7/32","ipv6":"fd7a:5a5e::7/128","dns":["100.64.0.1"],"mtu":1280}`. It performs session setup with the Edge, so call it right before building the interface. Use it for `VpnService.Builder`: addAddress for ipv4 and ipv6, addDnsServer for each dns entry, setMtu(mtu), addRoute 0.0.0.0/0 and ::/0, addDisallowedApplication(own package).
4. `establish()`, then `start(pfd.detachFd().toLong(), networkType)`. The core takes ownership of the fd and closes it on `stop()`. Never close it from Kotlin.
5. On network changes (ConnectivityManager callback) call `setNetworkType("wifi"|"cellular"|"roaming"|"ethernet"|"unknown")`.
6. `stop()` uploads remaining flow records (3 s budget), wipes the session keys and closes the TUN.

- The session from `tunnelConfig()` is valid for 2 minutes; after that `start` performs a new session setup itself.
- All methods are thread-safe. `tunnelConfig`, `enroll`, `start`, `setUserRules`, `setAppPolicy` do network I/O: call them off the main thread.

## Platform callbacks
- `connectionOwnerUID`: called once per new TCP/UDP flow (result cached 1 minute per connection), from the packet goroutine: must return within a few ms. Use `ConnectivityManager.getConnectionOwnerUid(protocol, InetSocketAddress(src), InetSocketAddress(dst))`; return -1 if unknown.
- `packagesForUID`: `PackageManager.getPackagesForUid(uid)` joined with ","; cached 1 minute. The first package is used as the app identity in rules and logs.
- `protect`: `VpnService.protect(fd)`. Called for every socket the core opens (Control Plane and Edge HTTPS, DNS lookups of the WireGuard endpoint, the WireGuard UDP sockets each time they are opened). If it returns false the connection is refused (fail-closed).
- `onEvent`: called from Go goroutines; must not block. Post to the main thread / a Flow.

## Events
The `payload` parameter is always a JSON document:

- `state`:
  ```json
  {"state":"connected","error":""}
  ```
  After a PSK rotation:
  ```json
  {"state":"connected","epoch":3}
  ```
  When the WireGuard tunnel is dead (no handshake for 3 minutes) the core reports `connecting` and sets up a new session:
  ```json
  {"state":"connecting","error":"tunnel down: no WireGuard handshake"}
  ```
  When the device certificate has expired:
  ```json
  {"state":"error","error":"certificate expired, re-enrollment required"}
  ```
- `snapshot`:
  ```json
  {"version":7,"stale":false,"issuedAt":"2026-11-19T10:00:00Z","expiresAt":"2026-11-20T10:00:00Z"}
  ```
  When the snapshot becomes stale while running:
  ```json
  {"version":7,"stale":true}
  ```
- `flow`: one `api.FlowRecord`:
  ```json
  {"start":"2026-11-19T10:00:00Z","end":"0001-01-01T00:00:00Z","flow":{"app":"com.example","uid":10123,"network":"wifi","protocol":"tcp","dstIp":"203.0.113.5","dstPort":443,"domain":"www.example.com"},"decision":{"action":"block","ruleId":"no-social","layer":"tenant","log":false},"bytesOut":0,"bytesIn":0,"where":"device","deviceId":"dev-1"}
  ```
  Emitted for every blocked flow and blocked DNS query, and for allowed flows matching a rule with `log: true` (at start and at end), rate limited to 20 per second (burst 50). Blocked DNS queries have `decision.layer = "dns"`, `decision.ruleId = "dns:<blocklist id>"` (`dns:custom` for `blockDomains`) and `flow.domain` = the queried name.
- `stats`: every 5 s while running, same JSON as `appStats()`.
- `error`:
  ```json
  {"op":"snapshot","message":"..."}
  ```
  `op` is `"snapshot"`, `"rotate"` (a PSK rotation failed; the core falls back to a new session), `"session"` (setting up a new session failed) or `"renew"` (certificate renewal failed). All are background failures retried with backoff.
- `log`:
  ```json
  {"level":"INFO","msg":"policy snapshot installed","time":"...","attrs":{"version":7}}
  ```
  Emitted for INFO and above. Never contains keys, PSKs or provisioning keys. A change of the snapshot signing keys is logged at WARN with `msg` `"snapshot signing keys changed"` and attrs `added` / `removed` (key IDs).

## JSON results
- `status()`:
  ```json
  {"state":"connected","error":"","enrolled":true,"deviceId":"dev-1","edge":"edge-1","network":"wifi","snapshotVersion":7,"stale":false,"pq":true,"kex":"X25519MLKEM768","epoch":3,"lastHandshake":1763550000,"certExpiresAt":"2026-11-20T10:00:00Z","txBytes":1234,"rxBytes":5678}
  ```
  `pq` is true and `kex` is present only when the live session-setup TLS connection was verified to use X25519MLKEM768; the UI must show the quantum-safe badge only in that case. `lastHandshake` is the WireGuard handshake time (unix seconds, omitted before the first handshake).
  `certExpiresAt` is the device certificate expiry (RFC 3339, UTC). `state` is never `connected` while the last WireGuard handshake is older than 3 minutes: it is then `connecting` with `error` `"no WireGuard handshake for <duration>"`. When the device certificate has expired, `state` is `error` with `error` `"certificate expired, re-enrollment required"`; the app must offer re-enrollment (unenroll, then enroll).
- `appStats()`: array, busiest first:
  ```json
  [{"app":"com.example","bytesIn":5678,"bytesOut":1234,"allowed":12,"blocked":3,"dnsQueries":40,"dnsBlocked":5}]
  ```
  `app` is `""` for traffic with unknown owner. `allowed`/`blocked` count flows.
- `recentFlows(limit)`: array of flow records (same schema as the `flow` event), newest first, last 2048 kept.
- `snapshot()`: the signed Policy Snapshot payload (`policy.Snapshot` JSON) or `""`.
- `setUserRules(json)`: `api.UserRules` JSON:
  ```json
  {"rules":[...],"apps":{"com.example":{"wifi":"allow","cellular":"block"}}}
  ```
  Rules get `source:"user"`; a rule with another source is rejected. Returns after the Control Plane accepted it and the new snapshot is installed. Fails with HTTP 403 if the tenant does not allow user rules.
- `setAppPolicy(pkg, wifi, cellular, roaming)`: each value `"allow"`, `"block"`, `"ask"` or `""` (unset); all empty removes the app. Convenience over setUserRules using the last user layer sent from this device.

## Security
- Server identity: every TLS connection checks the server leaf's SPIFFE URI SAN after chain verification (`pki.ExpectServer`): the Control Plane must be `spiffe://opensase/controlplane` (also on the enrollment bootstrap, CA file or `#sha256=` pin), an Edge session URL must be `spiffe://opensase/edge/<EdgeInfo.ID>`. Snapshot signing keys are refreshed from `GET /v1/pki/ca` only over a connection that proved the Control Plane identity.
- Certificate renewal: at 50% of the device certificate lifetime (immediately at start if more than 50% has elapsed) the core generates a new ECDSA P-256 key and CSR and calls `POST /v1/renew` with mTLS. The new certificate must be for the new key, have a new serial, carry the same device SPIFFE URI, chain to the enrolled tenant CA (roots from enrollment, never from the response) and not expire earlier than the current one. It is stored atomically in `device.pem` and used at once for the Control Plane and for the next Edge session setup. A failed renewal never stops the tunnel while the current certificate is valid: it is reported (`error` event, op `"renew"`) and retried with backoff (from 30 s, at most 10 min). An expired certificate cannot be renewed: re-enrollment is required.
- Session recovery: if a PSK rotation fails (HTTP 409 because the Edge already moved to the next epoch, a lost response, a timeout), the core sets up a new session at epoch 0 with a new WireGuard key and reconfigures WireGuard completely. A liveness check every 30 s does the same when the last WireGuard handshake is older than 3 minutes.

## Firewall behaviour
- Every new flow (5-tuple) is evaluated once: tenant rules > user rules (if allowed) > per-app policy for the current network > lockdown > default action. Established flows are not re-evaluated on every packet: only when the snapshot or network type changes (lazily, on the next packet).
- Tenant mandates are absolute (ADR-0012, review D1): under tenant Lockdown, user rules can only block (user `allow` and `ask` rules are ignored), and a per-app `allow`/`ask` only counts for packages listed in the snapshot's `firewall.tenantApps`; a user per-app `block` still applies.
- Block: TCP gets an RST, UDP/ICMP an ICMP "administratively prohibited"; the app fails fast.
- Ask: the first packet is dropped and `POST /v1/decide` is sent (one request per distinct flow, max 32 in flight); the verdict is cached for its TTL and the TCP/UDP retransmission passes. If the cloud is unreachable the flow is blocked for 10 s (fail-closed). The headless client and tests can use the snapshot default action instead (`FallbackToDefault`).
- No snapshot yet: everything is blocked.
- Inbound packets pass only for existing allowed flows (plus ICMP errors quoting one of them, e.g. "packet too big").
- Link-scoped ICMPv6 (router/neighbour discovery and MLD, types 130-137 and 143, and any ICMPv6 to a multicast or link-local address such as router solicitation to ff02::2) is dropped silently: no flow record, no event, no reply.
- Conntrack idle timeouts: TCP SYN 30 s, established 2 h, FIN/RST 10 s, UDP 60 s, ICMP 30 s; at most 16384 flows (least recently used evicted).
- DNS: every UDP/53 query to the tunnel DNS servers is checked against the DNS policy; blocked names get NXDOMAIN, or 0.0.0.0 / :: for A/AAAA when `blockResponse` is `"zero"` (NODATA for other types). Responses are snooped to map IP -> queried name only if they answer an outstanding forwarded query: same transaction ID, same question name, same client port, from the session DNS server (outstanding queries expire after 10 s, at most 4096). A response is used once. When the session has no DNS servers, queries are still filtered but nothing is snooped. CNAME chains map to the queried name, TTL clamped to 30 s..24 h, 8192 entries LRU; this fills `flow.domain` for domain rules. DNS over TCP, DoT and DoH are not inspected (the Edge resolver enforces DNS policy again).
- Limitations: non-first IP fragments are dropped; no SNI inspection.

## Digital experience samples
While a tunnel session is connected, the client collects a digital experience sample every 60 seconds (issue #76). Each measurement performs a sequential burst of 5 session probes (with a 2-second timeout per probe) to the current Edge session endpoint to compute round-trip time (`RTTms`, the median of answered probes in milliseconds, or 0 if none answered) and probe packet loss percentage (`LossPct`). It also includes DNS resolution latency (`DNSms`, the median duration of forwarded DNS queries answered through the tunnel resolver since the last sample, or 0 if empty) and the active network type (`Network`). Samples are queued in the client (up to 60 buffered samples, dropping the oldest on overflow) and sent to the Control Plane in `batch.Probes` with the next flow batch upload (`POST /v1/flows`), including when there are no flow records to send. Successfully uploaded samples are cleared from the queue, while errors retain them for retry.

## Device posture (SetPosture and the reporting loop)
The client core supports device posture reporting (ADR-0035):
- **Signal collection:** The host application collects device posture signals (`api.Posture`) using platform APIs and provides them to the core via `setPosture(postureJson)`. Call it before `enroll()` and `start()`, as well as whenever any signal changes.
- **Validation and enrichment:** The core validates that the payload is valid JSON and that string fields (`os`, `osVersion`, `clientVersion`) do not exceed 64 bytes. If `clientVersion` is unset, the core populates it from build information or `"dev"`. `collectedAt` is automatically set to the current UTC timestamp.
- **Storage and change detection:** The posture is stored under a mutex. If the incoming posture differs from the previously stored posture (ignoring `collectedAt`), the core signals the posture reporting loop.
- **Enrolment:** `enroll()` includes the currently stored posture (if set) in `EnrollRequest.Posture` sent to `POST /v1/enroll`.
- **Reporting loop:** When the tunnel starts, a background posture loop runs alongside the other loops:
  - Reports with `POST /v1/posture` using device mutual TLS (the same HTTP client and format as `/v1/flows`).
  - Reports at start, periodically every 15 minutes, and within 5 seconds after a change signal.
  - Skips reporting if no posture has been set.
  - On error, logs a warning and retries at the next tick.
- **Failing checks:** `postureFailing()` returns the JSON array of failed check names from the active snapshot (`"[]"` if compliant or not enrolled). `status()` also includes `postureFailing` next to the snapshot fields when failing checks exist.

## State directory
All files are mode 0600 and written atomically:

| File | Content | Notes |
|---|---|---|
| `device.key` | ECDSA P-256 private key (PKCS#8 PEM) | Generated on device, never leaves it. |
| `device.crt` | Device certificate | Used for mTLS. |
| `device.pem` | Renewed private key + certificate chain (PEM) | Written by certificate renewal in one atomic rename; preferred over `device.key`/`device.crt` when present. |
| `enrollment.json` | `api.EnrollResponse` | Contains tenant CA, edges, snapshot signing keys, control URL. |
| `snapshot.json` | Last verified signed snapshot envelope | Used offline at startup. |
| `user_rules.json` | Last user layer sent with `setUserRules` | Local record of user-defined policies. |
| `bootstrap-ca.pem` | PEM certificate bundle | Optional, provided by the installer for enrollment trust. |

WireGuard keys are generated per session and never stored; PSKs live only in memory and are wiped on rotation and stop.

## Headless Linux client (`cmd/opensase-client`)
- Same Engine with a Linux TUN (`osase0`) and a stub platform (UID -1, so app rules never match; network type from `-network`, default `ethernet`).
- Flags:

| Flag | Default | Description |
|---|---|---|
| `-state` | `/var/lib/opensase-client` | Directory storing device keys, enrollment, and snapshot. |
| `-control` | | Control Plane URL (optionally with `#sha256=<fingerprint>`). |
| `-key-file` | | File with the provisioning key (preferred). |
| `-key` | | Provisioning key (deprecated: visible in ps and docker inspect; a warning is logged). |
| `-renew-now` | `false` | Renew the device certificate right after the tunnel is up (tests); a failure is logged and the tunnel keeps running. |
| `-enroll` | `false` | Enroll if the state directory has no identity yet (needs `-control` and a provisioning key). |
| `-name` | hostname | Device name sent at enrollment. |
| `-ca` | | PEM file copied to `bootstrap-ca.pem` for initial trust. |
| `-network` | `ethernet` | Network type reported to engine (`wifi`, `cellular`, `ethernet`, etc.). |
| `-tun` | `osase0` | Name of the TUN interface to create/adopt. |
| `-routes` | `false` | Automatically configure routing tables via ip commands. |
| `-status-every` | `30s` | Interval for printing status JSON lines. |
| `-v` | `false` | Enable verbose logging. |

- The provisioning key is read from `-key-file`, else from the environment variable `OPENSASE_PROVISIONING_KEY`, else from `-key`. The variable is removed from the process environment after enrollment. Prefer `-key-file` in containers: environment variables are visible in `docker inspect`.
- Without `-routes` it prints the ip commands. With `-routes` (needs `--cap-add NET_ADMIN --device /dev/net/tun`) it runs them: address on osase0, host routes for the Control Plane, Edge session and WireGuard endpoint via the existing default gateway, then `0.0.0.0/1` and `128.0.0.0/1` (and `::/1`, `8000::/1`) into osase0.
- Example:
```
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v ./state:/state -v ./pk.txt:/run/secrets/pk:ro opensase-client \
  -state /state -control https://controlplane:8443 -ca /state/ca.pem -key-file /run/secrets/pk -enroll -routes
```
- Events are printed to stdout as JSON lines `{"event":"<kind>","payload":{...}}`, status JSON every `-status-every`.
