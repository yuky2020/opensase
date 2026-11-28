# Issue #61 Implementation Plan: Device Mesh Direct Links (ADR-0034)

**Scope:** Remaining work items 2–4 of [ADR-0034](../adr/0034-device-mesh.md): Control Plane discovery API, `mesh.directLinks` propagation, client-side direct WireGuard links with post-quantum mutual TLS PSK exchange, receiving-client enforcement and `device-mesh` flow accounting, Linux/Windows then Android platform plumbing, E2E/security tests, and threat-model updates.

---

## Current State

Item 1 of ADR-0034 (policy schema and Edge-relayed mesh) is implemented; direct links are not yet active (`docs/operations/mesh.md:34-35`):

- **Policy & schema:** `api.MeshPolicy` already defines `Rules` and `DirectLinks bool` (default `false`, `pkg/api/types.go:731-754`; `docs/schema/tenant-policy.schema.json:608-702`). `policy.Snapshot` carries `MeshInbound []MeshGrant` (`pkg/policy/types.go:69-88`) compiled in `pkg/policy/mesh.go:17-86` (`MeshAllows`, `HasMesh`, `UserID`) and `pkg/policy/evaluate.go:102-103, 293-296`, but does **not** carry `DirectLinks` (`internal/controlplane/snapshot.go:401, 488, 507, 760-770`).
- **Control Plane & store:** Latest migrations are `pkg/store/migrations/0020_posture.sql` and `pkg/store/migrations/postgres/0020_posture.sql`. There is no mesh-candidate table or discovery route (`internal/controlplane/server.go:218-224`). `handleEdgeSessions` (`internal/controlplane/hardening.go:78-102`) and `ReportEdgeSessions` (`pkg/store/edges.go:138-161`) record `(edge_id, device_id, updated_at)` without observed endpoints. `handleFlows` overwrites `rec.Where = "device"` for every device upload (`internal/controlplane/handlers.go:360-366`), stripping `"device-mesh"`.
- **Edge:** `internal/edge/filter.go:212-214, 333-339, 352-397` enforces `MeshAllows` on Edge-relayed IPv4/IPv6 mesh flows. `wgConfigurer` exposes only `IpcSetOperation` (`internal/edge/session.go:23-25`), and `reportLoop` (`internal/edge/edge.go:852-893`) posts `DeviceIDs`/`ConnectorIDs` without peers' observed WireGuard UDP endpoints.
- **PKI & PQ session:** `pqsession.DerivePSK` binds PSKs with `ExporterLabel` (`pkg/pqsession/pqsession.go:14-69`). `SignDeviceCSR` issues device certs with `ExtKeyUsageClientAuth` only and URI `spiffe://opensase/tenant/<t>/device/<id>` (no `ServerAuth`, no IP SANs, no `userId`, `pkg/pki/pki.go:115-161, 294`; `pkg/pki/identity.go:95-160`).
- **Client core & firewall:** `FilteringTUN.meshInbound` (`pkg/firewall/firewall.go:501-544`) checks only `HasMesh()` and tunnel-prefix source (relying on Edge enforcement), and `recordFor` hardcodes `Where: "device"` (`pkg/firewall/firewall.go:932-942`). `mobile.Engine` runs one WireGuard `device.Device` (`mobile/engine.go:459-483, 587-643`) whose `uapiFull` uses `replace_peers=true` (`mobile/session.go:235-250`) and whose `peerStats` assumes a single peer (`mobile/engine.go:899-920`, `mobile/loops.go:397`). `enrollment` retains a `*x509.CertPool`, not the parsed root cert (`mobile/state.go:33-37, 145-150`).
- **Platform networking:** Linux `opensase_killswitch` drops all non-bypass outbound packets (`internal/clientnet/killswitch_linux.go:27-65`), and split `/1` routes capture non-LAN public peer IPs on Linux (`internal/clientnet/linux.go:93-206`) and Windows (`internal/clientnet/windows.go:305-347`, `routeplan.go:31-108`); Windows WFP already allows the `opensased` service (`internal/wfp/blocker.go:138`, `rules.go:137-277`). Android excludes its own package (`OpenSaseVpnService.kt:219`) and protects sockets (`mobile/platform.go:28-67`), but does not pass `LinkProperties` LAN addresses to Go (`NetworkMonitor.kt:15-52`).
- **Tests & threat model:** `deploy/dev/e2e.sh:280-310` tests IPv6 Edge-path mesh between `client` and `gateway`; `test/security/go/dataplane_test.go:219-229` checks cross-tenant Edge drop only; `THREAT_MODEL.md:36-78` has no direct-link entry points or threats yet.

---

## Ordered Implementation Plan

Steps are sized to at most 5 files each, compile and pass CI independently, and keep direct links completely disabled until receiving-client policy enforcement (Step 5) is in place.

### Step 1 — Policy, `pqsession`, and API Contracts
- **Goal:** Add shared contract types for `mesh.directLinks`, discovery APIs, Edge-observed endpoints, `"device-mesh"` flow records, and mesh PSK derivation; no runtime behaviour changes yet.
- **Files:**
  - `pkg/policy/types.go` (**CONTRACT CHANGE**): add `MeshDirectLinks bool` (`json:"meshDirectLinks,omitempty"`) to `Snapshot`.
  - `pkg/policy/mesh.go` & `pkg/policy/evaluate.go`: compile `MeshDirectLinks` into `Compiled` and expose `(*Compiled).MeshDirectLinks() bool`.
  - `pkg/pqsession/pqsession.go` (**CONTRACT CHANGE**): add `MeshExporterLabel = "EXPORTER-opensase-mesh-psk-v1"` and `DeriveMeshPSK(cs, initWGPub, respWGPub, linkID, epoch)` enforcing `CheckPostQuantum` and domain-separating direct-link PSKs from Edge sessions.
  - `pkg/api/types.go` (**CONTRACT CHANGE**): document `POST /v1/mesh/candidates`, `GET /v1/mesh/peers`, and `FlowRecord.Where` value `"device-mesh"`; add `MeshCandidate` (`Addr`, `Kind`: `"lan"|"public"`), `MeshCandidatesRequest` (`WGPublicKey`, `MeshPort`, `Candidates`), `MeshPeer` (`DeviceID`, `UserID`, `DNSName`, `TunnelIPv4`, `TunnelIPv6`, `WGPublicKey`, `CertSerial`, `Candidates`), `MeshPeersResponse`, and `Endpoints map[string]string` (`json:"endpoints,omitempty"`) on `EdgeSessions`.
- **Proving tests:**
  - Extended `pkg/policy/mesh_test.go` (`MeshDirectLinks` default false / true compilation).
  - Extended `pkg/pqsession/pqsession_test.go` (`TestDeriveMeshPSK` matches both ends, differs from `DerivePSK`, binds key order/epoch, rejects non-PQ TLS).

### Step 2 — Store Schema & Migrations (SQLite and PostgreSQL)
- **Goal:** Add persistence for mesh candidates with TTL expiry and per-device Edge-observed public endpoints across both SQLite and PostgreSQL.
- **Files:**
  - `pkg/store/migrations/0021_mesh_candidates.sql` & `pkg/store/migrations/postgres/0021_mesh_candidates.sql`: create `mesh_candidates(device_id PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, tenant_id, wg_pub, mesh_port, candidates, updated_at, expires_at)` with index `(tenant_id, expires_at)`, and `ALTER TABLE edge_sessions ADD COLUMN endpoint TEXT NOT NULL DEFAULT ''`.
  - `pkg/store/mesh.go` (new): `UpsertMeshCandidates`, `ListMeshCandidates(ctx, tenantID, now)` (filters `expires_at > now` and `devices.revoked = 0`), `DeleteMeshCandidates`, `DeleteExpiredMeshCandidates(ctx, now)`.
  - `pkg/store/edges.go`: update `ReportEdgeSessions` to persist `endpoint` per `(edge_id, device_id)` and add `DeviceEndpoints(ctx, tenantID, since)` returning the freshest observed `ip:port` per active device.
  - `pkg/store/store.go`: delete `mesh_candidates` row inside `RevokeDevice`.
- **Proving tests:**
  - New `pkg/store/mesh_test.go` (runs under SQLite and `OPENSASE_TEST_POSTGRES`): upsert/overwrite, tenant isolation, expiry filtering and pruning, revocation cleanup, and Edge endpoint persistence/freshness.

### Step 3 — Edge Observed Public Endpoint Reporting
- **Goal:** Read each live WireGuard peer's observed outer UDP `ip:port` on the Edge and report it directly to the Control Plane in `POST /v1/edge/sessions` (Edge-authenticated so a client cannot spoof another peer's public endpoint).
- **Files:**
  - `internal/edge/session.go`: add `IpcGetOperation(io.Writer) error` to `wgConfigurer`; add a UAPI parser extracting `public_key` → `endpoint` while zeroing the buffer (`clear(buf.Bytes())`).
  - `internal/edge/edge.go`: map observed WG endpoints by `d.wgPub` to `deviceID` and include them in `api.EdgeSessions.Endpoints` inside `reportLoop`.
  - `internal/controlplane/hardening.go`: validate `netip.ParseAddrPort` on `Endpoints` entries in `handleEdgeSessions` (ignoring malformed/unspecified/loopback entries) and pass them to `ReportEdgeSessions`.
- **Proving tests:**
  - Extended `internal/edge/edge_test.go` (UAPI endpoint extraction, buffer wipe, `ReportSessions` populates `Endpoints`).
  - Extended `internal/controlplane/server_test.go` (`handleEdgeSessions` stores valid endpoints, rejects malformed ones, respects Private Edge tenant scope).

### Step 4 — Discovery API, `directLinks` Snapshot Propagation, and `device-mesh` Flows
- **Goal:** Expose `POST /v1/mesh/candidates` and `GET /v1/mesh/peers`, propagate `mesh.directLinks` in signed snapshots, and allow `"device-mesh"` flow records from devices.
- **Files:**
  - `internal/controlplane/mesh.go` (new): implement `handleMeshCandidates` (validate 32-byte non-zero Curve25519 `wgPublicKey`, valid `meshPort` with `meshPort < 65535`, ≤ 16 `ip:port` candidates rejecting loopback/unspecified/link-local/multicast/tunnel prefixes, rate-limit via `flowLimit`, upsert with 5 min TTL) and `handleMeshPeers` (return empty list when `!tp.Mesh.DirectLinks` or calling device is posture-restricted; return only same-tenant, non-revoked, non-restricted peers allowed with the caller in either direction by `tp.Mesh.Rules`; include tunnel IPs from `tunneladdr.AddrAt(d.TunnelOffset)`, `userId`, `certSerial`, LAN candidates, and Edge-observed public endpoint from `DeviceEndpoints`).
  - `internal/controlplane/server.go`: register `POST /v1/mesh/candidates` and `GET /v1/mesh/peers` under `r.Use(s.requireDevice)`; call `DeleteExpiredMeshCandidates` in `singletonJobs`.
  - `internal/controlplane/snapshot.go`: set `Snapshot.MeshDirectLinks = tp.Mesh.DirectLinks` in `compileDevices` (forced `false` when posture-restricted alongside `snapMesh = nil`).
  - `internal/controlplane/handlers.go`: in `handleFlows` for `PeerDevice`, preserve `rec.Where == "device-mesh"` and force all other values to `"device"` (preventing `"edge"`/`"cloud"` spoofing).
- **Proving tests:**
  - New `internal/controlplane/mesh_test.go`: mTLS device auth (unauthenticated/edge/revoked/superseded rejected), cross-tenant isolation, `directLinks: false` returns empty peers, policy filtering (allowed, asymmetric, excluded peer), posture-restricted device excluded, stale candidate expiry, bad candidate/key validation, `Snapshot.MeshDirectLinks` propagation, and `Where: "device-mesh"` preserved while `"edge"` spoof is overwritten.

### Step 5 — Receiving-Client Enforcement & `device-mesh` Flow Accounting (`pkg/firewall`)
- **Goal:** Build and prove receiving-client enforcement **before** any direct-link transport exists: enforce signed `Snapshot.MeshInbound` + `MeshDirectLinks` on inbound direct-link packets, emit `Where: "device-mesh"` from both sides, and drop non-tunnel-address traffic.
- **Files:**
  - `pkg/firewall/conntrack.go`: add `meshDirect bool`, `meshDevice string`, `meshUser string`, `meshDstPort uint16` to `entry` so policy hot-swaps re-check the exact peer and port, and `recordFor` knows direct-link flows.
  - `pkg/firewall/firewall.go`: add lock-free peer map (`SetMeshPeers(localV4, localV6 netip.Addr, peers []MeshPeerInfo)`) and `DirectInbound(pkt []byte) (pass bool, reject []byte)` that:
    - requires `ps != nil && ps.c.MeshDirectLinks()`, valid source in active direct peers, and `p.Dst` equal to local tunnel IPv4/IPv6 (blocks any Internet/transit traffic on direct links);
    - for new inbound flows (TCP SYN without ACK, UDP, ICMP/ICMPv6 echo), evaluates `ps.c.MeshAllows(peer.UserID, peer.DeviceID, proto, p.DstPort)`; on deny, records a blocked `"device-mesh"` flow and returns a TCP RST / ICMP unreachable to send back over the direct link;
    - updates `reevaluate` so established direct-link flows re-check `ps.c.MeshDirectLinks()` and `ps.c.MeshAllows(...)` on every snapshot update;
    - stamps `Where: "device-mesh"` in `recordFor` for both inbound direct-link flows and outbound flows whose destination is an active direct-link peer.
- **Proving tests:**
  - New `pkg/firewall/mesh_test.go`: user/device/all/port/protocol/`icmpv6` allow & block, RST/ICMP unreachable on deny, `MeshDirectLinks == false` drops all direct packets, non-tunnel destination dropped, snapshot hot-swap revoking a rule or `directLinks` terminates live flow, and both outbound and inbound direct flows record `Where: "device-mesh"`.

### Step 6 — Mutual Device PQ TLS Handshake & PSK Exchange (`pkg/pki`, `mobile/`)
- **Goal:** Implement peer-to-peer TLS 1.3 (`X25519MLKEM768`) PSK negotiation on port `mesh+1` with mutual device certificates, same-tenant + policy verification, and epoch rotation.
- **Files:**
  - `pkg/pki/identity.go`: add `VerifyDevicePeer(rawCerts [][]byte, root *x509.Certificate, wantTenant, wantDevice string, now time.Time) (Identity, error)` verifying `[leaf, tenant CA, root]` with `ExtKeyUsageClientAuth` (keeping `ServerAuth` off device certs) and checking `PeerDevice` SPIFFE URI.
  - `mobile/state.go`: parse and store `root *x509.Certificate` and `tenantCA *x509.Certificate` on `enrollment` from `resp.CAPEM`.
  - `mobile/mesh_tls.go` (new): PQ TLS 1.3 server (port `mesh+1`, `GetCertificate` reading `id.cert.Load()`, `RequireAndVerifyClientCert`, `VerifyConnection` verifying PQ + same tenant + allowed peer) and client (`GetClientCertificate`, `InsecureSkipVerify: true` strictly paired with `VerifyPeerCertificate`/`VerifyConnection` calling `pki.VerifyDevicePeer` + `pqsession.CheckPostQuantum`), JSON handshake exchange (`wgPublicKey`, `linkId`, `epoch`, `rotateAfterSeconds`), `pqsession.DeriveMeshPSK`, epoch rotation (0 / cur / cur+1), and `clear(psk[:])`.
- **Proving tests:**
  - Extended `pkg/pki/pki_test.go` (`TestVerifyDevicePeer`: valid same-tenant peer passes; cross-tenant, Edge/CP cert, wrong device ID, expired cert fail).
  - New `mobile/mesh_tls_test.go`: mutual PQ handshake derives identical PSK on both peers, classic TLS rejected, wrong tenant or disallowed peer rejected, epoch rotation updates PSK and wipes old PSK, certificate renewal hot-swaps seamlessly.

### Step 7 — Client Core Direct-Link Manager, Mesh WG Device & Path Choice (`mobile/`)
- **Goal:** Run the dedicated mesh WireGuard `device.Device` (separate key, `allowed_ip` limited strictly to each peer's `/32` and `/128` tunnel addresses), mux it with the Edge WG device through Step 5's receiving enforcement, and implement candidate reporting, LAN-first / public UDP hole punching with 5 s fallback and 2 min retry, and link rotation—all gated on `Compiled.MeshDirectLinks()`.
- **Files:**
  - `mobile/tunmux.go` (new): `tunMux` implementing `tun.Device` for `edgeDev` and `meshDev` above `FilteringTUN`: dispatches outbound packets to `meshDev` only when `p.Dst` is an active direct-link peer's tunnel IP (all other traffic—including Internet and fallback peers—goes to `edgeDev`), and routes every `meshDev` inbound packet through `FilteringTUN.DirectInbound` (writing any rejection packet back to `meshDev`).
  - `mobile/mesh.go` (new): mesh manager owning `meshDev` (fresh X25519 key, dedicated UDP `meshPort`, optional `fwmark` and `SocketControl` hooks for OS bypass), LAN address collector, candidate reporter (`POST /v1/mesh/candidates`), peer poller (`GET /v1/mesh/peers`), path chooser (try LAN candidates first, then public candidates with simultaneous sends for UDP hole punching; if no WG handshake completes within 5 s keep Edge path; retry every 2 min; tear down peer on stale handshake, policy removal, or `MeshDirectLinks == false`), and per-peer PSK rotation matching `RotateAfterSec`.
  - `mobile/engine.go`: attach `tunMux` and `mesh` manager to `runState` in `StartDevice`/`Stop`; add Go-only `SetMeshSocketHooks(fwmark uint32, dialCtrl, listenCtrl func(string, string, syscall.RawConn) error)` and `SetMeshPeerRoutesHook(func(add, remove []netip.Addr))`; expose `meshDirectPeers` count in `Status()`.
  - `mobile/loops.go`: signal the mesh manager from `installEnvelope` when `MeshDirectLinks` or `MeshInbound` changes so direct links start/stop promptly.
  - `mobile/api.go` (**CONTRACT CHANGE**): document the additive `meshDirectPeers` field in `Status()` JSON.
- **Proving tests:**
  - New `mobile/mesh_test.go`: two in-process `Engine`s on channel TUNs verify direct link setup when `directLinks: true` + rule present, UAPI `allowed_ip` contains only peer tunnel IPs, receiving client drops disallowed port and both sides emit `Where: "device-mesh"`, unreachable peer stays on Edge after 5 s timeout and retries, flipping `directLinks: false` tears down direct peers cleanly, and PSK rotation succeeds without dropping traffic.

### Step 8 — Linux Direct-Link Routing & Kill Switch Integration
- **Goal:** Allow marked mesh sockets (`SO_MARK` / `fwmark`) to reach LAN and public peer candidates without leaking unprivileged app traffic through the Linux nftables kill switch or looping into `/1` tunnel routes in table `main`.
- **Files:**
  - `internal/clientnet/clientnet.go`: add `MeshMark uint32` to `Config`.
  - `internal/clientnet/linux.go`: when `c.MeshMark != 0`, install and undo a dedicated physical routing table (e.g. table `51820` with the physical IPv4/IPv6 default gateways + `ip [-6] rule add fwmark <mark> lookup 51820` plus `suppress_prefixlength 0` or on-link LAN preference so LAN stays on-link while public candidates bypass `/1` tunnel routes), and expose a Linux `SO_MARK` socket-control helper (`CAP_NET_ADMIN` required, so unprivileged processes cannot spoof the mark).
  - `internal/clientnet/killswitch_linux.go`: when `meshMark != 0`, emit `meta mark <mark> accept` in `opensase_killswitch` `output` chain.
  - `cmd/opensase-client/main.go`: pass `MeshMark` in `clientnet.Config` and wire `eng.SetMeshSocketHooks` before `StartDevice`.
  - `internal/desktop/daemon.go`: add `SetMeshSocketHooks` to `desktop.Engine` (and `fakeEngine` in tests) and wire `MeshMark` on Linux in `Connect`.
- **Proving tests:**
  - Extended `internal/clientnet/linux_test.go` and `internal/clientnet/killswitch_linux_test.go` (dedicated `fwmark` table + policy rule + rollback, `meta mark` nft rule present only when `MeshMark != 0`).

### Step 9 — Windows Direct-Link Routing Integration
- **Goal:** Route public peer candidates outside Wintun on Windows (LAN candidates already use physical connected subnet routes, and WFP `permitOpenSASEService` at `internal/wfp/rules.go:137-277` already permits `opensased` sockets) with LIFO cleanup on disconnect.
- **Files:**
  - `internal/clientnet/routeplan.go`: add `planMeshPeerBypass(peers []netip.Addr, gw4, gw6 netip.Addr)` emitting deduplicated `/32` and `/128` physical bypass routes while excluding tunnel, loopback, and unspecified addresses.
  - `internal/clientnet/windows.go`: add a thread-safe dynamic peer-bypass updater (calling `gw.luid.AddRoute`/`DeleteRoute` and tracking installed peer routes on `rollbackStack` for disconnect cleanup).
  - `internal/desktop/daemon.go`: add `SetMeshPeerRoutesHook` to `desktop.Engine` and connect it on Windows to the dynamic peer-bypass updater, clearing the hook on `Disconnect`.
- **Proving tests:**
  - Extended `internal/clientnet/routeplan_test.go` (`TestPlanMeshPeerBypass` for v4/v6 public peers, filtering tunnel/loopback, deduplication).
  - Extended `internal/desktop/daemon_test.go` (hook invoked on connect and cleared on disconnect).

### Step 10 — Android Direct-Link Support
- **Goal:** Enable direct links on Android after Linux and Windows are verified: protect all mesh sockets via `VpnService.protect` and supply underlying-network LAN addresses from `ConnectivityManager.LinkProperties`.
- **Files:**
  - `mobile/api.go` (**CONTRACT CHANGE**): add `SetLocalAddrs(addrsJSON string) error` to `Engine` (gomobile-safe JSON `[]string` of local LAN IPs on the active physical network).
  - `mobile/mesh.go` & `mobile/mesh_tls.go`: use `newProtectedBind(e.protect, ...)` for `meshDev`, apply `e.protect` via `net.ListenConfig.Control` / `dialer(e.protect)` on mesh TLS sockets, and prefer `SetLocalAddrs` over `net.InterfaceAddrs()` when set (avoiding Android 11+ netlink restrictions) while triggering candidate refresh on network changes.
  - `clients/mobile/android/app/src/main/kotlin/eu/opensase/android/vpn/NetworkMonitor.kt`: collect non-loopback/non-link-local unicast addresses from `ConnectivityManager.getLinkProperties(network)`.
  - `clients/mobile/android/app/src/main/kotlin/eu/opensase/android/vpn/OpenSaseVpnService.kt`: push local LAN addresses to `g.engine.setLocalAddrs(...)` at connect and whenever `monitor.current` changes.
- **Proving tests:**
  - Extended `mobile/mesh_test.go` (`SetLocalAddrs` candidate selection and `Protect` called for mesh WG + TLS sockets, failing closed if `Protect` returns `false`).
  - Android unit test for `NetworkMonitor` link-address extraction (`./gradlew testDebugUnitTest`).

### Step 11 — E2E Tests, Security Tests, `THREAT_MODEL.md`, and Docs
- **Goal:** Verify direct path, Edge fallback path, unauthorized-peer isolation on both paths, and document the new trust boundary and threats.
- **Files:**
  - `deploy/dev/docker-compose.yml`: add `client2` on `default` (same network as `client` → direct path) and `client-edgeonly` on an isolated network attached only to `edge` and `controlplane` (no direct L3 path to `client` → Edge fallback).
  - `deploy/dev/e2e.sh`: add mesh direct-links section enabling `mesh.directLinks: true` + a port-scoped mesh rule: verify `client` ↔ `client2` connects directly (allowed port passes, disallowed port refused by receiving client, `Where: "device-mesh"` flow records from both devices), verify `client` ↔ `client-edgeonly` falls back to Edge after ~5 s and passes, and verify restoring `directLinks: false` tears down direct links.
  - `test/security/go/mesh_test.go` (new): add sectest (`SEC-DP-010`) with a narrow rule allowing only `devA1` → `devA2` on one port (`mesh.directLinks: true`), proving: (a) positive control `devA1` → `devA2` allowed port succeeds while a disallowed port fails; (b) a same-tenant device outside the rule (`devA3`) and a cross-tenant device (`devB1`) cannot reach `devA2` via the Edge path (RST/drop) **or** the direct path (omitted from `GET /v1/mesh/peers`, direct PQ TLS handshake on `mesh+1` rejected, raw UDP on `meshPort` dropped).
  - `THREAT_MODEL.md`: add entry points for mesh TLS (`mesh+1`) and mesh WireGuard UDP; add threats per ADR-0034 (compromised client accepts arbitrary inbound direct-link traffic and bypasses Edge inspection; candidate poisoning/peer enumeration via discovery API) with mitigations (`mesh.directLinks: false` default, receiving-client enforcement, sender-side firewall, PQ mTLS + tenant/policy check, candidate validation/TTL).
  - `docs/operations/mesh.md`: update "How traffic flows" for `mesh.directLinks`, direct vs Edge fallback, `device-mesh` flow records, and the inspection trade-off.
- **Proving tests:**
  - `deploy/dev/e2e.sh` (full dev stack green including direct + Edge-fallback mesh checks).
  - `test/security/run.sh` (`SEC-DP-010` passing alongside existing `SEC-DP-*`).

---

## Open Questions

ADR-0034 is silent on the following details; decide before implementing the referenced step:

1. **Observed NAT port vs separate mesh WireGuard socket (Steps 3, 7):** `wireguard-go` binds one private key and one UDP port per `device.Device`. With a separate mesh WG key/socket (`meshPort`), the UDP port the Edge observed on `wg0` is the Edge socket's NAT mapping, not `meshPort`'s NAT mapping. Should the Edge expose a small UDP echo on a known port so `meshDev`'s socket learns its own mapped public `ip:port`, or should 1.0 combine the Edge-observed public IP with `meshPort` (working only on port-preserving Cone NATs)?
2. **Peer `userId` and asymmetric outbound authorization (Steps 4, 6):** Device certs carry only `tenantId` and `deviceId` (`pkg/pki/pki.go:294`), and `Snapshot.MeshInbound` only encodes inbound grants (`pkg/policy/types.go:72`). Is using `GET /v1/mesh/peers` as the authenticated source for peer `userId` (needed by `MeshAllows`) and outbound pair authorization acceptable—meaning a peer unknown to the cached discovery list triggers a rate-limited refresh or fails—or should `userId` be added to device certs / outbound grants to `Snapshot`?
3. **Handshake framing and glare on port `mesh+1` (Step 6):** Should the TLS 1.3 exchange on `mesh+1` use HTTP/1.1 (`POST /v1/mesh/session`, mirroring `POST /v1/session`) or length-prefixed JSON with ALPN `"opensase-mesh/1"`, and when both peers initiate simultaneously should lexicographically smaller `deviceId` win?
4. **Exporter label separation (Step 1):** Confirm adding `pqsession.MeshExporterLabel` (`"EXPORTER-opensase-mesh-psk-v1"`) vs reusing `ExporterLabel` directly.
5. **Mesh listener port selection (Step 7):** Should `meshPort` default to a fixed port (e.g., UDP `51821`, TLS `51822`) with fallback on bind conflict, or an OS-assigned port $P$ retrying until $P+1$ TCP is also free?
6. **Revocation window on direct links (Steps 4, 6, 7):** Because the Edge is off-path, a revoked device's cert remains valid until its 24 h `NotAfter`. Confirm tearing down direct peers that drop out of `GET /v1/mesh/peers` (or whose `certSerial` changes) on each discovery poll (~1–2 min).
7. **Group and device-tag selectors (Step 4):** ADR-0034 mentions group/tag selectors, but `api.MeshSelector` (`pkg/api/types.go:750-754`) currently supports only `All`, `Users`, and `Devices`. Confirm keeping group/tag selectors out of issue #61's direct-link scope.

---

## Decisions (lead, 2026-11-28)

1. **Public endpoint:** 1.0 combines the Edge-observed public IP with the device's `meshPort`. This works behind port-preserving NATs only; every other case falls back to the Edge path after 5 s. LAN candidates are always tried first. A UDP mapping probe is out of scope for #61.
2. **Peer `userId`:** `GET /v1/mesh/peers` (device mTLS to the Control Plane) is the authenticated source of peer `userId` and of outbound pair authorization. A packet from a source not in the cached peer list triggers at most one refresh per 30 s; until then it is dropped. Device certificates are not changed.
3. **Handshake framing:** length-prefixed JSON over TLS 1.3 with ALPN `opensase-mesh/1`. On glare, the peer with the lexicographically smaller `deviceId` is the initiator; the other closes its outbound attempt.
4. **Exporter label:** a separate `MeshExporterLabel = "EXPORTER-opensase-mesh-psk-v1"`, so a direct-link PSK can never equal an Edge-session PSK.
5. **Ports:** default UDP `51821` and TCP `51822`. On a bind conflict, take an OS-assigned UDP port P and require TCP P+1 to be free, retrying up to 8 times.
6. **Revocation:** discovery polls every 60 s. A peer that leaves the list, or whose `certSerial` changes, is torn down on that poll. The mesh TLS handshake also rejects certificates whose serial differs from the discovery entry.
7. **Selectors:** group and device-tag selectors stay out of #61.

Contract changes in Steps 1, 7 and 10 are approved as listed.
