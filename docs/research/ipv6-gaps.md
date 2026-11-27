# Issue #74 Gap Analysis: End-to-End IPv6

**Scope:** Dual-stack tunnel addressing, policy matching for IPv6, Edge egress and DNS `AAAA` through the tunnel, and eliminating IPv6 leaks around the tunnel.

---

## Executive Summary

OpenSASE already has substantial IPv6 groundwork across packet parsing, policy compilation, tunnel address planning, client-side DNS filtering, Linux/Windows kill switches, and Android `VpnService` routing. However, **end-to-end IPv6 egress is deliberately disabled at the Edge kernel layer**, and several cross-family bugs, bypass-route omissions, and inspection/redirect gaps must be closed before enabling IPv6 forwarding.

| # | Area | Current State | Primary Risk | Effort |
|---|---|---|---|---|
| 1 | [Tunnel addressing](#1-tunnel-addressing) | Dual-stack `100.64.0.0/10` + `fd7a:5a5e::/64` works; `e.ipv6=false` response mismatch | **Breakage** (clients receive v6 tunnel IP when Edge has none) | **S** |
| 2 | [Client routes and leaks per platform](#2-client-routes-and-leaks-per-platform) | Split `::/1`+`8000::/1` and v6 kill switches exist; no v6 bypass routes; silent leak fallbacks | **Leak & Breakage** (v6 endpoint routing loops; v6 leaks when kill switch off / v6 setup fails) | **L** |
| 3 | [Client firewall and DNS](#3-client-firewall-and-dns) | IPv6 parse/build, link-local ICMPv6 drop, AAAA filter/snoop work; minor ICMPv6 quote & TCP/53 gaps | **Breakage & Bypass** (PMTU with ext headers; TCP/53 snoop miss) | **S** |
| 4 | [Edge forwarding and filter](#4-edge-forwarding-and-filter) | Built-in v6 deny + DoH IPs work; cross-family snoop bug, `icmpv6` protocol bug, v4-only DNS redirect & TLS inspection | **Bypass & Breakage** (domain rules bypassed cross-family; `icmpv6` rules never match; v6 web blocked under inspection) | **L** (M without v6 TLS inspection) |
| 5 | [Edge egress NAT](#5-edge-egress-nat) | `ip6tables FORWARD DROP` only; zero IPv6 NAT/forwarding/MSS rules; dev compose & Helm missing v6 sysctl/network | **Breakage & Leak** (no v6 egress; missing defence-in-depth `OSASE_FWD6` once enabled) | **M** |
| 6 | [Edge DNS resolver](#6-edge-dns-resolver) | Listens on `[fd7a:5a5e::1]:53`, handles `AAAA`, internal `AAAA`, SafeSearch `AAAA`; cross-family snoop & flow-log bugs | **Bypass & Breakage** (cross-family snoop miss; unreachable `AAAA` on v4-only Edges; wrong flow-log `DstIP`/`Protocol`) | **S** |
| 7 | [ZTNA and synthetic addresses](#7-ztna-and-synthetic-addresses) | Connector dials IPv6 backends; client-to-Edge synthetic path is 100% IPv4-only (`AAAA` returns empty NOERROR) | **Breakage** (IPv6-only clients cannot reach ZTNA; dual-stack works via v4 synthetic) | **M** (optional for dual-stack) |
| 8 | [Mesh](#8-mesh) | Edge filter, client `meshInbound`, and internal DNS `AAAA` support v6; Edge kernel drops v6 mesh; `mesh.go` lacks `icmpv6` | **Breakage** (all v6 mesh packets dropped in kernel; `icmpv6` breaks after `protoName` fix) | **S** |
| 9 | [Control Plane and policy](#9-control-plane-and-policy) | IPv6 CIDRs, internal `AAAA`, posture snapshot, cloud decide work; `compileDecide` normalization & routed v6 subnets missing | **Bypass & Breakage** (v4-mapped CIDR miss in cloud decide; v6 workload routes rejected) | **S** (M with v6 workload routes) |
| 10 | [Tests](#10-tests) | Strong `pkg/packet` & `pkg/policy` v6 unit tests; security tests actively assert v6 egress fails; zero v6 E2E coverage | **Breakage & Blind Spot** (`SEC-DP-103` and `SEC-DP-009` will fail once v6 egress works; regressions undetected) | **M** |

**Effort scale:** `S` = < 1 day, `M` = 1–3 days, `L` = 3–7 days.

---

## 1. Tunnel Addressing

### What already works for IPv6
- **Shared dual-stack address plan (`pkg/tunneladdr/tunneladdr.go:14-38`):** Defines `Prefix4 = 100.64.0.0/10`, `Prefix6 = fd7a:5a5e::/64`, `EdgeIPv4 = 100.64.0.1`, `EdgeIPv6 = fd7a:5a5e::1`, and `AddrAt(off)` which maps a single `uint32` host offset to both IPv4 and IPv6 (`b6[12..15] = off`).
- **Control Plane persistent offsets (`pkg/store/store.go:349-390, 425-429`, `internal/controlplane/handlers.go:504`):** Every enrolled device receives a stable `TunnelOffset` distributed in `EdgeDevice.TunnelOffset`, keeping both IPv4 and IPv6 addresses constant across Edge failovers.
- **Edge dual-stack registry and interface (`internal/edge/registry.go:22-27, 46-47, 150-152, 166-209`, `internal/edge/edge.go:401-406`):** Edge allocates and indexes both `d.ip4` and `d.ip6` in `byIP`, assigns `fd7a:5a5e::1/64` with `nodad` on `wg0`, and sets `e.ipv6 = true`.
- **WireGuard peer and session plumbing (`internal/edge/session.go:225-227, 257-287`, `mobile/session.go:171`, `docs/adr/0002-client-tunnel-wireguard-pq-psk.md:28-55`):** Edge configures `allowed_ip=<ip4>/32` and `allowed_ip=<ip6>/128` per peer; `SessionResponse` carries `TunnelIPv4` and `TunnelIPv6`; client WireGuard UAPI sets `allowed_ip=0.0.0.0/0` and `allowed_ip=::/0`.

### What is missing or wrong
1. **Unconditional `TunnelIPv6` and `allowed_ip` when `e.ipv6 == false` (`internal/edge/session.go:218-227, 257-287`):**
   - `e.ipv6` gates `EdgeIPv6` in `DNSServers` (lines 218–221), but `SessionResponse.TunnelIPv6` is always populated (line 226) and `writePeerConfig` / `writePeerAllowedIPs` always install `allowed_ip=<ip6>/128` (lines 264–266, 279–281). If the Edge failed to assign `fd7a:5a5e::1/64` (or has IPv6 egress disabled), clients still install `fd7a:5a5e::x/128` and IPv6 default routes into a tunnel whose Edge has no IPv6 address.
   - **Change needed:** Gate `TunnelIPv6` and the peer IPv6 `allowed_ip` on `e.ipv6` (and ensure clients still prevent IPv6 leaks when `TunnelIPv6 == ""`; see Area 2).
2. **`e.ipv6` checks local interface address only, not IPv6 forwarding or WAN egress (`internal/edge/edge.go:401-406`):**
   - `configureInterface` sets `e.ipv6 = true` as soon as `ip -6 addr replace fd7a:5a5e::1/64 dev wg0 nodad` succeeds, even when `net.ipv6.conf.all.forwarding=0` or the Edge has no IPv6 WAN default route (as in the current dev container stack).
   - **Change needed:** Separate local IPv6 capability from IPv6 egress readiness (e.g., check `/proc/sys/net/ipv6/conf/all/forwarding` and an explicit `-ipv6-egress` / auto-detected IPv6 WAN default route), and expose the state on `/metrics` and startup logs.
3. **Observability omissions (`internal/edge/session.go:129-130`, `mobile/loops.go:606-611`):**
   - Edge logs `"ipv4"` only on session establishment; client detects `TunnelIPv6` changes on session reset (line 606) but logs only `old`/`new` IPv4 (line 611).
   - **Change needed:** Include `"ipv6"` in both log statements.
4. **Hardcoded ULA prefix and synthetic-range reservation (`pkg/tunneladdr/tunneladdr.go:16, 42-48`, `pkg/policy/types.go:172`):**
   - `Prefix6` is hardcoded to `fd7a:5a5e::/64` (suitable for NAT66; operators with a routed global IPv6 prefix cannot override it). `Usable(off)` only checks IPv4 `synthetic` overlap (safe as long as any future IPv6 synthetic prefix lives outside `fd7a:5a5e::/64`, e.g. `fd7a:5a5e:1::/64`). Also, the comment at `pkg/policy/types.go:172` erroneously states `100.64.0.0/16` instead of `100.64.0.0/10`.
   - **Change needed:** Fix the doc comment in `pkg/policy/types.go:172`; document ULA-only NAT66 vs optional future configurable `Prefix6` / NPTv6.

### Risk & Effort
- **Risk:** **Breakage** (silent IPv6 blackholing when an Edge runs without IPv6 kernel support or without IPv6 WAN egress).
- **Effort:** **S**.

---

## 2. Client Routes and Leaks per Platform

### Linux (`internal/clientnet/linux.go`, `killswitch_linux.go`, `cmd/opensase-client/`)

#### What already works for IPv6
- **Dual-stack tunnel addressing and split default routes (`internal/clientnet/linux.go:43-45, 73-76`):** Assigns `-6 address replace <ipv6> dev <dev>` and installs `::/1` and `8000::/1` via the TUN device when `c.IPv6 != ""`.
- **Dual-stack nftables kill switch (`internal/clientnet/killswitch_linux.go:25-53`):** Creates `table inet opensase_killswitch` with `hook output` policy `drop`, allowing `lo`, `tunDev`, resolved IPv4 and IPv6 bypass addresses (`ip6 daddr { ... } accept` via `resolveAllow` using `"ip"`, lines 56–72), DHCPv4 (`68->67`), DHCPv6 (`546->547`), and outbound NDP (`nd-router-solicit`, `nd-neighbor-solicit`, `nd-neighbor-advert`).
- **Dual-stack `systemd-resolved` DNS (`internal/clientnet/linux.go:165-190`):** Passes all `c.DNS` entries (IPv4 and IPv6) to `resolvectl dns <dev>`, sets routing domain `~.` and `default-route yes`, and reverts on disconnect.

#### What is missing or wrong
1. **No IPv6 bypass host routes and hard dependency on IPv4 default gateway (`internal/clientnet/linux.go:48-70, 80-101`):**
   - `defaultGateway` runs `ip -4 route show default` only and returns an error (`"no IPv4 default route..."`, line 98) on IPv6-only hosts.
   - Even on dual-stack hosts, lines 61–68 filter `if ip4 := ip.To4(); ip4 != nil`, discarding every IPv6 address returned by `LookupIP(ctx, "ip", h)`. If the Edge or Control Plane uses an IPv6 address (or resolves to `AAAA`), no `/128` bypass route via the physical IPv6 gateway is installed; traffic to the Edge/Control Plane loops into `::/1` / `8000::/1` and breaks the tunnel.
   - **Change needed:** Add `defaultGateway6(ctx)` (`ip -6 route show default`), emit `ip -6 route replace <ip6>/128 via <gw6> dev <gwDev6>` (or `dev <gwDev6>` for on-link gateways) for every resolved IPv6 bypass address (deduplicated), and require at least one default gateway (v4 or v6) rather than mandating IPv4.
2. **Silent IPv6 setup failure causes IPv6 leaks when kill switch is off (`internal/clientnet/linux.go:30, 44, 74-75, 126`):**
   - All `-6` `ip` commands are marked `optional: true`. If `c.IPv6 == ""` or `-6 route replace` fails, `configurePlatform` logs a warning and leaves the physical IPv6 default route untouched. When `disableKillSwitch: true` (or in `opensase-client`), all IPv6 traffic leaks around the tunnel.
   - **Change needed:** If IPv6 is enabled in the kernel (`net.ipv6.conf.all.disable_ipv6 == 0`) and `c.IPv6 == ""` (or `-6 address/route` fails), install unreachable/blackhole split routes (`ip -6 route replace unreachable ::/1` and `unreachable 8000::/1`, preserving `/128` bypass routes) or fail closed unless the kill switch is active.
3. **Headless CLI never enables the kill switch (`cmd/opensase-client/main.go:230-237`):**
   - Unlike `internal/desktop/daemon.go:251` (`KillSwitch: d.eng.KillSwitch()`), `cmd/opensase-client/main.go:230-237` never sets `netCfg.KillSwitch`. Headless Linux clients (including the E2E/security client container) therefore run without nftables leak protection.
   - **Change needed:** Populate `KillSwitch: eng.KillSwitch()` (with a CLI override flag if container environments lack `nft` privileges).
4. **DNS leak on systems without `systemd-resolved` (`internal/clientnet/linux.go:136-143, 165-168`):**
   - If `resolvectl` is absent, Linux leaves `/etc/resolv.conf` untouched and only prints a stderr hint (line 141). On hosts with IPv6 RDNSS/DHCPv6 or local resolvers, AAAA queries either leak around the tunnel (kill switch off) or fail completely (kill switch on).
   - **Change needed:** Add a managed `/etc/resolv.conf` fallback (backup and restore on `undo`, writing both tunnel IPv4 and IPv6 nameservers) or require `resolvconf` / `systemd-resolved`.
5. **Bypass routes are never removed on disconnect (`internal/clientnet/linux.go:117-145`):**
   - `undo` reverts `resolvectl` and deletes the nftables table, but never deletes the `/32` (and new `/128`) bypass host routes installed on the physical interface.
   - **Change needed:** Track installed bypass routes (both v4 and v6) and run `ip [-6] route del ...` in `undo` (and on partial setup error).
6. **Kill switch covers `output` hook only (`internal/clientnet/killswitch_linux.go:39`):**
   - On hosts with IP forwarding enabled (containers, routers, VMs), forwarded IPv6 packets bypass `hook output`.
   - **Change needed:** Add a `chain forward { type filter hook forward priority 0; policy drop; oifname "<tun>" accept; iifname "<tun>" accept; }` when not in gateway mode (or document host-forwarding scope).
7. **Workload Gateway mode is IPv4-only (`cmd/opensase-client/gateway.go:38-40, 55-85, 184-197`, `cmd/opensase-client/geneve.go:373-387, 447`):**
   - Explicitly rejects IPv6 CIDRs (`!p.Addr().Is4()`), enables only `net.ipv4.ip_forward`, installs only `iptables` rules, and `geneveIngress` drops `hdr.Protocol != geneve.ProtoIPv4` and `pkt.Version != 4`.
   - **Change needed:** Out of scope for personal-client #74 MVP, but must be tracked if workload gateways carry IPv6 (enable `net.ipv6.conf.all.forwarding`, `ip6tables` rules, and `geneve.ProtoIPv6` `0x86DD` in `geneve.go`).

### Windows (`internal/clientnet/windows.go`, `routeplan.go`, `internal/wfp/`)

#### What already works for IPv6
- **Wintun IPv6 interface, split routes, and DNS (`internal/clientnet/windows.go:132-139, 150-157, 159-179, 256-259`, `internal/clientnet/routeplan.go:55-70`):** Configures `AF_INET6` MTU and metric `1`, assigns `/128` via `SetIPAddressesForFamily`, sets `AF_INET6` DNS via `SetDNS`, installs `::/1` + `8000::/1` into Wintun when `c.IPv6 != ""`, and flushes IPv6 routes and DNS on teardown.
- **Full IPv6 WFP kill switch (`internal/wfp/rules.go:89-123, 229-263, 342-403, 469-503, 611-973, 1086-1120, 1208-1365`, `internal/wfp/blocker.go:100-198`):** Installs `FWPM_LAYER_ALE_AUTH_CONNECT_V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6` filters permitting TUN, service SID, resolved IPv6 bypass IPs, `::1` loopback, DHCPv6 (`546`/`547`), and NDP (ICMPv6 types `133`–`137`), blocking all other IPv6 at weight 0, and blocking port-53 DNS over IPv6 at weight 14 except `DNSServers` at weight 15.

#### What is missing or wrong
1. **No IPv6 physical gateway lookup or `/128` bypass routes (`internal/clientnet/windows.go:58-91, 116-119`, `internal/clientnet/routeplan.go:19-38`):**
   - `findPhysicalDefaultGateway` queries `winipcfg.GetIPForwardTable2(windows.AF_INET)` only and fails with `"no IPv4 default route found"` on IPv6-only networks.
   - `windowsRoutePlan` skips `!ip.Is4()` (lines 25–27) even though `windows.go:183, 229` resolves both IPv4 and IPv6 into `bypassIPs` and passes IPv6 addresses to WFP `permitBypass`. Any IPv6 Edge/Control Plane endpoint therefore has no `/128` physical route and loops into Wintun `::/1` + `8000::/1`.
   - **Change needed:** Add `AF_INET6` physical default gateway discovery (`findPhysicalDefaultGateways` returning optional v4 and v6 `(LUID, ifIndex, nextHop)`), extend `windowsRoutePlan` to accept both `gw4` and `gw6` and emit `/128` bypass routes via `gw6`, and succeed when at least one family has a physical default gateway.
2. **IPv6 leak when `c.IPv6 == ""`, kill switch disabled, or daemon crashes (`internal/clientnet/windows.go:150-157, 221-242`, `routeplan.go:55-70`, `internal/wfp/blocker.go:60`, `docs/adr/0032-windows-client.md:105-106`, `THREAT_MODEL.md:65`):**
   - If `c.IPv6 == ""` (or `SetIPAddressesForFamily(AF_INET6)` fails—silently ignored with a warning at line 154!), `windowsRoutePlan` omits `::/1` and `8000::/1`. When `KillSwitch` is off—or if `opensased` crashes, because WFP uses `FWPM_SESSION_FLAG_DYNAMIC` (`blocker.go:60`) which immediately removes all filters on process exit—IPv6 leaks via the physical NIC.
   - **Change needed:** Treat IPv6 address/DNS configuration failure as an error when `c.IPv6 != ""` (or roll back cleanly); when `c.IPv6 == ""`, still block physical IPv6 via WFP (already covered when kill switch is on) or install sink routes into Wintun when kill switch is off; evaluate persistent/boot-time WFP sublayer cleanup vs crash-leak window documented in `THREAT_MODEL.md:65`.
3. **Partial error cleanup missing during route installation (`internal/clientnet/windows.go:198-219`):**
   - If `tunLUID.AddRoute` fails on `::/1` or `8000::/1` (line 209), already-installed bypass routes and adapter DNS are leaked without rollback (cleanup only runs if `wfp.Enable` fails at lines 231–239).
   - **Change needed:** Run the same rollback helper on any error after interface/route configuration starts.
4. **Windows DNS leak (SMHNR) when kill switch is off (`internal/clientnet/windows.go:170-179`):**
   - `SetDNS` passes `domains = nil` (no root `.` search / NRPT policy). When `KillSwitch` is false, Windows Smart Multi-Homed Name Resolution can race `AAAA`/`A` queries against physical interface IPv6 RDNSS/DHCPv6 DNS servers.
   - **Change needed:** Pass `[]string{"."}` or configure an NRPT catch-all rule pointing to `dns4`/`dns6` so non-kill-switch sessions do not leak DNS to physical NIC resolvers.
5. **WFP `blockDNS` overrides `permitTunInterface` (`internal/wfp/rules.go:89-123, 1208-1242`, `internal/wfp/blocker.go:150-165`):**
   - `blockDNS` uses weight `14`, higher than `permitTunInterface` (`12`), blocking port-53 IPv4 and IPv6 queries to non-tunnel resolvers before they enter the TUN. This blocks Edge `dns.redirectQueries` on Windows when kill switch is active (strictly leak-safe, but breaks forced DNS redirection for apps with hardcoded resolvers).
   - **Change needed:** Scope `blockDNS` to non-TUN interfaces (or lower its weight below `permitTunInterface` when the Edge policy has `dns.redirectQueries` enabled, while keeping physical-interface port 53 blocked).

### Android & Shared Mobile Core (`clients/mobile/android/`, `mobile/`)

#### What already works for IPv6
- **Dual-stack `VpnService.Builder` (`clients/mobile/android/app/src/main/kotlin/eu/opensase/android/vpn/OpenSaseVpnService.kt:154-168`):** Adds both `cfg.ipv4` and `cfg.ipv6`, installs full default routes `0.0.0.0/0` and `::/0`, configures all `cfg.dns` entries, sets MTU `1280`, and excludes its own package via `addDisallowedApplication(packageName)` so outer WireGuard/session sockets never loop.
- **Dual-stack socket protection (`mobile/platform.go:23-61`):** Protects both IPv4 and IPv6 WireGuard UDP sockets (`PeekLookAtSocketFd4` and `PeekLookAtSocketFd6`) via Android's `VpnService.protect`.
- **Dual-stack UID ownership lookup (`clients/mobile/android/app/src/main/kotlin/eu/opensase/android/core/PlatformBridge.kt:36-48`):** Resolves IPv4 and IPv6 numeric literals via `InetAddress.getByName` for `ConnectivityManager.getConnectionOwnerUid`.

#### What is missing or wrong
1. **Empty `cfg.ipv6` handling in `VpnService.Builder` (`OpenSaseVpnService.kt:157-160`):**
   - Once the Edge omits `TunnelIPv6` when `!e.ipv6` (Area 1), `parseCidr(cfg.ipv6)` returns `null`, so `addAddress` is skipped for IPv6 while `b.addRoute("::", 0)` (line 159) is still called. Depending on Android version, routing `::/0` without an IPv6 interface address can throw `IllegalArgumentException` or fail to capture IPv6 (leaking on IPv6 cellular/Wi-Fi).
   - **Change needed:** When `cfg.ipv6` is empty, assign a link-local/ULA sink address (e.g. `fd7a:5a5e::ffff/128`) alongside `addRoute("::", 0)` (or omit `allowFamily(AF_INET6)` only after verifying `VpnService` blocks unallowed families on all target API levels—Android API 21+ blocks unallowed families only when `allowBypass` is false and another family is added, so explicitly blackholing via `::/0` + sink address is deterministic and safe).
2. **Outer WireGuard endpoint hard-prefers IPv4 (`mobile/session.go:143-149`):**
   - `resolveEndpoint` always picks the first IPv4 address if DNS returns both `A` and `AAAA`. On IPv6-only mobile networks (where IPv4 has no route or broken CLAT), WireGuard UDP stalls even though the Edge is reachable via `AAAA`.
   - **Change needed:** Prefer the address family that succeeded for the TLS session-setup connection (or try IPv6/IPv4 via Happy Eyeballs / family-matched lookup) before falling back.

### Risk & Effort
- **Risk:** **Leak & Breakage** — High. Missing IPv6 bypass routes break dual-stack/IPv6-only Edge connections; optional `-6` commands on Linux, missing kill switch in `opensase-client`, and ignored IPv6 errors / SMHNR on Windows allow IPv6 leaks around the tunnel.
- **Effort:** **L** (cross-platform: Linux, Windows + WFP, Android, and shared `mobile/`).

---

## 3. Client Firewall and DNS

### What already works for IPv6
- **IPv6 packet parsing and rejection (`pkg/packet/packet.go:128-247`, `pkg/packet/build.go:28-179`):** Zero-allocation parsing of IPv6 headers, Hop-by-Hop (`0`), Routing (`43`), Fragment (`44`), and Destination Options (`60`) up to 8 headers; extracts ports and ICMPv6 type/code/echo ID (`128`/`129`). `BuildTCPReset` and `BuildICMPUnreachable` (ICMPv6 type 1 code 1, capped at 1280 bytes per RFC 4443) compute valid IPv6 pseudo-header checksums.
- **Silent link-local ICMPv6 drop (`pkg/firewall/firewall.go:386-419`):** Drops MLD/NDP (`130`–`137`, `143`) and link-local/multicast ICMPv6 before policy evaluation so OS chatter never pollutes flow logs or injects errors.
- **IPv6 flow construction, conntrack, and inbound ICMPv6 errors (`pkg/firewall/firewall.go:640-673, 804-843`, `pkg/firewall/conntrack.go:68-69`):** Sets `Protocol = "icmpv6"` for `ProtoICMPv6`, unmaps `DstIP`, tracks `ProtoICMPv6` idle timeout, and accepts inbound ICMPv6 error messages (`ICMPType < 128`, e.g. Packet Too Big type 2) matching tracked outbound TCP/UDP flows.
- **Client-side `AAAA` DNS filtering and snooping (`pkg/dnsfilter/dnsfilter.go:155-229`, `pkg/dnsfilter/udp.go:18-77`, `pkg/dnsfilter/cache.go:29-63`):** Blocks `AAAA` with `NXDOMAIN` or `::` (`blockResponse == "zero"`), constructs valid IPv6 UDP replies with IPv6 pseudo-header checksums, and snoops both `*dns.A` and `*dns.AAAA` into `domainCache` keyed by `netip.Addr` (so cross-family queries work on the client).

### What is missing or wrong
1. **`quotedFlowKey` ignores IPv6 extension headers and non-TCP/UDP quotes (`pkg/firewall/firewall.go:823-827`):**
   - For inbound ICMPv6 errors (such as Packet Too Big for PMTU discovery), `quotedFlowKey` reads `rest[6]` directly as the transport protocol and `rest[40:]` as the transport header, without walking extension headers, and returns `false` for quoted ICMPv6 echo flows.
   - **Change needed:** Reuse `packet.Parse` (or a lenient prefix parser) on `rest` to walk IPv6 extension headers and extract `FlowKey` for TCP, UDP, and ICMPv6 echo.
2. **Client DNS interceptor handles UDP/53 only (`pkg/firewall/firewall.go:675-689`):**
   - `isDNS` requires `p.Protocol == packet.ProtoUDP && p.DstPort == 53`. Truncated responses (common with dual-stack `AAAA` + `HTTPS`/`SVCB` + DNSSEC) that retry over TCP/53 bypass `pkg/dnsfilter` blocking and snooping on the client (the Edge resolver still enforces DNS policy, but client-side `Match.Domains` rules miss TCP-resolved IPv6 addresses).
   - **Change needed:** Document TCP/53 fallback as Edge-enforced, or add lightweight TCP/53 stream snooping if client-only domain rules must match TCP-resolved `AAAA` records.
3. **Authentication Header (51) stops extension-header walking (`pkg/packet/packet.go:144-175`):**
   - Packets carrying IPv6 AH (`51`) stop at protocol `51` and are treated as unknown protocol. Low real-world impact inside a WireGuard tunnel, but worth noting alongside RFC 8200 header handling.
   - **Change needed:** Optional: skip AH (`length = (hdr[1]+2)*4`) in `parseIPv6` if AH-encapsulated traffic is ever expected.
4. **Protocol label divergence with Edge (`pkg/firewall/firewall.go:653-654` vs `internal/edge/filter.go:163-164`):**
   - Client sets `Protocol = "icmpv6"` while Edge sets `"icmp"` (see Area 4); client is correct and Edge must align with it.

### Risk & Effort
- **Risk:** **Breakage** (low–medium: PMTU drops on packets with IPv6 extension headers; missed client-side domain match after TCP/53 fallback).
- **Effort:** **S**.

---

## 4. Edge Forwarding and Filter

### What already works for IPv6
- **Built-in IPv6 deny and DNS-bypass guard (`internal/edge/guard.go:30-57, 75-109`):** Denies `fe80::/10`, `::1/128`, `::/128`, `ff00::/8`, `fc00::/7` (unless `AllowPrivate`), all Edge host IPv6 interface addresses (`hostAddrs()`), third-party port `53`/`853` over IPv6, and built-in public IPv6 DoH addresses (lines 52–53).
- **IPv6 packet filter primitives (`internal/edge/filter.go:169-181, 202, 233-244, 324-326, 394-410`):** Recognizes ICMPv6 echo request (`128`) and ICMPv6 errors (`1`–`4`, allowing PMTU inbound), treats `EdgeIPv6` as local (DNS + ping only, rejecting all other ports), and generates valid IPv6 TCP RST / ICMPv6 unreachable rejections.
- **SNI and HTTP Host peeking (`internal/edge/web.go:66-131`):** Operates on TCP payload bytes independently of IP version, so SNI/Host SaaS, category, and SafeSearch enforcement work for IPv6 TCP flows once forwarded.

### What is missing or wrong
1. **BUG — Cross-family DNS `snoop` cache miss (`internal/edge/state.go:115, 130-159`, `internal/edge/dns.go:151, 265`, `internal/edge/safesearch.go:101`, `internal/edge/filter.go:241`):**
   - `snoopKey` is `{client netip.Addr, ip netip.Addr}`. When a dual-stack client queries `AAAA` over IPv4 (`100.64.0.x -> 100.64.0.1`), `dns.go:151` stores `(100.64.0.x, <dst_v6>)`. When the client then opens a flow over IPv6 from `fd7a:5a5e::x` to `<dst_v6>`, `filter.go:241` looks up `(fd7a:5a5e::x, <dst_v6>)` and **misses** (and symmetrically for `A` queried over IPv6 followed by an IPv4 connection). This **bypasses Edge `Match.Domains` firewall rules and domain-based DoH blocking** (`guard.go:103`).
   - **Change needed:** Change `snoopKey` to `{deviceID string, ip netip.Addr}`, pass `d.id` from `dns.go:151, 265`, `safesearch.go:101`, and `filter.go:241`, and sweep by live device ID instead of tunnel IP (`edge.go` sweep loop).
2. **BUG — `protoName` collapses ICMPv6 to `"icmp"` (`internal/edge/filter.go:163-164`):**
   - `case packet.ProtoICMP, packet.ProtoICMPv6: return "icmp"`. Because `pkg/policy/evaluate.go:419-420, 670-671` maps `"icmpv6"` exclusively to `protoICMPv6` (while `"icmp"` matches both), **any tenant/user firewall rule matching `protocols: ["icmpv6"]` never matches on the Edge**, and Edge flow logs mislabel ICMPv6 as `"icmp"`.
   - **Change needed:** Return `"icmpv6"` for `packet.ProtoICMPv6` in `filter.go:163-164`, replace `proto == "icmp"` / `proto != "icmp"` checks at `filter.go:227, 235, 242, 292, 362, 366` with an `isICMP(proto)` helper (`proto == "icmp" || proto == "icmpv6"`), and update `pkg/policy/mesh.go` (Area 8) in the same commit.
3. **Forced DNS redirection (`dns.redirectQueries`) is IPv4-only (`internal/edge/filter.go:247`, `internal/edge/edge.go:439-443, 465-483`):**
   - `filter.go:247` gates `RuleDNSRedirect` on `dst.Is4()`, and `redirectDNS` / `ensureRedirect` invoke `iptables` only. IPv6 port-53 queries to external resolvers are blocked rather than redirected.
   - **Change needed:** Generalize `ensureRedirect` to accept `iptables` vs `ip6tables`; when `e.ipv6`, install `ip6tables -t nat PREROUTING -i <tun> -p udp/tcp --dport 53 ! -d fd7a:5a5e::1 -j DNAT --to-destination [fd7a:5a5e::1]:53` and change `filter.go:247` from `dst.Is4()` to `(dst.Is4() || f.e.ipv6)`.
4. **TLS inspection and web rules explicitly block IPv6 and are IPv4-only (`internal/edge/inspect.go:322, 899-909`, `internal/edge/edge.go:455-461, 486-497`, `internal/edge/redirect.go:28-136`, `internal/edge/origdst_linux.go:13-40`):**
   - `webBlockRule` (`inspect.go:903-906`) blocks IPv6 TCP/443 (when `InspectEnabled`) and TCP/80 (when `InspectEnabled || HasWebRules`) with `web:ipv6`, forcing fallback to IPv4.
   - `upstreamOK` (`inspect.go:322`) checks `!TunnelPrefix4.Contains(a)` and `!SyntheticPrefix.Contains(a)` but **omits `!TunnelPrefix6.Contains(a)`**.
   - `startInspect` (`edge.go:490`) binds `"tcp4"` only; `redirect.go` manages IPv4 `iptables` `OSASE_INSPECT` rules for `d.ip4/32` only; `origdst_linux.go:13-40` calls `IPPROTO_IP` `SO_ORIGINAL_DST` only and rejects non-`AF_INET` connections.
   - **Change needed (two options):**
     - *Short-term (minimal fix for #74 if v6 inspection is deferred):* Keep `webBlockRule` blocking IPv6 80/443 only for devices that actually enable `InspectEnabled`/`HasWebRules` (already scoped per device), AND add `!TunnelPrefix6.Contains(a)` to `upstreamOK` (`inspect.go:322`).
     - *Full IPv6 web inspection:* Bind `startInspect` on `"tcp"` (`:<port>`), add `IPPROTO_IPV6` `IP6T_SO_ORIGINAL_DST` (`80`, 28-byte `RawSockaddrInet6`) to `origdst_linux.go`, duplicate per-device `OSASE_INSPECT6` management via `ip6tables` for `d.ip6/128` in `redirect.go`, add `OSASE_IN6` conntrack DNAT accepts in `edge-entrypoint.sh`, and remove the two IPv6 cases in `webBlockRule` (`inspect.go:903-906`) once `ip6tables` inspection redirect is active.
5. **Startup forwarding check is IPv4-only (`internal/edge/ipforward_linux.go:12-25`, `internal/edge/edge.go:287-291`):**
   - Only reads `/proc/sys/net/ipv4/ip_forward`; never inspects `/proc/sys/net/ipv6/conf/all/forwarding`.
   - **Change needed:** Read `/proc/sys/net/ipv6/conf/all/forwarding` (and optionally check for an IPv6 default route) to drive `e.ipv6` / warn clearly when IPv6 forwarding is disabled.
6. **Built-in deny list missing special IPv6 ranges (`internal/edge/guard.go:30-40`):**
   - `alwaysDenied` omits NAT64 prefixes `64:ff9b::/96` (RFC 6052) and `64:ff9b:1::/48` (RFC 8215)—which could let a tunnel client pivot to private IPv4 or cloud metadata through an upstream NAT64 translator—and `100::/64` (RFC 6666 discard-only). `privateRanges` omits `2001:2::/48` (RFC 5180 IPv6 benchmarking equivalent of `198.18.0.0/15`).
   - **Change needed:** Add `64:ff9b::/96`, `64:ff9b:1::/48`, and `100::/64` to `alwaysDenied`, and `2001:2::/48` to `privateRanges` (mirror in `edge-entrypoint.sh`).
7. **Kernel routes for routed workload subnets are IPv4-only (`internal/edge/kroutes.go:58-62, 99, 109`):**
   - Filters `p.Addr().Is4()` and runs `ip route` without `-6`.
   - **Change needed:** When IPv6 workload routes are supported, accept `p.Addr().Is6()` and prepend `"-6"` for IPv6 prefixes.

### Risk & Effort
- **Risk:** **Bypass & Breakage** — High. Cross-family snoop miss silently bypasses Edge domain rules and domain-based DoH blocks; `protoName` silently breaks `icmpv6` firewall rules; missing NAT64 deny enables potential SSRF/pivot on NAT64 networks.
- **Effort:** **M** for filter/snoop/guard/DNS-redirect fixes; **L** including full IPv6 TLS inspection (`origdst_linux.go` + `ip6tables` `OSASE_INSPECT6`).

---

## 5. Edge Egress NAT

### What already works for IPv6
- **Container packages (`deploy/dev/Dockerfile.edge:11`, `deploy/release/Dockerfile.edge:18`):** Both images install `iptables` (which provides `ip6tables` / `iptables-nft`) and `iproute2`.
- **Tunnel `INPUT` protection (`deploy/dev/edge-entrypoint.sh:15, 119-130`):** Already defines `EDGE_IP6="fd7a:5a5e::1"`, sets `ip6tables -P FORWARD DROP`, and installs `OSASE_IN6` on `INPUT -i $TUN` allowing `RELATED,ESTABLISHED`, DNS (UDP/TCP 53), and `ipv6-icmp` to `EDGE_IP6`, dropping all else.
- **Helm `initContainer` sysctl (`deploy/helm/opensase-edge/templates/deployment.yaml:28`):** Already runs `sysctl -w net.ipv4.ip_forward=1 && sysctl -w net.ipv6.conf.all.forwarding=1 || true`.

### What is missing or wrong
1. **No IPv6 NAT, MSS clamping, or `OSASE_FWD6` forwarding rules (`deploy/dev/edge-entrypoint.sh:118-130, 139`):**
   - Lines 118–130 explicitly disable IPv6 forwarding (`# --- IPv6 (no IPv6 NAT in dev: nothing is forwarded) ---`). There is no `POSTROUTING` MASQUERADE, no `TCPMSS --clamp-mss-to-pmtu`, and no `OSASE_FWD6` chain. Line 139 also hardcodes `-inspect-listen "0.0.0.0:$INSPECT_PORT"` (IPv4-only).
   - **Change needed:** Under the `if ip6tables -L -n` block in `deploy/dev/edge-entrypoint.sh`:
     - Define `POOL6="fd7a:5a5e::/64"`.
     - Add `ip6tables -t nat -A POSTROUTING -s "$POOL6" -o "$WAN" -j MASQUERADE` (with optional env toggle for routed/NPTv6 deployments if an operator supplies a global prefix).
     - Add `ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`.
     - Create `OSASE_FWD6` hooked from `FORWARD` mirroring `OSASE_FWD`:
       1. `-i "$WAN" -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`
       2. Defence-in-depth drops from `-i "$TUN"` to `fe80::/10`, `::1/128`, `::/128`, `ff00::/8`, `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`
       3. Device mesh: `-i "$TUN" -o "$TUN" -s "$POOL6" -d "$POOL6" -j ACCEPT`
       4. Private range drops (`fc00::/7`, `2001:2::/48`) when `ALLOW_PRIVATE != 1`
       5. Drop third-party DNS/DoT (`-i "$TUN" -p udp/tcp --dport 53` and `853`)
       6. Accept egress: `-i "$TUN" -o "$WAN" -s "$POOL6" -j ACCEPT`
     - When IPv6 TLS inspection is enabled, mirror `OSASE_INSPECT6` in `ip6tables -t nat PREROUTING`, add `OSASE_IN6` conntrack DNAT accepts for ports 80/443, and change line 139 to `-inspect-listen ":$INSPECT_PORT"`.
     - Note: Check `ip6tables -t nat -L -n` separately from `ip6tables -L -n`, so hosts without `ip6table_nat` kernel support fail safely with a clear log rather than aborting startup under `set -e`.
2. **Dev compose lacks IPv6 forwarding sysctl and IPv6 WAN network (`deploy/dev/docker-compose.yml:77-79, 98, 271-275`):**
   - `edge.sysctls` sets `net.ipv6.conf.all.disable_ipv6: 0` but **omits `net.ipv6.conf.all.forwarding: 1`**.
   - `edge.command` (line 98) hardcodes `-ztna-listen 0.0.0.0:15001`.
   - `networks.default` (lines 271–275) defines IPv4-only IPAM (`172.31.250.0/24`) without `enable_ipv6: true` and an IPv6 subnet, so the Edge container has no IPv6 default route on `eth0` and cannot NAT66 outbound in dev/CI.
   - **Change needed:** Add `net.ipv6.conf.all.forwarding: 1` to `edge.sysctls`, enable `enable_ipv6: true` with a ULA subnet (e.g. `fd7a:5a5e:ff::/64`) on `networks.default` (note: external internet IPv6 reachability in dev still depends on host IPv6 WAN or a local IPv6 test responder service on `default`), and switch `-ztna-listen` to `:15001` if IPv6 ZTNA is added.
3. **Helm `sysctl` mode omits IPv6 forwarding (`deploy/helm/opensase-edge/templates/deployment.yaml:20-23, 28`):**
   - `ipForward: sysctl` only sets `net.ipv4.ip_forward: "1"` (omits `net.ipv6.conf.all.forwarding: "1"`), and `initContainer` masks errors with `|| true`.
   - **Change needed:** Add `{name: net.ipv6.conf.all.forwarding, value: "1"}` under `ipForward: sysctl` (configurable via a `values.yaml` toggle such as `ipv6.enabled: true` for IPv4-only clusters where that sysctl may not be allowed), and log clearly if `initContainer` cannot set IPv6 forwarding.
4. **Helm Service lacks dual-stack family settings (`deploy/helm/opensase-edge/templates/service.yaml:9-16`, `deploy/helm/opensase-edge/values.yaml:30-37`):**
   - Neither `ipFamilyPolicy` nor `ipFamilies` is exposed, so Kubernetes Services default to single-stack IPv4 even on dual-stack clusters.
   - **Change needed:** Add optional `service.ipFamilyPolicy` (e.g. `PreferDualStack`) and `service.ipFamilies` to `values.yaml` and render them in `templates/service.yaml`.
5. **Release deployment docs and quickstart omit IPv6 forwarding (`deploy/release/README.md:32, 170, 195`, `deploy/release/quickstart/quickstart.sh:155`):**
   - Container run commands pass `--sysctl net.ipv4.ip_forward=1` only; `quickstart.sh:155` hardcodes `-ztna-listen 0.0.0.0:15001`.
   - **Change needed:** Add `--sysctl net.ipv6.conf.all.forwarding=1` to release docs and quickstart scripts.

### Risk & Effort
- **Risk:** **Breakage & Leak** — High. Without `OSASE_FWD6`, NAT66, and `net.ipv6.conf.all.forwarding=1`, IPv6 egress cannot work at all; enabling forwarding without `OSASE_FWD6` defence-in-depth rules would expose Edge-host/ULA/NAT64 ranges if the userspace filter ever regressed.
- **Effort:** **M**.

---

## 6. Edge DNS Resolver

### What already works for IPv6
- **Dual-stack tunnel listeners (`internal/edge/edge.go:323-331`):** Serves UDP and TCP on both `100.64.0.1:53` and `[fd7a:5a5e::1]:53` when `e.ipv6` is true.
- **Dual-stack client identification (`internal/edge/dns.go:36-44, 54-55`):** `remoteAddr` unmaps IPv4/IPv6 addresses and resolves the device via `reg.byTunnelIP(client)`.
- **`AAAA` forwarding, blocking, ECH stripping, and SafeSearch (`internal/edge/dns.go:110-165, 270-285`, `internal/edge/ech.go:7-66`, `internal/edge/safesearch.go:74-105, 118-137`):**
  - Forwards `AAAA` queries upstream, inspects CNAME chains for cloaking, snoops `*dns.A` and `*dns.AAAA`, and strips ECH config from `HTTPS`/`SVCB` records while preserving other parameters.
  - Blocked `AAAA` returns `NXDOMAIN` or `::` (`net.IPv6zero`) when `blockResponse == "zero"`.
  - SafeSearch resolves and warms both `TypeA` and `TypeAAAA` for covered safe hostnames.
- **Internal DNS `AAAA` and IPv6 forwarders (`internal/edge/dns.go:170-243`, `pkg/policy/dnszone.go:66-71, 105-115`):** Answers `<device>.<user>.<zone>` `AAAA` with `target.ip6` when `rs.e.ipv6`, static `AAAA` records, `CNAME -> AAAA` chains, and conditional forwarding to IPv6 upstream resolvers (`[addr]:port`).

### What is missing or wrong
1. **Cross-family `snoop` key bug (`internal/edge/dns.go:151, 265`, `internal/edge/safesearch.go:101`, `internal/edge/state.go:115`):**
   - Records `snoop.add(client, ip, ...)` using the transport IP (`d.ip4` or `d.ip6`) that carried the DNS query rather than `d.id`. See Area 4 for full impact and fix (`snoopKey{deviceID, ip}`).
2. **DNS flow logs hardcode `EdgeIPv4` and `"udp"` (`internal/edge/dns.go:160, 290`):**
   - Both `LogQueries` (line 160) and `block` (line 290) emit `Protocol: "udp"` and `DstIP: EdgeIPv4.String()`, even when the query arrived on `fd7a:5a5e::1` or over TCP.
   - **Change needed:** Derive `DstIP` from `remoteAddr(w.LocalAddr())` (fallback `EdgeIPv4`) and `Protocol` from `w.LocalAddr()` (`"tcp"` for `*net.TCPAddr`, `"udp"` otherwise).
3. **`AAAA` forwarded even when Edge lacks IPv6 WAN egress (`internal/edge/dns.go:110-165`, `internal/edge/edge.go:401-406`):**
   - On an IPv4-only Edge host where `wg0` still receives `fd7a:5a5e::1/64` (`e.ipv6 = true`), the resolver forwards external `AAAA` queries upstream and returns global IPv6 addresses whose connections are then silently dropped at `ip6tables FORWARD`, causing Happy Eyeballs stalls or broken IPv6-first clients.
   - **Change needed:** Tie external `AAAA` forwarding (or `e.ipv6` advertisement in Area 1) to verified IPv6 egress readiness; on IPv4-only Edges, either disable `e.ipv6` entirely or return empty `NOERROR` for external `AAAA` while still serving internal zone `AAAA` only if IPv6 mesh is active.
4. **Defensive `Unmap()` on snooped `AAAA` (`internal/edge/dns.go:146`, `internal/edge/safesearch.go:92`):**
   - `netip.AddrFromSlice(v.AAAA)` should call `.Unmap()` (matching `pkg/dnsfilter/dnsfilter.go:215` and `snoop.add`) so IPv4-mapped `AAAA` records cannot bypass IPv4 checks or mismatch `p.Dst.Unmap()`.
   - **Change needed:** Use `ip = ip.Unmap()` before storing in `snoop` and `safe`.
5. **Default upstream DNS is IPv4-only (`cmd/edge/main.go:37`, `internal/edge/edge.go:105`):**
   - Defaults to `1.1.1.1:53`. This resolves `AAAA` fine on dual-stack Edges, but IPv6-only Edge hosts must configure an IPv6 upstream (`[addr]:53`).
   - **Change needed:** Document IPv6 upstream configuration and verify bracketed `[ipv6]:53` works cleanly in startup flags and Helm `values.yaml`.

### Risk & Effort
- **Risk:** **Bypass & Breakage** — Medium–High (cross-family snoop bypasses domain rules; returning unreachable `AAAA` degrades client connections on IPv4-only Edges; inaccurate audit logs).
- **Effort:** **S**.

---

## 7. ZTNA and Synthetic Addresses

### What already works for IPv6
- **Connector dials IPv6 private backends (`internal/connector/dial.go:51-60, 95-122`):** Uses `LookupNetIP(ctx, "ip", host)`, blocks IPv6 loopback/link-local/multicast/unspecified destinations, and dials IPv6 targets via `net.JoinHostPort(ip.String(), ...)`. Dual-stack clients can therefore already reach IPv6-only private apps behind a Connector via synthetic IPv4.
- **Deterministic dual-stack fallback (`internal/edge/dns.go:245-268`):** `synthesize` returns an authoritative empty `NOERROR` for private-app `AAAA` queries, steering dual-stack clients directly to the synthetic IPv4 `A` record (`100.96.0.0/12`) without waiting for an upstream timeout.

### What is missing or wrong
1. **Client-to-Edge synthetic ZTNA path is 100% IPv4-only:**
   - `pkg/policy/types.go:173`: Defines `SyntheticPrefix = "100.96.0.0/12"` only (no IPv6 synthetic prefix).
   - `internal/edge/synth.go:16, 48-66`: `synthMap` uses `uint32` `base`/`size`, `prefix.Addr().As4()`, and `netip.AddrFrom4`.
   - `internal/edge/dns.go:252`: `synthesize` answers `dns.TypeA` only.
   - `internal/edge/filter.go:203`: `synthetic := dst.Is4() && SyntheticPrefix.Contains(dst)`.
   - `internal/edge/broker.go:104`: Checks `!SyntheticPrefix.Contains(dst.Addr())` only.
   - `internal/edge/edge.go:117, 432, 502`, `cmd/edge/main.go:46`, `deploy/dev/edge-entrypoint.sh:16, 62-63, 110`, `deploy/dev/docker-compose.yml:98`: Listen on `"tcp4"` (`0.0.0.0:15001`) and install IPv4 `iptables` REDIRECT + `OSASE_IN` DNAT accept only.
   - `internal/edge/origdst_linux.go:13-40`: Calls `IPPROTO_IP` `SO_ORIGINAL_DST` only and errors on non-`AF_INET` sockets.
2. **Concrete change needed (if IPv6 synthetic ZTNA is required beyond dual-stack):**
   - Reserve an IPv6 synthetic prefix outside `fd7a:5a5e::/64` (e.g. `SyntheticPrefix6 = "fd7a:5a5e:1::/64"`, avoiding any collision with `tunneladdr.Prefix6`).
   - Add an IPv6 `synthMap` (or dual-stack allocation sharing an offset) and answer `dns.TypeAAAA` in `dns.go:252` when `rs.e.ipv6`.
   - Extend `origdst_linux.go` to query `IPPROTO_IPV6` `IP6T_SO_ORIGINAL_DST` (`80`, 28-byte `sockaddr_in6`) when `c.RemoteAddr()` is IPv6, bind `startZTNA` on `"tcp"` (`:15001`), accept `SyntheticPrefix6` in `filter.go:203` and `broker.go:104`, and add `ip6tables` `PREROUTING` REDIRECT + `OSASE_IN6` conntrack DNAT rules in `edge.go` and `edge-entrypoint.sh`.
   - *Note:* For dual-stack issue #74, keeping synthetic ZTNA on IPv4 (with empty `AAAA` NOERROR) does **not** break dual-stack clients or IPv6-only backends, so IPv6 synthetic ZTNA can safely be a later step—whereas `origdst_linux.go` dual-stack support is shared if IPv6 TLS inspection is implemented.

### Risk & Effort
- **Risk:** **Breakage** — Low for dual-stack clients (works via v4 synthetic + empty `AAAA` NOERROR); **High** only if IPv6-only clients are introduced later.
- **Effort:** **M**.

---

## 8. Mesh

### What already works for IPv6
- **Edge mesh filter (`internal/edge/filter.go:206-208, 328-334, 343-391`):** `outbound` routes packets destined for `TunnelPrefix6` (excluding `EdgeIPv6`) into `meshOutbound`; `reg.byTunnelIP(dst)` resolves the target device by `ip6`; `inbound` (lines 328–334) allows tracked mesh packets back out `wg0` toward the target peer.
- **Client mesh inbound acceptance (`pkg/firewall/firewall.go:501-530`):** `meshInbound` checks both `tunneladdr.Prefix4` and `tunneladdr.Prefix6`, excludes `EdgeIPv4` and `EdgeIPv6`, and allows TCP SYN, UDP, and ICMPv6 echo (`128`).
- **Internal DNS `AAAA` for mesh peers (`internal/edge/dns.go:186-201`):** `<device>.<user>.<zone>` already returns `AAAA` with `target.ip6` whenever `rs.e.ipv6` is true.

### What is missing or wrong
1. **Edge kernel drops all IPv6 mesh traffic (`deploy/dev/edge-entrypoint.sh:118-130`, `deploy/dev/docker-compose.yml:77-79`):**
   - IPv4 has `iptables -A OSASE_FWD -i "$TUN" -o "$TUN" -s "$POOL" -d "$POOL" -j ACCEPT` (line 86), whereas IPv6 has `ip6tables -P FORWARD DROP` (line 120) with no `OSASE_FWD6` mesh rule and no `net.ipv6.conf.all.forwarding=1` in dev compose. Every IPv6 mesh packet allowed by `filter.go` is dropped by the Edge kernel.
   - **Change needed:** Add `ip6tables -A OSASE_FWD6 -i "$TUN" -o "$TUN" -s "$POOL6" -d "$POOL6" -j ACCEPT` (before private-range `fc00::/7` drops!) and enable `net.ipv6.conf.all.forwarding=1`.
2. **Mesh policy compiler and matcher lack `"icmpv6"` (`pkg/policy/mesh.go:20-24, 43-52`, `pkg/policy/types.go:86`, `docs/schema/tenant-policy.schema.json:671-679`):**
   - `compileMesh` only accepts `"", "tcp", "udp", "icmp"` (rejects `"icmpv6"`).
   - `MeshAllows` compares `g.proto != proto` strictly and skips port checks only when `proto != "icmp"`. Today this only happens to allow ICMPv6 because `internal/edge/filter.go:163-164` erroneously collapses `ProtoICMPv6` to `"icmp"`. Fixing `protoName` (Area 4) will **break IPv6 mesh ping** unless `MeshAllows` is updated simultaneously.
   - **Change needed:** Accept `"icmpv6"` in `compileMesh`, `pkg/policy/types.go`, and `tenant-policy.schema.json:674`; in `MeshAllows`, match `g.proto == "icmp"` against both `"icmp"` and `"icmpv6"` (mirroring `pkg/policy/evaluate.go:417-420`), match `g.proto == "icmpv6"` against `"icmpv6"` only, and skip port checks for `proto == "icmp" || proto == "icmpv6"`.
3. **Documentation states mesh is IPv4-only (`docs/operations/mesh.md:30`):**
   - **Change needed:** Update `docs/operations/mesh.md` once IPv6 mesh forwarding is enabled.

### Risk & Effort
- **Risk:** **Breakage** — High (100% of IPv6 mesh traffic is currently silently dropped in the Edge kernel, and `MeshAllows` will break for ICMPv6 when `protoName` is fixed).
- **Effort:** **S**.

---

## 9. Control Plane and Policy

### What already works for IPv6
- **Policy CIDR and protocol evaluation (`pkg/policy/evaluate.go:417-431, 500-528, 670-690, 853-867`):** Compiles IPv6 CIDRs and bare IPv6 host addresses (`/128`), unmaps IPv4-in-IPv6 prefixes (`/96..128`), rejects IPv6 zone IDs (`%eth0`), supports `protocols: ["icmp"]` (matches ICMPv4 + ICMPv6) and `protocols: ["icmpv6"]` (ICMPv6 only), and evaluates zero-alloc.
- **Internal DNS policy (`pkg/policy/dnszone.go:66-71, 105-115`):** Validates `AAAA` static records and IPv6 conditional forwarder addresses (`netip.ParseAddr` / `netip.ParseAddrPort`).
- **Posture-restricted snapshot (`internal/controlplane/snapshot.go:427, 444-449`):** Allows DNS to both `EdgeIPv4/32` and `EdgeIPv6/128`, and formats Control Plane allow CIDRs with `/32` or `/128`.
- **Cloud decision API (`internal/controlplane/snapshot.go:662-691`):** `compileDecide` and `cloudDecide` accept and match IPv6 CIDRs and bare IPv6 addresses in `decideBlockCidrs`.
- **Dual-stack Control Plane listener (`internal/controlplane/server.go:328`):** Listens on `"tcp"` (`:9443`), dual-stack on Linux.

### What is missing or wrong
1. **`compileDecide` lacks zone rejection and IPv4-mapped normalization (`internal/controlplane/snapshot.go:662-672`):**
   - Unlike `policy.parsePrefix` (`pkg/policy/evaluate.go:509-526`), `compileDecide` calls `netip.ParsePrefix`/`netip.ParseAddr` directly without rejecting zoned IPv6 addresses (`fe80::1%eth0`) or unmapping IPv4-mapped prefixes (`::ffff:1.2.3.4/128`). Because `cloudDecide` (line 684) calls `ip = ip.Unmap()`, a v4-mapped entry in `decideBlockCidrs` will silently fail to match.
   - **Change needed:** Export or mirror `policy.parsePrefix` in `compileDecide` (reject `a.Zone() != ""`, unmap v4-in-v6 prefixes with `bits >= 96`).
2. **Schema and docs gaps (`docs/schema/tenant-policy.schema.json:230, 671-679`, `docs/reference/policy.md:52`):**
   - `mesh` protocol enum omits `"icmpv6"` (`schema.json:674`); `docs/reference/policy.md:52` omits `"icmpv6"` from firewall rule protocols; `schema.json:230` documents `dns.redirectQueries` as IPv4-only.
   - **Change needed:** Add `"icmpv6"` to mesh schema and policy reference docs; update `redirectQueries` description once IPv6 DNS redirect lands.
3. **Routed Workload Gateway device routes reject IPv6 (`pkg/store/routes.go:18-43`):**
   - `validateRoute` rejects any `!p.Addr().Is4()` and only allows RFC 1918 `/16../32`.
   - **Change needed:** Deferred outside personal-client #74 MVP; when workload gateways support IPv6, permit ULA `fc00::/7` (excluding `fd7a:5a5e::/64` and any synthetic v6 range, e.g. `/48../128`) or operator-configured routed IPv6 prefixes, alongside `internal/edge/kroutes.go` and `cmd/opensase-client/gateway.go`.
4. **Quickstart IPv6 literal formatting (`deploy/release/quickstart/quickstart.sh:38-40, 45, 90, 153`):**
   - Interpolates `"https://$HOST:8443"` and `"$HOST:51820"` without brackets if `HOST` is an IPv6 literal.
   - **Change needed:** Bracket `$HOST` when it contains `:` (and not already bracketed).

### Risk & Effort
- **Risk:** **Bypass** (low–medium: v4-mapped CIDR miss in `decideBlockCidrs`) and **Breakage** (low: schema validation rejecting `"icmpv6"` in mesh grants).
- **Effort:** **S** (`M` if IPv6 routed workload subnets are included).

---

## 10. Tests

### What already works for IPv6
- **Unit tests with IPv6 coverage:**
  - `pkg/tunneladdr/tunneladdr_test.go:8-34` (`AddrAt` v4+v6).
  - `pkg/packet/packet_test.go:217-230, 284-298, 312, 342-350, 366-367, 442-444, 482-492, 502-507, 523-524, 547` (IPv6 parse, ext headers, fragments, ICMPv6 echo, TCP RST, ICMPv6 unreachable 1280B cap, fuzzing).
  - `pkg/policy/evaluate_test.go:62-64, 91-92, 146, 151, 186-188, 208, 340, 483-484, 516, 545, 644` (IPv6 CIDR, v4-mapped, zone rejection, `icmp` matching `icmpv6`).
  - `pkg/policy/dnszone_test.go:14, 53` (`AAAA` internal record compilation/validation).
  - `pkg/dnsfilter/dnsfilter_test.go:93-94, 111, 113, 231, 237` (IPv6 UDP transport, `zero` -> `::` for `AAAA`, `AAAA` snooping).
  - `pkg/firewall/firewall_test.go:323-362` (`TestLinkLocalICMPv6DroppedSilently`).
  - `internal/clientnet/routeplan_test.go:41-59` (`::/1` + `8000::/1` when `IPv6` set).
  - `internal/clientnet/killswitch_linux_test.go:13, 20, 22` (`ip6 daddr` allow set and NDP).
  - `internal/edge/edge_test.go:393, 408, 770-785, 860` (`TunnelIPv6` + WireGuard `allowed_ip=fd7a:5a5e::2/128`).
  - `internal/edge/inspect_test.go:285-311` (`TestWebBlockRule` covers current IPv6 web block).
- **Raw WireGuard security harness (`test/security/go/tunnel_test.go:67, 197-215, 286-288, 320-323`):** Already builds IPv6 TCP/UDP packets and supports DNS queries over `a1.ip6`.

### What is missing or wrong
1. **Existing security tests actively assert IPv6 egress MUST FAIL (will break once #74 lands):**
   - `test/security/50-dataplane.sh:57-67` (`SEC-DP-103`): Checks `ip -6 route get 2001:4860:4860::8888` routes via `$TUN` (good), then **fails the test if `curl -6 https://example.com` succeeds** (lines 61–62)!
   - `test/security/go/dataplane_test.go:258-281` (`SEC-DP-009`): Checks Edge refuses `[::1]:8443`, `[fe80::1]:80`, `[fd00::1]:80`, `[fd7a:5a5e::1]:8443` (good), then **fails the test if global IPv6 `example.com:443` returns SYN-ACK** (lines 268–279)!
   - `internal/edge/edge_test.go:903-937` (`TestFilterDNSRedirect`) and `internal/edge/inspect_test.go:285-311` (`TestWebBlockRule`) explicitly assert IPv6 DNS redirect and IPv6 web inspection are blocked.
   - **Change needed:**
     - Refactor `SEC-DP-103` (`50-dataplane.sh:57-67`) to assert: (a) `ip -6 route get` goes strictly via `$TUN`, never physical `eth0`; (b) blocked IPv6 destinations (ULA/link-local, third-party IPv6 DNS/DoT/DoH, port 25 over IPv6) fail; (c) an allowed IPv6 endpoint succeeds through `$TUN` (positive control when IPv6 WAN/test target is available); and (d) with kill switch on and tunnel down, zero IPv6 packets escape.
     - Refactor `SEC-DP-009` (`dataplane_test.go:258-281`) to keep refusing loopback/link-local/ULA/Edge non-DNS ports, add NAT64 (`[64:ff9b::a9fe:a9fe]:80`), IPv6 DNS/DoT/DoH bypass (`[2001:4860:4860::8888]:53/443`, `[2606:4700:4700::1111]:853/443`), IPv6 tenant policy (e.g. TCP/25 over v6), and assert that an allowed global IPv6 target **does** return SYN-ACK when Edge IPv6 egress is active.
2. **Missing unit tests across core packages:**
   - `pkg/firewall/firewall_test.go`: Zero IPv6 tests outside `TestLinkLocalICMPv6DroppedSilently`—missing IPv6 TCP/UDP allow/block + RST/ICMPv6 unreachable, inbound related ICMPv6 error (including with ext headers), IPv6 DNS block + cross-family AAAA snoop, and IPv6 `TestMeshInbound`.
   - `pkg/policy/evaluate_test.go` & `pkg/policy/mesh_test.go` (missing file): Missing test that `protocols: ["icmpv6"]` matches `"icmpv6"` and does NOT match `"icmp"`; missing mesh unit tests for `"icmp"` vs `"icmpv6"`.
   - `internal/edge/edge_test.go`: `TestFilter` (lines 616–757) and `TestFilterMesh` (lines 941–1012) are 100% IPv4-only; no test for `e.ipv6 == false` session response, `protocols: ["icmpv6"]`, cross-family snoop, or NAT64 built-in deny.
   - `internal/edge/dns_test.go` & `internal/edge/safesearch_test.go`: 100% `TypeA` over `127.0.0.1`—missing `TypeAAAA` forwarding/blocking (`NXDOMAIN` and `zero` -> `::`), `[::1]` IPv6 transport, flow-log `DstIP`/`Protocol` verification on v6/TCP, internal DNS `AAAA` device/record/CNAME, and `TypeAAAA` SafeSearch.
   - `internal/clientnet/`: Missing Linux `routeCommands` unit tests (IPv6 bypass `/128`, IPv6-only host, fallback unreachable route), missing IPv6 bypass tests in `routeplan_test.go`, and missing WFP filter unit tests (`internal/wfp/rules_test.go` does not exist).
   - `internal/controlplane/`: Missing `compileDecide` unit test for IPv6 zones and v4-mapped IPv6 prefixes.
3. **Zero IPv6 coverage in `deploy/dev/e2e.sh` and harness gaps (`test/security/go/tunnel_test.go`):**
   - `deploy/dev/e2e.sh:62-129, 230-235` checks only IPv4 tunnel address, IPv4 route, IPv4 DNS, and private-app `AAAA -> empty NOERROR`.
   - `test/security/go/tunnel_test.go:219, 340`: `icmpEcho` builds IPv4 only; `resolve4` has no `resolve6` helper.
   - **Change needed:** Add an IPv6 section to `deploy/dev/e2e.sh` verifying `fd7a:5a5e::` on `osase0`, `ip -6 route get`, `dig @fd7a:5a5e::1 ... AAAA` (allowed + blocked), IPv6 HTTPS egress (`curl -6`), IPv6 policy block (TCP/25 or IPv6 CIDR), IPv6 third-party DNS/DoT block, and IPv6 mesh connectivity; add `icmpv6Echo` and `resolve6` to `tunnel_test.go`.

### Risk & Effort
- **Risk:** **Breakage & Blind Spot** — High (`SEC-DP-103`/`SEC-DP-009` break on deployment; cross-family and leak regressions go undetected without dedicated unit/E2E tests).
- **Effort:** **M**.

---

## Ordered Implementation Plan

Steps are ordered so **policy correctness and leak closure land before IPv6 egress forwarding is enabled**, keeping every intermediate commit safe and testable.

### Step 1 — Policy & Control Plane IPv6 Correctness
- **Goal:** Fix `"icmpv6"` mesh matching, `compileDecide` IPv6 normalization, and policy schema/docs.
- **Files:**
  - `pkg/policy/mesh.go` (accept `"icmpv6"`, match `"icmp"` against `"icmp"`/`"icmpv6"`, skip port checks for `"icmpv6"`)
  - `pkg/policy/types.go` (update `MeshGrant.Protocol` comment and `SyntheticPrefix` `/10` doc comment)
  - `internal/controlplane/snapshot.go` (reject IPv6 zones and unmap v4-in-v6 in `compileDecide`)
  - `docs/schema/tenant-policy.schema.json`, `docs/reference/policy.md`
- **Proving tests:**
  - New `pkg/policy/mesh_test.go` (`TestMeshAllowsICMPv6`)
  - Extended `pkg/policy/evaluate_test.go` (`protocols: ["icmpv6"]` matches `"icmpv6"`, rejects `"icmp"`)
  - New test in `internal/controlplane/` (`TestCompileDecideIPv6Normalization`)

### Step 2 — Edge Filter, Snoop, Built-in Guard, and DNS Correctness
- **Goal:** Eliminate cross-family snoop bypass, fix Edge `protoName` for ICMPv6, harden IPv6 built-in denies, and fix DNS flow logging.
- **Files:**
  - `internal/edge/state.go` (key `snoopKey` by `deviceID string` + `ip netip.Addr`; sweep by live device ID)
  - `internal/edge/edge.go` (update `snoop.sweep` callback in `sweepLoop`)
  - `internal/edge/dns.go` (pass `d.id` to `snoop.add`; `Unmap()` on `AAAA`; derive flow-log `DstIP`/`Protocol` from `w.LocalAddr()`)
  - `internal/edge/safesearch.go` (pass `d.id` to `snoop.add`; `Unmap()` on `AAAA`)
  - `internal/edge/filter.go` (lookup `snoop` by `d.id`; return `"icmpv6"` in `protoName`; use `isICMP` helper)
  - `internal/edge/guard.go` (add `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64` to `alwaysDenied`; `2001:2::/48` to `privateRanges`)
  - `internal/edge/inspect.go` (add `!TunnelPrefix6.Contains(a)` in `upstreamOK`)
- **Proving tests:**
  - Extended `internal/edge/edge_test.go` (`TestFilterIPv6`: TCP/UDP/ICMPv6 allow/block, `protocols: ["icmpv6"]`, cross-family AAAA-over-v4 -> TCP-over-v6 domain block, NAT64 deny, IPv6 `TestFilterMesh` TCP + ICMPv6)
  - Extended `internal/edge/dns_test.go` (`TestResolverIPv6`: `AAAA` over `[::1]`, `zero` -> `::`, `DstIP`/`Protocol` log check, internal DNS `AAAA` device/record/CNAME)
  - Extended `internal/edge/safesearch_test.go` (`TestSafeSearchAAAA`)

### Step 3 — Edge IPv6 Readiness & Session Consistency
- **Goal:** Ensure Edge never hands out `TunnelIPv6` or installs v6 `allowed_ip` when IPv6 is unavailable, and checks IPv6 forwarding at startup.
- **Files:**
  - `internal/edge/ipforward_linux.go` (add `checkIPv6Forward()` reading `/proc/sys/net/ipv6/conf/all/forwarding`)
  - `internal/edge/edge.go` (set `e.ipv6` only when `wg0` IPv6 addr AND IPv6 forwarding are active, or explicit flag; log IPv6 state on startup)
  - `internal/edge/session.go` (gate `TunnelIPv6` and WireGuard `allowed_ip=<ip6>/128` on `e.ipv6`; log `"ipv6"` on session setup)
  - `mobile/loops.go` (log IPv6 on tunnel address change)
- **Proving tests:**
  - Extended `internal/edge/edge_test.go` (`TestSessionIPv6Disabled` verifying empty `TunnelIPv6`, no v6 `DNSServers`, no v6 `allowed_ip` when `e.ipv6 == false`)
  - New unit test for `checkIPv6ForwardFile` in `internal/edge/`

### Step 4 — Client Firewall IPv6 Hardening
- **Goal:** Fix ICMPv6 error quoting with extension headers and expand client firewall IPv6 test coverage.
- **Files:**
  - `pkg/firewall/firewall.go` (update `quotedFlowKey` to parse quoted IPv6 extension headers and quoted ICMPv6 echo)
- **Proving tests:**
  - Extended `pkg/firewall/firewall_test.go` (`TestOutboundVerdictsIPv6`, `TestStatefulInboundIPv6` with Packet Too Big quoting ext-header packet, `TestDNSBlockIPv6`, `TestDomainRuleViaAAAASnoop`, `TestMeshInboundIPv6`)

### Step 5 — Linux Client Routes, Bypass, and Leak Closure
- **Goal:** Add IPv6 `/128` bypass routes, IPv6-only gateway support, clean route teardown, fallback unreachable routes when IPv6 is missing, kill-switch activation in `opensase-client`, and non-`systemd-resolved` DNS handling.
- **Files:**
  - `internal/clientnet/linux.go` (add `defaultGateway6`, `/128` bypass routes, teardown of installed bypass routes, unreachable `::/1` + `8000::/1` when kernel v6 is enabled but `c.IPv6 == ""`, `/etc/resolv.conf` backup/restore fallback)
  - `internal/clientnet/killswitch_linux.go` (add `forward` drop chain alongside `output` when not in gateway mode)
  - `cmd/opensase-client/main.go` (wire `netCfg.KillSwitch = eng.KillSwitch()` with optional flag)
- **Proving tests:**
  - New `internal/clientnet/linux_test.go` (`TestRouteCommandsIPv6Bypass`, `TestRouteCommandsIPv6OnlyHost`, `TestRouteCommandsNoTunnelIPv6Blackhole`)
  - Extended `internal/clientnet/killswitch_linux_test.go` (assert `forward` chain rules)

### Step 6 — Windows Client Routes, Bypass, Rollback, and DNS Leak Closure
- **Goal:** Add IPv6 `/128` bypass routes, dual-stack gateway discovery, error rollback, and SMHNR DNS leak closure.
- **Files:**
  - `internal/clientnet/routeplan.go` (accept optional `gw4`, `gw6`; emit deduplicated `/32` and `/128` bypass routes)
  - `internal/clientnet/windows.go` (discover both `AF_INET` and `AF_INET6` physical gateways; stop ignoring IPv6 addr/DNS errors when `c.IPv6 != ""`; roll back installed routes/DNS on any `AddRoute` failure; configure root `.` domain / NRPT on Wintun DNS)
  - `internal/wfp/rules.go` (scope `blockDNS` cleanly so Edge `dns.redirectQueries` can operate on TUN if enabled while physical port 53 stays blocked)
- **Proving tests:**
  - Extended `internal/clientnet/routeplan_test.go` (`TestWindowsRoutePlan` cases for IPv6 bypass `/128`, mixed v4+v6 bypass, IPv6-only host)
  - New `internal/wfp/rules_test.go` (verify generated IPv6 bypass, DNS, NDP, DHCPv6, and catch-all block filter structures)

### Step 7 — Android & Mobile Core IPv6 Robustness
- **Goal:** Handle empty `cfg.ipv6` without leaking and remove hard IPv4 endpoint preference on IPv6-only mobile networks.
- **Files:**
  - `clients/mobile/android/app/src/main/kotlin/eu/opensase/android/vpn/OpenSaseVpnService.kt` (when `cfg.ipv6` is empty, add deterministic sink address + `::/0` route so IPv6 cannot leak or throw)
  - `mobile/session.go` (select WireGuard endpoint address family matching the reachable session connection / fallback across AAAA and A)
- **Proving tests:**
  - New `mobile/session_test.go` (`TestResolveEndpointIPv6Only` and family preference)
  - Android unit test for `OpenSaseVpnService` builder helper (empty vs populated `cfg.ipv6`)

### Step 8 — Edge Forced DNS Redirect for IPv6 (`dns.redirectQueries`)
- **Goal:** Redirect IPv6 third-party UDP/TCP port-53 queries to `[fd7a:5a5e::1]:53` when `dns.redirectQueries` is enabled.
- **Files:**
  - `internal/edge/edge.go` (parameterize `ensureRedirect` for `iptables`/`ip6tables`; add `ip6tables` DNAT in `redirectDNS` when `e.ipv6`)
  - `internal/edge/filter.go` (change `dst.Is4()` to `(dst.Is4() || f.e.ipv6)` at line 247)
- **Proving tests:**
  - Extended `internal/edge/edge_test.go` (`TestFilterDNSRedirect` adding IPv6 UDP/53 + TCP/53 allowed and IPv6 TCP/853 DoT still blocked)

### Step 9 — Edge Egress NAT, `OSASE_FWD6`, Dev Stack, and Helm Charts
- **Goal:** Enable IPv6 forwarding, NAT66 masquerade, TCP MSS clamping, `OSASE_FWD6` defence-in-depth + mesh rules, and dual-stack container/Helm config.
- **Files:**
  - `deploy/dev/edge-entrypoint.sh` (add `POOL6`, `ip6tables -t nat POSTROUTING MASQUERADE`, `mangle TCPMSS`, full `OSASE_FWD6` chain including mesh `-i $TUN -o $TUN -s $POOL6 -d $POOL6 -j ACCEPT` and NAT64/ULA/DNS/DoT drops)
  - `deploy/dev/docker-compose.yml` (add `net.ipv6.conf.all.forwarding: 1` to `edge.sysctls`; add `enable_ipv6: true` and IPv6 IPAM subnet to `networks.default`)
  - `deploy/helm/opensase-edge/templates/deployment.yaml`, `deploy/helm/opensase-edge/templates/service.yaml`, `deploy/helm/opensase-edge/values.yaml` (add `net.ipv6.conf.all.forwarding` to `sysctl` mode; expose `service.ipFamilyPolicy` and `service.ipFamilies`)
  - `deploy/release/README.md`, `deploy/release/quickstart/quickstart.sh`, `docs/operations/mesh.md`
- **Proving tests:**
  - `helm template` dry-run rendering both `ipForward=sysctl` and `ipFamilyPolicy=PreferDualStack`
  - Dev stack E2E and security checks in Step 10

### Step 10 — Update Security & E2E Tests for Live End-to-End IPv6
- **Goal:** Replace "IPv6 must fail" assertions with end-to-end IPv6 egress, policy, DNS, mesh, and leak-prevention tests.
- **Files:**
  - `test/security/go/tunnel_test.go` (add `icmpv6Echo` and `resolve6` helpers)
  - `test/security/go/dataplane_test.go` (update `SEC-DP-009`: keep loopback/link-local/ULA/Edge non-DNS refusal, add NAT64 + IPv6 DNS/DoT/DoH bypass + IPv6 TCP/25 policy refusal, assert allowed global IPv6 returns SYN-ACK when Edge has IPv6 WAN)
  - `test/security/50-dataplane.sh` (update `SEC-DP-103`: assert IPv6 routes via `$TUN`, blocked IPv6 destinations fail, allowed IPv6 HTTPS succeeds via `$TUN`, and zero leak outside `$TUN`)
  - `deploy/dev/e2e.sh` (add IPv6 tunnel address, `ip -6 route get`, `dig @fd7a:5a5e::1` `AAAA` allowed + blocked, `curl -6`, IPv6 TCP/25 block, IPv6 third-party DNS/DoT block, and IPv6 mesh checks)
- **Proving tests:**
  - `deploy/dev/e2e.sh` (full dev stack green including new IPv6 assertions)
  - `test/security/run.sh` (`SEC-DP-009` and `SEC-DP-103` passing)

### Step 11 (Follow-up) — Dual-Stack `SO_ORIGINAL_DST` and IPv6 TLS Inspection
- **Goal:** Remove the `web:ipv6` fallback block for inspected tenants by supporting IPv6 transparent proxy interception.
- **Files:**
  - `internal/edge/origdst_linux.go` (add `IPPROTO_IPV6` `IP6T_SO_ORIGINAL_DST` = `80` decoding `sockaddr_in6`)
  - `internal/edge/edge.go` (bind `startInspect` on `"tcp"`)
  - `internal/edge/redirect.go` (manage `ip6tables` `OSASE_INSPECT6` chain for `d.ip6/128` alongside IPv4 `OSASE_INSPECT`)
  - `internal/edge/inspect.go` (remove IPv6 cases from `webBlockRule` once IPv6 redirect is active)
  - `deploy/dev/edge-entrypoint.sh` (add `ip6tables` `OSASE_INSPECT6` hook, `OSASE_IN6` DNAT `ctorigdstport 80/443`, and `-inspect-listen ":$INSPECT_PORT"`)
- **Proving tests:**
  - Extended `internal/edge/inspect_test.go` (IPv6 `inspectFixture` over `[::1]`, updated `TestWebBlockRule`)
  - Extended `test/security/50-dataplane.sh` (`SEC-DP-120`–`127` over `curl -6`)

### Step 12 (Follow-up, Optional for Dual-Stack) — IPv6 ZTNA Synthetics & IPv6 Workload Gateway
- **Goal:** Enable ZTNA for IPv6-only clients and IPv6 subnets behind Workload Gateways.
- **Files:**
  - ZTNA: `pkg/policy/types.go`, `internal/edge/synth.go`, `internal/edge/dns.go`, `internal/edge/filter.go`, `internal/edge/broker.go`, `internal/edge/edge.go`, `deploy/dev/edge-entrypoint.sh`, `deploy/dev/docker-compose.yml`
  - Workload Gateway: `pkg/store/routes.go`, `internal/edge/kroutes.go`, `cmd/opensase-client/gateway.go`, `cmd/opensase-client/geneve.go`, `deploy/dev/edge-entrypoint.sh`
- **Proving tests:**
  - New `internal/edge/` ZTNA IPv6 synthetic unit test (DNS `AAAA` -> `SyntheticPrefix6` -> broker -> IPv6 Connector dial)
  - New `pkg/store/` & `internal/edge/` routed IPv6 subnet tests + `cmd/opensase-client/` IPv6 GENEVE (`0x86DD`) unit test
