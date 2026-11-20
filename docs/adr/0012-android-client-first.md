# ADR-0012: Android Client first, with on-device firewall and cloud decisions

- Status: Accepted (2026-11-19)
- Supersedes the MVP ordering in `docs/effort-estimate.md` (desktop first). Mobile moves to Phase 1.

## Decision

The first deliverable is an end-to-end slice:

```
Android app ──VpnService (all traffic)──▶ Go core (firewall + DNS + WireGuard/PQ-PSK)
     ▲                                          │ tunnel
     │ signed Policy Snapshot / decisions       ▼
Control Plane ◀────────────── peers ─────── Edge (WireGuard, cloud firewall, DNS, NAT)
```

1. **All traffic captured.** `VpnService` routes `0.0.0.0/0` and `::/0`. The app excludes
   itself with `addDisallowedApplication(own package)`, so its control traffic never loops.
   Always-on VPN and lockdown are supported.
2. **Go core via gomobile.** All logic is in Go (`mobile/`, `pkg/...`), so it can be tested
   on the desktop and reused by future desktop clients. Flutter (Dart) handles the UI; native Kotlin only handles `VpnService`
   and platform callbacks (UID lookup, network type).
3. **L3 packet filter wrapped around a wireguard-go TUN.** The Android TUN fd is wrapped by
   `FilteringTUN`. Outbound packets are classified (5-tuple, owning app UID via
   `ConnectivityManager.getConnectionOwnerUid`, network type, domain learned from DNS
   snooping) and evaluated before WireGuard encrypts them. Inbound packets only pass if they
   match an existing flow (stateful).
4. **The cloud is the source of truth.** The policy is authored in the Control Plane:
   - tenant rules, which are mandatory;
   - the user's own rules, which the UI edits and sends to the cloud, when the tenant allows them.

   Each change produces a signed Policy Snapshot. The device evaluates the snapshot locally
   (fast, works offline). Flows that match an `ask` rule, or the `ask` default, are sent to
   the cloud decision API (`POST /v1/decide`). Its verdicts are cached with a TTL. The first
   packet of an undecided flow is dropped, and TCP/UDP retransmission picks up the cached
   verdict.
5. **Defence in depth on the Edge.** The Edge evaluates the same snapshot again for
   rules that do not depend on device-only attributes (app, network type). The DNS resolver
   at the Edge enforces DNS policy, so a tampered client still cannot bypass tenant rules.
6. **Quantum safe tunnel** as in ADR-0002.

## Firewall feature set (client)

- Per-app allow/block, set separately for Wi-Fi, cellular and roaming.
- Default action for unknown apps: allow, block or ask the cloud.
- Lockdown mode: block everything except the allowlisted apps.
- IP/CIDR, port and protocol rules. Domain rules: exact or `*.suffix`.
- DNS filtering with blocklists (ads, trackers, malware) and a block response
  (NXDOMAIN or 0.0.0.0).
- Connection log: app, destination, domain, verdict, rule id, bytes. Exported to the cloud in batches.
- Per-app traffic statistics.
- Rule precedence: tenant rules > user rules (if allowed) > per-app policy > default action.
  First match wins inside each layer.
- Tenant mandates are absolute (security review D1, 2026-11-19). A tenant per-app entry cannot
  be overridden by a user per-app entry. Under tenant Lockdown, user rules can only block, so a
  user `allow` rule is ignored, and per-app allows only count if they come from the tenant layer.

## Deliberately out of scope for this slice

Local-only mode without an Edge (needs a userspace TCP/IP forwarder), SNI inspection,
iOS, OIDC login (a provisioning key is used instead), Postgres (SQLite in dev).
