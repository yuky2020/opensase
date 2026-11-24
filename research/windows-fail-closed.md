# Windows fail-closed (kill switch) with the Windows Filtering Platform

Research for OpenSASE issue #38. Date: 2026-11-24.

Question: how open-source WireGuard-based clients implement a kill switch on Windows with the Windows
Filtering Platform (WFP): filter layers, sublayer weights, persistent vs dynamic sessions, DNS leak
handling, and what happens when the service crashes. Then, what this means for `opensased`
(ADR-0032 lists the fail-closed filters as missing).

Scope of sources: the reference open-source implementation, **WireGuard for Windows
`golang.zx2c4.com/wireguard/windows@v1.1.1`**, which OpenSASE already depends on (`go.mod` line 17).
I read it from the local module cache, `~/go/pkg/mod/golang.zx2c4.com/wireguard/windows@v1.1.1/`, and
the paths below are relative to that directory. Platform behaviour comes from the official WFP
documentation on learn.microsoft.com. Other WireGuard-based Windows clients are left out because each
of them is a commercial product, which the brief excludes.

---

## 1. Platform facts (official WFP documentation)

### 1.1 Arbitration: layers, sublayers, weights

From *Filter Arbitration* (https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration):

- "Each filter layer is divided into sub-layers ordered by priority (also called weight). Network
  traffic traverses sub-layers from the highest priority to the lowest priority."
- "Within each sub-layer, filters are ordered by weight." Within a sublayer, evaluation stops at the
  first matching filter that returns Permit or Block: "Skip the remaining filters and return the
  action from the last evaluated filter."
- Across sublayers: "Evaluate all sub-layers even if a higher priority sub-layer has decided to block
  the traffic." Basic policy: "'Block' overrides 'Permit'", and a hard Block is final.
- Default action strength: a filter **permit is a soft permit** and a filter **block is a hard
  block**. Setting `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` makes the action hard. A hard permit can then
  be overridden only by a callout Veto.
- "Since there is no cross-layer arbitration, traffic permitted with 'Hard Permit' may still be
  blocked at another layer."

Consequence: a kill switch needs its own sublayer, holding a low-weight "block all" and higher-weight
"permit X" filters. Our permits never override blocks in *other* sublayers, such as the built-in
Windows Firewall sublayers, because a soft permit loses to any block. Our hard block still applies even
when another sublayer permits.

### 1.2 Filter weights

From *FWPM_FILTER0* (https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
and *Filter Weight Assignment* (https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment):
a weight can be an `FWP_UINT64` (used as is), `FWP_EMPTY` (automatic, in [0, 2^60)), or an
`FWP_UINT8` 0–15. With the 0–15 form, "BFE automatically generates the low-order 60 bits ... and then
uses the supplied value to set the 4 high-order bits", which splits the weight space into 16 ranges.

### 1.3 Session and object lifetimes

From *Object Management* (https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) and
*FWPM_SESSION0* (https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0):

- A session "ends either when the client calls FwpmEngineClose0 or the client process terminates"
  (RPC rundown).
- `FWPM_SESSION_FLAG_DYNAMIC`: "any objects added during the session are automatically deleted when
  the session ends."
- The four lifetimes:
  - **Dynamic** objects live until deleted or until the owning session ends.
  - **Static** objects (the default) live "until they are deleted, BFE stops, or the system is
    shutdown".
  - **Persistent** objects (`FWPM_*_FLAG_PERSISTENT`) live "until they are deleted" and are re-added
    when BFE starts.
  - **Built-in** objects are predefined by BFE.
- **Boot-time** filters (`FWPM_FILTER_FLAG_BOOTTIME`) are "added to the system when the TCP/IP driver
  starts, and removed when BFE finishes initialization". They cannot be combined with `PERSISTENT`
  (FWPM_FILTER0 flag table).
- Provider gating: "At service start, BFE only adds persistent objects to the system if they are not
  associated with a provider, or the associated provider has no Windows service name, or the
  associated Windows service is set to auto-start." FWPM_FILTER0 adds that such filters show up with
  `FWPM_FILTER_FLAG_DISABLED` otherwise.
- Reference rule: "A persistent object cannot refer to a dynamic object, a static object, or a
  persistent object owned by a different provider." So persistent filters need a persistent provider
  and a persistent sublayer.
- Transactions are ACID. If `txnWaitTimeoutInMSec` is 0, the lock wait defaults to 15 s.

### 1.4 ALE layers

From *Application Layer Enforcement*
(https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-):

- ALE layers are stateful and classify "per-connection or per-socket operation".
- They are "the only WFP layers where network traffic can be filtered based on the application
  identity ... and based on the user identity—using a security descriptor".
- Dual-stack caveat: "classifications at the IPv4 ALE layer may not occur" for true dual-IP sockets.
  Such traffic is seen at the V6 layer as IPv4-mapped addresses. A kill switch therefore has to cover
  both the V4 and the V6 layers.

### 1.5 Service SID

From *SERVICE_SID_INFO* (https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info):
with `SERVICE_SID_TYPE_UNRESTRICTED`, "the service SID is added to the service process token" as an
owner group. The account name is `NT SERVICE\<SvcName>`.

The MSI `MsiServiceConfig` table (Windows Installer 5.0+) can set this through `ConfigType`
`SERVICE_CONFIG_SERVICE_SID_INFO` (5) (https://learn.microsoft.com/en-us/windows/win32/msi/msiserviceconfig-table).
The same page notes that changes made through this table take effect "the next time the system is
started". That matters for the installer path; see §4.

---

## 2. Reference implementation: WireGuard for Windows v1.1.1 `tunnel/firewall`

Files: `tunnel/firewall/blocker.go` (188 lines), `rules.go` (1221), `helpers.go` (148),
`types_windows.go`, `syscall_windows.go`. License: MIT (SPDX header in every file).

### 2.1 Public API

```go
func EnableFirewall(luid uint64, doNotRestrict bool, restrictToDNSServers []netip.Addr) error
func DisableFirewall()
```

- The package keeps one global `wfpSession`. `EnableFirewall` returns an error if it is already
  enabled (`blocker.go`).
- The package only *adds* WFP objects. Its syscall bindings are EngineOpen/Close, TransactionBegin,
  Commit and Abort, ProviderAdd, SubLayerAdd, FilterAdd, GetAppIdFromFileName and FreeMemory
  (`syscall_windows.go`, `zsyscall_windows.go`). There is no FilterDelete or enumeration, and the
  package never uses the `cFWPM_FILTER_FLAG_PERSISTENT`/`BOOTTIME` constants it declares
  (`types_windows.go:184-185`). Cleanup happens only by closing the dynamic session.

### 2.2 Session, provider, sublayer (`blocker.go`)

- `createWfpSession`: `flags: cFWPM_SESSION_FLAG_DYNAMIC` and `txnWaitTimeoutInMSec: windows.INFINITE`.
- `registerBaseObjects`: the provider and the sublayer get **random GUIDs** (`windows.GenerateGUID()`)
  on every enable. Sublayer weight is `^uint16(0)` (0xFFFF, the maximum), so the WireGuard sublayer is
  evaluated before every other sublayer.
- Everything is installed inside one transaction (`runTransaction` in `helpers.go`). On failure the
  transaction is aborted and the engine closed, so a half-installed rule set is never committed.

### 2.3 Rule set and weights (`blocker.go` `EnableFirewall`, `rules.go`)

All filters live in the one sublayer and use `FWP_UINT8` weight ranges. They sit only at the four ALE
layers `ALE_AUTH_CONNECT_V4/V6` (outbound) and `ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound).

| Weight | Function (rules.go) | Action | Conditions |
|---|---|---|---|
| 15 | `permitWireGuardService` | **hard** permit (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) | `ALE_APP_ID` == own exe (from `FwpmGetAppIdFromFileName0(os.Executable())`) **AND** `ALE_USER_ID` matches a security descriptor granting only the process's *service SID* |
| 15 | `blockDNS` (allow part) | permit | remote port 53, UDP or TCP, remote address ∈ configured DNS servers |
| 14 | `blockDNS` (deny part) | block | remote port 53, UDP or TCP |
| 13 | `permitLoopback` | permit | `FWPM_CONDITION_FLAGS` has `FWP_CONDITION_FLAG_IS_LOOPBACK` |
| 12 | `permitTunInterface` | permit | `IP_LOCAL_INTERFACE` == tunnel LUID |
| 12 | `permitDHCPIPv4` / `permitDHCPIPv6` | permit | UDP 68→67 to 255.255.255.255, and DHCPv6 546↔547 to ff02::1:2 / ff05::1:3 from fe80::/10 |
| 12 | `permitNdp` | permit | ICMPv6 types 133–137 (router/neighbour discovery, redirect) |
| 0 | `blockAll` | block | none (matches everything) |

Notes from the code:

- The DNS deny filter has weight 14, above `permitTunInterface` at 12. Port-53 traffic to a server
  that is not configured is therefore blocked **even inside the tunnel**. `blockDNS` returns an error
  if the allow weight is not greater than the deny weight.
- The DNS rules are installed only if `restrictToDNSServers` is non-empty, and only in restrict mode.
- The service permit pairs the app ID with the service SID: "This prevents other processes hosted in
  the same exe from matching this filter" (`rules.go:149-151`). `getCurrentProcessSecurityDescriptor`
  (`helpers.go`) looks for an `S-1-5-80-…` group that is ENABLED|ENABLED_BY_DEFAULT|OWNER in the
  process token. If there is none, it returns `ERROR_NO_SUCH_GROUP`, and `EnableFirewall` fails. The
  manager installs tunnel services with `SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED`
  (`manager/install.go:173`) to make sure the SID is there.
- `permitHyperV` (an L2 `MAC_FRAME_NATIVE` permit) exists but is commented out ("try enabling it" if
  somebody complains).

### 2.4 When the kill switch is active (`tunnel/addressconfig.go:165-177`, `docs/netquirk.md`)

```go
doNotRestrict := true
if len(conf.Peers) == 1 && !conf.Interface.TableOff {
    for _, allowedip := range conf.Peers[0].AllowedIPs {
        if allowedip.Bits() == 0 && allowedip == allowedip.Masked() { doNotRestrict = false; break }
    }
}
return firewall.EnableFirewall(uint64(luid), doNotRestrict, conf.Interface.DNS)
```

- Restrict mode turns on only for **one peer with an exact `/0`** allowed IP.
- With `doNotRestrict == true`, the service-permit filter is still installed. This is "One firewall rule
  is added, however, which allows the tunnel service to send and receive WireGuard packets"
  (netquirk.md).
- `docs/netquirk.md` states it outright: using `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`)
  instead of `/0` "achieves nearly the same thing, but does not activate the above firewalling
  semantics". **OpenSASE's split-default routes are exactly this non-kill-switch shape.**
- The DNS rule exists to defeat Windows' "ordinary multihomed DNS resolution behavior" (netquirk.md,
  linking the Windows DNS client documentation). Without it, the DNS client can query the DNS servers
  of every interface.

### 2.5 Ordering in the service (`tunnel/service.go:190-215`, `tunnel/interfacewatcher.go:148-190`)

1. The adapter is created and `PreUp` runs.
2. **`enableFirewall` runs** before privileges are dropped (`elevate.DropAllPrivileges`) and before the
   peer configuration is pushed and the adapter brought up. Fail-closed is therefore in place before
   any tunnel traffic can flow.
3. Addresses, routes and DNS are set asynchronously by `interfaceWatcher` (`configureInterface`). The
   service also turns off router discovery and DAD on the tunnel interface (`addressconfig.go`).
4. Teardown (`interfaceWatcher.Destroy`) runs `Flush{Routes,IPAddresses,DNS}` for both families, then
   `firewall.DisableFirewall()` (closes the session).

### 2.6 Behaviour on crash

The session is dynamic. Per §1.3, filters disappear as soon as the process terminates, including on a
crash or when the process is killed. **WireGuard for Windows fails open on service death.** It makes no
attempt to persist filters. I found no `SetRecoveryActions` in `manager/` or `tunnel/` in v1.1.1, so
v1.1.1 itself does not restart a crashed tunnel service either. The design favours "never leave the
machine bricked" over "never leak during a crash window".

---

## 3. Current OpenSASE state (from the repository, read-only)

- `docs/adr/0032-windows-client.md`, Consequences section, has no kernel-level filter. After the
  process is killed, the bypass host routes and split routes may stay behind. There is an **IPv6
  leak** when the session has no IPv6 address, because the physical v6 default stays in place.
- `internal/clientnet/windows.go` `configurePlatform` works in this order:
  1. sets MTU and metric 1;
  2. sets the addresses;
  3. calls `SetDNS` on the tunnel;
  4. resolves `c.Bypass` with `net.DefaultResolver` (on Windows this goes through the system DNS
     client service, not through `opensased`'s own sockets);
  5. installs `/32` bypass routes via the physical gateway, plus `0/1` and `128/1` (and `::/1`,
     `8000::/1` only if IPv6 is allocated).

  `undo` deletes the bypass routes and flushes the routes and DNS on the tunnel.
- `internal/desktop/daemon.go` `Connect` creates the TUN, then calls `eng.StartDevice`, then
  `netMgr.Configure`. No firewall step exists. `Disconnect` calls `undo()` and then `eng.Stop()`.
- `cmd/opensased/main_windows.go:163-185` builds `mgr.Config` **without a `SidType`**. Recovery is set
  to restart after 5 s, up to 3 times within 86400 s. `deploy/desktop/windows/opensase.wxs` installs
  the service with `ServiceInstall` and `util:ServiceConfig` (failure actions only) and sets no SID
  type either.
- `cmd/opensase-client/platform_windows.go` only stubs gateway mode. It has no firewall code.

The tunnel runs as userspace WireGuard over Wintun inside the `opensased` process. Encrypted UDP to the
Edge and HTTPS to the control plane therefore both come from `opensased.exe`. This is the same
"permit own process" shape that §2.3 handles.

---

## 4. What carries over to `opensased`, and the gotchas

1. **Importing `tunnel/firewall` as is works only partly.** The package is not `internal`, so it can be
   imported. However:
   - (a) `permitWireGuardService` requires a service SID in the token. The current service config has
     none, so `EnableFirewall` fails with `ERROR_NO_SUCH_GROUP`. Foreground `opensased run` outside the
     SCM, and `opensase-client` run as an elevated console app, will **always** fail.
   - (b) It is dynamic-only. It has one global session and no delete or enumeration. It cannot
     express persistent or boot-time filters.
   - (c) The display names and the provider say "WireGuard".
   - (d) Restrict and DNS behaviour come as one `doNotRestrict` flag. There is no hook for extra
     permits such as LAN access or bypass IPs.
2. **The SID type must be in place before the first start.** Add `SidType:
   windows.SERVICE_SID_TYPE_UNRESTRICTED` to `mgr.Config` (as `manager/install.go:173` does) and the
   equivalent `MsiServiceConfig`/WiX setting.

   The MSI table documentation says changes take effect "the next time the system is started". Verify
   on a real install whether the SID is present at first service start after an MSI install, or only
   after a reboot. *(Not verified here.)* An app-ID-only permit (with no user-ID condition) avoids the
   dependency but is weaker: any process launched from the same exe path matches.
3. **The order of DNS resolution and firewall changes.** Bypass hosts are resolved by the system DNS
   client (svchost), not by `opensased`. Once a `blockAll` is active, that lookup would be blocked
   unless the query goes to a DNS server that is permitted. Options:
   - resolve the bypass hosts *before* enabling restrict mode;
   - add explicit permits for the resolved bypass IPs (remote-address filters) on the physical
     interface;
   - rely on the app-ID permit only for the daemon's own connections, and accept that bypass *route*
     installation is just an optimisation.
4. **DNS leak handling.** With split routes and no WFP, Windows multihomed DNS can still send queries
   to the physical interface's servers (netquirk.md). The WireGuard pattern blocks port 53 unless the
   destination is a tunnel DNS server, with weights 15/14 above the tunnel permit at 12. That stops
   plain DNS on 53. It does **not** stop DNS-over-HTTPS or DNS-over-TLS on other ports. Those are caught
   only by `blockAll` (off-tunnel) in restrict mode. If `pkg/dnsfilter` answers on an address inside
   the tunnel, that address must be in the allow list.
5. **IPv6.** `blockAll` covers the V6 ALE layers, which closes ADR-0032's IPv6 leak *without* needing
   an IPv6 tunnel address. It also handles dual-stack sockets that are classified only at V6 (§1.4).
   DHCPv6 and NDP permits (types 133–137) are needed so the physical link keeps working.
6. **Crash window.** With a dynamic session, the 5 s SCM restart delay is a fail-open window. The
   physical bypass routes and split routes also persist (ADR-0032), and those split routes point at a
   Wintun adapter that is gone. Getting fail-closed across a crash needs persistent filters (§1.3).
   Persistent filters require a persistent provider and sublayer with fixed GUIDs, and bindings to
   `FwpmFilterDeleteById0`/enumeration that the upstream package lacks.

   Provider gating (§1.3) gives a built-in escape hatch: tie the provider to the `OpenSASE` service
   name, and BFE drops the persistent filters if the service is no longer auto-start, for example after
   an uninstall or when an admin disables the service. Startup must also remove stale objects by their
   fixed GUIDs before re-adding them.
7. **Boot-time filters** cover the gap before BFE starts but are removed "when BFE finishes
   initialization". They are only useful in combination with persistent filters, and they cannot be
   combined with `PERSISTENT` on the same filter.
8. **Hard vs soft.** Only the self-permit needs to be hard (`CLEAR_ACTION_RIGHT`), so that a block in
   another sublayer cannot cut the tunnel transport. This mirrors upstream. Our soft permits for the
   tunnel interface remain subject to Windows Firewall blocks, which is the right behaviour.

---

## 5. Implications for OpenSASE (input to a decision)

**Option A: reuse `golang.zx2c4.com/wireguard/windows/tunnel/firewall` (dynamic session).**
Call `EnableFirewall(luid, !killSwitch, dnsServers)` in `clientnet.configurePlatform` after the bypass
lookup and before the split routes. Call `DisableFirewall()` in `undo`. Add the service SID type to the
SCM and MSI install.

- Pros: small change; an upstream-audited rule set with MIT licence; atomic transaction; closes the
  IPv6 and DNS leaks while the daemon is alive.
- Cons: fails open on crash, during the 5 s restart window; "WireGuard" naming in the WFP UI; one global
  session; no LAN or bypass-IP permits; console mode never works (no service SID).

**Option B: own WFP package modelled on upstream, still dynamic.**
For example `internal/clientnet/wfp_windows.go`, with the same layers and weights, our own names, extra
permits (bypass IPs, an optional LAN), and app-ID-only matching in console mode.

- Pros: same crash semantics as A, but tailored; testable rule planning as a pure function, like
  `windowsRoutePlan`.
- Cons: about 1–1.5k lines of unsafe WFP struct code to maintain (upstream `rules.go` alone is 1221
  lines).

**Option C: B plus persistent "block all except self" filters.**
Use a fixed-GUID persistent provider tied to service name `OpenSASE` and a persistent sublayer, with
dynamic per-connection permits layered on top.

- Pros: true fail-closed across daemon crashes and reboots, which is what a SASE product's "always-on"
  usually means; provider gating avoids bricking after uninstall.
- Cons: a crashed or broken daemon leaves the user offline until it restarts or is uninstalled, which
  is a support burden. It needs an explicit admin "disable kill switch" path, plus startup
  reconciliation of stale filters. It needs a real Windows test matrix: uninstall, BFE restart,
  upgrade, and Safe Mode. This goes beyond what the upstream reference does.

**Cross-cutting, whatever the option:**

- add `SERVICE_SID_TYPE_UNRESTRICTED` to service creation and the MSI;
- put the kill-switch behaviour behind a per-device or per-policy flag, because upstream ties it to the
  `/0` route shape;
- clean up the bypass and split routes on next start, since they also survive a crash.

**Suggested direction (for discussion):** start with **A or B now** to close the live-process DNS and
IPv6 leaks. Prefer **B** if bypass and LAN permits and console-mode support are needed. Treat **C** as a
separate, explicitly decided "always-on" feature with its own ADR, because it changes the failure mode
from leaking to losing connectivity. Upstream WireGuard deliberately does not make that trade-off.

---

## Sources

- `golang.zx2c4.com/wireguard/windows@v1.1.1`:
  - `tunnel/firewall/blocker.go`, `rules.go`, `helpers.go`, `types_windows.go`, `syscall_windows.go`
  - `tunnel/addressconfig.go`, `tunnel/service.go`, `tunnel/interfacewatcher.go`
  - `manager/install.go`
  - `docs/netquirk.md`
- Filter Arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- Object Management: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- FWPM_SESSION0: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
- FWPM_FILTER0: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- Filter Weight Assignment: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment
- Application Layer Enforcement: https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-
- SERVICE_SID_INFO: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info
- MsiServiceConfig table: https://learn.microsoft.com/en-us/windows/win32/msi/msiserviceconfig-table
- OpenSASE (read-only):
  - `docs/adr/0032-windows-client.md`
  - `internal/clientnet/windows.go`
  - `internal/desktop/daemon.go`
  - `cmd/opensased/main_windows.go`
  - `cmd/opensase-client/platform_windows.go`
  - `deploy/desktop/windows/opensase.wxs`
