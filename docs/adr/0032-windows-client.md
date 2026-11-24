# ADR-0032: Windows platform layer for OpenSASE client

Status: accepted (2026-11-24)

## Context

OpenSASE has a portable client core (`mobile.Engine`) shared between the mobile application and the desktop client (`cmd/opensase-client`). The core handles enrollment, post-quantum session negotiation (`pkg/pqsession`), WireGuard protocol encapsulation, packet parsing (`pkg/packet`), firewall policy enforcement (`pkg/firewall`), and local DNS filtering (`pkg/dnsfilter`).

However, the desktop client's platform integration in `cmd/opensase-client` was initially Linux-specific, relying on `/dev/net/tun`, Linux `ip(8)` routing commands, iptables packet forwarding, `/proc/sys` sysctls, and `/etc/resolv.conf` hints.

To support Windows desktop users (issue #31), a platform layer is required to configure network devices, interface addresses, routing tables, and DNS settings natively on Windows while keeping the Go core and portable codebase unchanged.

## Decision

Issue #31 slice A implements the Windows platform layer for `cmd/opensase-client`:

1. **Wintun TUN Adapter:**
   - Wintun is used as the virtual network adapter driver on Windows via `golang.zx2c4.com/wireguard/tun`.
   - `wintun.dll` must be placed in the same directory as the client executable (`os.Executable`). Before calling `tun.CreateTUN`, the client checks that `wintun.dll` exists and produces a clear error directing the user to place the signed `wintun.dll` from the official Wintun distribution there if missing.
   - The default TUN adapter name on Windows is `OpenSASE` (compared to `osase0` on Linux).

2. **Network and Route Configuration via winipcfg:**
   - Low-level network configuration is performed using `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg`.
   - The Wintun adapter LUID is obtained directly from the native TUN handle (`tun.NativeTun.LUID()`) or through index lookup (`winipcfg.LUIDFromIndex`).
   - The tunnel interface IP addresses (/32 for IPv4 and /128 for IPv6) are assigned using `(LUID).SetIPAddressesForFamily`.
   - MTU and a low interface metric (1) are set via `(LUID).IPInterface(family)` to ensure tunnel traffic priority.
   - DNS servers provided by the session configuration are configured directly on the adapter via `(LUID).SetDNS(family, servers, domains)`.
   - All state modifications are logged with `log/slog` at `Info` level recording prefix, gateway, and interface index only.

3. **Split Default Routes and Bypass Host Routes:**
   - The physical default route and its next-hop gateway are located by querying `winipcfg.GetIPForwardTable2`, excluding the Wintun adapter's LUID.
   - Host routes (`/32`) for all bypass targets (such as Control Plane and Edge endpoints) are resolved via `net.DefaultResolver` and installed on the physical interface via the physical default gateway. Resolution failures are skipped with a warning, matching Linux behavior.
   - Split default routes (`0.0.0.0/1` and `128.0.0.0/1`, plus `::/1` and `8000::/1` if IPv6 is allocated) are installed into the Wintun adapter. This overrides the physical default route without deleting it.
   - A pure, OS-independent helper `windowsRoutePlan(c netConfig, bypassIPs []netip.Addr, gw netip.Addr) []plannedRoute` computes the route table entries and deduplicates duplicate bypass addresses.

4. **Teardown and Cleanup:**
   - On shutdown or exit, the client removes the installed bypass host routes from the physical interface and flushes the routes and DNS configurations on the Wintun adapter via `(LUID).FlushRoutes` and `(LUID).FlushDNS`.

5. **Gateway Mode is Linux-Only:**
   - Workload Gateway mode (`-gateway`, `-geneve-listen`, `-gateway-routed`, `-geneve-cidrs`, `-health-listen`) relies on Linux iptables and packet forwarding. On Windows, setting any gateway flag is rejected with a clear error at startup through a platform capability check (`gatewaySupported() bool`).

6. **Roadmap for Subsequent Slices (Issue #31):**
   - **Slice B (Windows Service):** Run the background tunnel process as a Windows service under `LocalSystem` to manage adapter configuration without requiring interactive user elevation.
   - **Slice C (Desktop UI):** Notification area / system tray interface for connection control, status display, and user feedback.
   - **Slice D (Installer):** An MSI package bundling the executable, Windows service registration, and signed `wintun.dll`.

## Consequences

- **Administrator Privileges Required (Slice A):** Because slice A runs interactively as a console application, configuring network interfaces, IP addresses, and routing tables on Windows requires running the process with Administrator privileges. Slice B will eliminate this requirement for end users by introducing a background service.
- **Fail-Closed Forwarding on Process Termination:** In slice A, if the client process is forcibly terminated (e.g. killed via task manager), the routes on the physical interface may remain until reset or adapter restart, and there is no kernel-level firewall filter to prevent unencrypted traffic leaks. A future slice will add Windows Filtering Platform (WFP) filters to enforce fail-closed leak prevention.
- **IPv6 Leak Limitation:** When the tunnel configuration allocates an IPv6 address, IPv6 split routes (`::/1` and `8000::/1`) are installed into the tunnel. However, if the session does not provide an IPv6 address, physical IPv6 default routes remain in place and IPv6 traffic will continue to route over the physical interface. This is a known limitation until WFP-based IPv6 filtering is introduced.
