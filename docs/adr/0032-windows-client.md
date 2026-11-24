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
   - **Slice B (Daemon and Service):** Background tunnel process managing adapter configuration and routing without requiring user elevation for the desktop UI.
     - **Slice B1 (Shared Daemon & Unix API):** Shared platform package (`internal/clientnet`), desktop daemon core (`internal/desktop`), local JSON API over Unix domain socket with group and peer credential checks, and systemd unit (`opensased.service`).
     - **Slice B2 (Windows Service & Named Pipe):** Windows service integration (`opensased` running as a Windows service) and local API exposed over a secured Windows named pipe with access control lists.
   - **Slice C (Desktop UI):** Cross-platform Flutter desktop client (Linux and Windows) for connection management, policy viewing, and status display.
   - **Slice D (Installer):** An MSI package bundling the executable, Windows service registration, and signed `wintun.dll`.

## Desktop daemon and local API (slice B)

To allow an unprivileged desktop UI (slice C) to control the client on both Linux and Windows, slice B introduces a background daemon (`opensased`) and a shared network package (`internal/clientnet`):

1. **Shared Platform Network Package (`internal/clientnet`):**
   - Encapsulates interface allocation (`CreateTUN`), network configuration (`Configure`), and route planning across operating systems.
   - On Windows, verifies `wintun.dll` next to the executable and applies interface configuration via `winipcfg`.
   - On Linux, manages link MTU, tunnel addressing, and routing via `ip(8)`.

2. **Desktop Daemon Core (`internal/desktop`):**
   - The daemon owns an instance of `mobile.Engine` and tracks connection state (`IsConnected`), route cleanup handles, and a FIFO ring buffer of the last 200 engine events.
   - Exposes a local HTTP/1.1 JSON API over a local transport (Unix domain socket in slice B1; Windows named pipe in slice B2):
     - `GET /v1/status`: Engine status JSON plus `connected` boolean.
     - `POST /v1/connect`: Idempotent tunnel setup (creates TUN, calls `StartDevice`, applies routing and DNS).
     - `POST /v1/disconnect`: Idempotent tunnel teardown (undoes routing/DNS, stops engine, closes TUN).
     - `POST /v1/enroll`: Submits provisioning key, control URL, and device name; refused with HTTP 409 while connected.
     - `POST /v1/unenroll`: Teardown and state deletion.
     - `GET /v1/flows?limit=N`: Returns recent network flow records.
     - `GET /v1/events`: Server-Sent Events (SSE) stream that replays the last 200 events from the ring buffer and pushes real-time engine events, limited to 8 concurrent streams.

3. **Access Control and Defense in Depth:**
   - **Socket / Pipe Permissions:** On Unix, the socket directory is mode `0750` and the socket file is mode `0660`, owned by the `opensase` group (falling back to root-only `0600` if the group is absent). In slice B2, Windows named pipes will configure security descriptors restricting access to Administrator and designated user groups.
   - **Peer Credential Verification:** On Linux, each connection is checked using `SO_PEERCRED` to ensure the caller UID is 0 or a member of the configured group. Non-Linux Unix platforms use a permissive stub, to be augmented for Windows in slice B2.
   - **Host Header Check:** Requests with a `Host` header other than `localhost` (with optional port) or empty are rejected with HTTP 403 to prevent DNS rebinding attacks if a browser or proxy interacts with the local endpoint.
   - **Payload Bounds:** Request bodies are capped at 64 KiB, and unknown JSON fields are rejected (HTTP 400).

4. **UI Isolation:**
   - The desktop UI process never holds private keys, certificate material, or session tokens. All cryptographic operations, key generation, and CSR signing remain enclosed within the daemon state directory. Provisioning keys are never returned in responses or recorded in logs.

## Windows service and named pipe (slice B2)

Slice B2 implements Windows service integration and named pipe local API delivery for `opensased`:

1. **Service Registration and Lifecycle (`cmd/opensased`):**
   - `opensased install`: Connects to the Service Control Manager via `golang.org/x/sys/windows/svc/mgr` and registers the service `OpenSASE` (Display Name: "OpenSASE client") with automatic start (`StartAutomatic`) pointing to the executable with argument `run`. Configures failure recovery actions to restart after 5 seconds up to 3 times. Registers the Windows event log source `OpenSASE`.
   - `opensased uninstall`: Stops the running service, deletes the service from the SCM, and removes the event log source.
   - `opensased run`: Detects SCM execution via `svc.IsWindowsService()`. Under SCM, it runs `svc.Run` with a service handler accepting `Stop` and `Shutdown`, reporting transitions (`StartPending`, `Running`, `StopPending`, `Stopped`), and gracefully disconnecting any active tunnel (undoing physical bypass routes and adapter DNS/routes) within a 20-second timeout window. When executed outside the SCM, it runs in the foreground for console debugging until interrupted (Ctrl+C).
   - **Logging:** Daemon events are recorded to both stderr and the Windows event log (`OpenSASE` source) at Info and Error level. Keying material and tokens are never logged.

2. **Named Pipe Listener with SDDL:**
   - The daemon listens on named pipe `\\.\pipe\opensase` using `github.com/Microsoft/go-winio` (`winio.ListenPipe`) with `MessageMode: false`.
   - **Security Descriptor (SDDL):** `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`
     - `SYSTEM` (`SY`) and Built-in `Administrators` (`BA`): Granted `GENERIC_ALL` (`GA`).
     - `Interactive Users` (`IU`): Granted `GENERIC_READ | GENERIC_WRITE` (`GRGW`), allowing the desktop UI running in the logged-in user's desktop session to communicate with the daemon.
     - Remote/network callers receive no access because only `IU` is granted among non-admin principals.

3. **Privilege Separation and Admin-Only Operations:**
   - When serving requests over the named pipe, the daemon identifies the caller's token in `ConnContext` by impersonating the pipe client (`windows.ImpersonateNamedPipeClient`) or resolving the peer process token via `GetNamedPipeClientProcessId`.
   - **Interactive User Operations:** Any connected interactive user is allowed to read status (`GET /v1/status`), view recent flows (`GET /v1/flows`), stream events (`GET /v1/events`), and initiate tunnel connections (`POST /v1/connect`) or disconnections (`POST /v1/disconnect`).
   - **Admin-Only Operations:** Operations that mutate sensitive device identity—`POST /v1/enroll` and `POST /v1/unenroll`—are guarded by an admin check middleware. The middleware requires the caller token to be a member of `Administrators` (`S-1-5-32-544`) and elevated (`TokenIsElevated != 0`). Non-admin callers or callers whose token cannot be identified receive HTTP 403 Forbidden.
   - On Linux, this is unified under `allowAdminOp(ctx)`, where enroll/unenroll are restricted to root (UID 0) or the daemon user.
   - **State Directory ACL:** The state directory defaults to `%ProgramData%\OpenSASE` and is initialized with a protected DACL restricting access to `SYSTEM` and `Administrators` (`mobile.restrictPath` semantics).

## Consequences

- **Administrator Privileges Required (Slice A):** Because slice A runs interactively as a console application, configuring network interfaces, IP addresses, and routing tables on Windows requires running the process with Administrator privileges. Slice B will eliminate this requirement for end users by introducing a background service.
- **Fail-Closed Forwarding on Process Termination:** In slice A, if the client process is forcibly terminated (e.g. killed via task manager), the routes on the physical interface may remain until reset or adapter restart, and there is no kernel-level firewall filter to prevent unencrypted traffic leaks. A future slice will add Windows Filtering Platform (WFP) filters to enforce fail-closed leak prevention.
- **IPv6 Leak Limitation:** When the tunnel configuration allocates an IPv6 address, IPv6 split routes (`::/1` and `8000::/1`) are installed into the tunnel. However, if the session does not provide an IPv6 address, physical IPv6 default routes remain in place and IPv6 traffic will continue to route over the physical interface. This is a known limitation until WFP-based IPv6 filtering is introduced.
