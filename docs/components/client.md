# Client

## Purpose
The Client is an endpoint daemon paired with a lightweight per-OS user interface deployed on user devices to steer traffic into the OpenSASE fabric. It authenticates users against their tenant IdP using standard OIDC flows, continuously gathers device Posture, and intercepts DNS queries for configured Application Segments. Operating against locally cached, cryptographically signed Policy Snapshots, it establishes encrypted WireGuard tunnels to the nearest Edge. In doing so, it enforces local bypass lists, trusted network detection, and tenant-configured fail-open or fail-closed semantics across all network transitions.

## Responsibilities
- Authenticate end users against the tenant IdP using OIDC authorization code flow with PKCE or device authorization flow.
- Retrieve, cryptographically verify, and locally cache immutable Policy Snapshots distributed from the Control Plane.
- Intercept endpoint DNS queries, identifying Application Segment FQDNs and mapping them to synthetic IPs drawn from a designated CGNAT range (100.64.0.0/10).
- Evaluate client Steering rules to determine which flows route through the Edge and which bypass the tunnel directly to the local network.
- Establish, manage, and monitor an encrypted WireGuard tunnel to the primary or secondary Edge using wireguard-go.
- Integrate directly with OS networking primitives: Windows Filtering Platform (WFP) and Wintun on Windows, NetworkExtension packet tunnel provider on macOS, TUN and nftables on Linux, and native VPN APIs on iOS and Android.
- Collect continuous endpoint Posture attributes including OS version, patch level, disk encryption status, firewall configuration, EDR running state, and installed certificates.
- Periodically stream Posture telemetry to the connected Edge and Control Plane for continuous session posture evaluation.
- Perform automated captive portal detection to pause tunnel establishment until the host completes local Wi-Fi authentication.
- Implement trusted network detection (TND) via gateway MAC, local subnet probing, and DNS reachability to suspend tunneling inside corporate premises.
- Enforce tenant-defined fail-open (direct breakout) or fail-closed (block non-essential traffic) behavior during network or fabric disconnection.
- Manage local route table integrity, preventing split-tunnel route flapping and DNS leaking during interface changes.
- Execute automated background software updates utilizing cryptographically signed release packages and staged installation pipelines.
- Provide real-time status and diagnostics to the local user interface for troubleshooting connectivity and policy status.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Tenant IdP | HTTPS / OIDC (PKCE, Device Code) | Outbound | User authentication and identity token acquisition |
| Control Plane | gRPC over mTLS | Outbound | Component enrollment, Policy Snapshot synchronization, and telemetry export |
| Edge | WireGuard over UDP | Outbound | Primary data-plane transport for steered application and internet flows |
| Edge | gRPC over mTLS / TLS | Outbound | In-session Posture metric updates and edge health keepalives |
| Local OS Network Stack | WFP, NetworkExtension, TUN/nftables | Bidirectional | Packet capture, virtual interface routing, and DNS interception |
| Local User / Tray UI | IPC (Named pipe / Unix domain socket) | Bidirectional | Daemon status reporting, login prompts, and diagnostics display |
| Local DNS Resolvers | DNS (UDP/TCP port 53) | Outbound | Recursive resolution for non-intercepted public and local domain queries |

## Key design decisions
- **Tunnel transport protocol**: Proposed: WireGuard implemented via wireguard-go with gVisor netstack fallback for high throughput, kernel efficiency, and rapid network roaming across Wi-Fi and cellular interfaces. Alternative: MASQUE (HTTP/3 CONNECT-IP) over QUIC to masquerade tunnel traffic as standard outbound HTTPS on port 443.
- **Application traffic steering and DNS interception**: Proposed: Local DNS interception mapping Application Segment FQDNs to synthetic IPv4/IPv6 addresses from the CGNAT block (100.64.0.0/10), routing synthetic destinations into the virtual tunnel interface. Alternative: Standard route injection redirecting enterprise subnet CIDR ranges without DNS synthesis.
- **Platform network driver integration**: Proposed: Dedicated platform-native packet capture engines (Windows WFP + Wintun driver, macOS NetworkExtension packet tunnel provider, Linux TUN + nftables). Alternative: Standalone userspace transparent proxy redirecting traffic via system SOCKS5 or PAC proxy settings.
- **Daemon and UI separation**: Proposed: Dual-process architecture comprising a privileged system background daemon and an unprivileged per-OS status bar application communicating via secure local IPC. Alternative: Single monolithic userspace application executing under the logged-in user context and invoking elevated system utilities via sudo or UAC prompts.
- **Policy evaluation mechanism**: Proposed: Local in-process evaluation of compiled routing and bypass tables directly derived from the signed Policy Snapshot. Alternative: Dynamic cloud lookup querying the nearest Edge on every newly initiated endpoint flow.
- **Fail-safe network posture**: Proposed: Configurable kernel packet filtering rules applied at driver initialization, maintaining deterministic fail-open or fail-closed states independent of userspace crashes. Alternative: Runtime userspace firewall scripting executed reactively upon detected disconnection events.

## Security considerations
- The background daemon runs with elevated system privileges; local IPC endpoints must authenticate client process identity (UID/SID verification) to avoid local privilege escalation.
- Policy Snapshots and auto-update binaries must be signed with ed25519 signing keys rooted in the tenant PKI to prevent unauthorized tampering or poisoned updates.
- Synthetic IP allocations must be strictly bounded within the virtual network adapter to prevent route hijacking, DNS leaks, or IP collision with local physical LAN networks.
- Endpoint Posture collectors must gather data directly from low-level OS APIs and verify cryptographic process signatures to resist evasion or manipulation by local users.
- In fail-closed configuration, the Client must engage persistent OS packet filters to prevent traffic leakage if the daemon crashes or is forcibly terminated.
- Sensitive credentials including OIDC refresh tokens and private keys must be stored within native OS credential vaults (Windows Credential Manager, macOS Keychain, Linux Secret Service).

## Failure modes & HA
- **Edge unavailability**: Client detects loss of edge keepalives and automatically fails over to the next closest PoP based on Anycast or GeoDNS priority lists.
- **Control Plane unreachable**: Continues normal data-plane forwarding and Steering based on the last validated Policy Snapshot cached in persistent local storage.
- **Captive portal encountered**: Temporarily suppresses tunnel activation and opens the host browser to complete network onboarding before initiating WireGuard handshakes.
- **Tunnel driver crash or network disruption**: Daemon engages an exponential backoff reconnection loop and resets OS routing tables to prevent permanent loss of network connectivity.
- **Total fabric disconnection**: Immediately executes tenant policy: fail-open reverts to direct local internet breakout, while fail-closed seals the network interface against non-essential egress.
- **Local DNS deadlocks**: Implements fallback to physical interface DNS if the internal synthetic DNS responder encounters unhandled errors.

## MVP scope vs later
- **MVP**:
  - Support for Linux (TUN + nftables), Windows 10/11 (Wintun) and macOS 12+ (NetworkExtension packet tunnel); Linux ships first.
  - Background Go daemon with minimal tray status UI and OIDC PKCE browser authentication.
  - WireGuard tunnel to Edge carrying ZTNA private flows only (internet traffic goes direct until Phase 2).
  - DNS interception mapping Application Segment FQDNs to synthetic CGNAT IPs.
  - Basic Posture collection (OS version, disk encryption state, firewall status).
  - Tenant-level fail-open/fail-closed toggle and static trusted network detection.
- **Later**:
  - iOS and Android support via native platform VPN APIs.
  - Advanced Posture collection (EDR API integration, client certificate validation, process hash checks).
  - MASQUE over QUIC (HTTP/3) transport fallback for networks blocking UDP port 51820.
  - Automated background self-update service with signed binary verification and staged rollouts.
  - Fast user switching, per-app split tunneling, and multi-tenant profile management.
  - Zero-touch enterprise deployment via MDM/GPO with automated device enrollment tokens.

## Open questions
- Should the fallback transport for UDP-restricted enterprise firewalls be MASQUE over QUIC, or WireGuard encapsulated inside TLS over TCP?
- What synthetic IP allocation strategy best guarantees conflict-free routing when enterprise internal networks already consume portions of 100.64.0.0/10?
- How can zero-drop connection handoff be maintained during background daemon updates across diverse desktop operating systems?
- Should posture collection plugins be implemented as sandboxed WebAssembly modules or compiled natively into the Go binary?
- How should multiple active physical network adapters (e.g., simultaneous Ethernet and Wi-Fi) be handled during trusted network detection?

## Effort drivers
- Maintaining divergent OS-specific network extensions across Windows WFP, macOS NetworkExtension, and Linux nftables with distinct lifecycle and sandbox constraints.
- Managing OS-specific edge conditions including system sleep/wake cycles, adapter transitions, split-DNS conflicts, and captive portal detection quirks.
- Minimizing kernel-to-userspace context switches and memory allocation overhead under high-throughput endpoint workloads.
- Hardening cross-privilege IPC mechanisms and driver installation packages against platform security controls and strict code-signing rules.
- Ensuring rock-solid stability in fail-closed modes to eliminate the risk of bricking user network access during software crashes.
