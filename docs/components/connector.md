# Connector

## Purpose
The Connector is a customer-managed data-plane component deployed within private datacenters, cloud VPCs, or branch networks adjacent to internal applications. It makes private Application Segments reachable through the OpenSASE fabric without requiring inbound firewall ports, public IP addresses, or external DNS records. By establishing redundant outbound-only multiplexed mTLS tunnels to multiple Edges, it dynamically terminates Microtunnels and forwards application payload streams locally over TCP or UDP. Operating as part of a Connector Group, it delivers local health monitoring, automatic failover, and active-active load balancing.

## Responsibilities
- Enroll into the tenant Control Plane using a single-use Provisioning Key to obtain an identity certificate from the tenant CA.
- Establish and maintain N redundant outbound mTLS multiplexed transport connections (HTTP/2 or QUIC) across distinct Edges.
- Listen for inbound Microtunnel dispatch requests delivered over the multiplexed transport sessions from connected Edges.
- Resolve internal application hostnames through customer local DNS infrastructure, supporting split-horizon and private zones.
- Dial local private applications over TCP or UDP and stitch the local socket streams directly to incoming Microtunnels.
- Execute continuous synthetic health checks (TCP connect, HTTP/HTTPS response validation, ICMP ping) against configured Application Segments.
- Report local application reachability, latency, and connector health metrics upstream to the Control Plane and connected Edges.
- Join a Connector Group to support horizontal scaling, geographic distribution, and active-active fault tolerance.
- Buffer and manage local flow backpressure and stream flow control during bursty application traffic transfers.
- Execute in-place automated software updates using signed binary verification without dropping established user connections.
- Enforce tenant isolation by verifying cryptographic tenant identifiers on every incoming Microtunnel dispatch command.
- Terminate stale, timed-out, or broken application socket connections cleanly and propagate connection resets across the Microtunnel.
- Maintain localized metrics counters covering active Microtunnels, throughput, DNS latency, and upstream link health.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Control Plane | gRPC over mTLS | Outbound | Component enrollment, configuration sync, health reporting, and telemetry export |
| Edge | HTTP/2 or QUIC over mTLS | Outbound | Multiplexed transport for control signaling and data-plane Microtunnels |
| Private Applications | TCP / UDP / ICMP | Outbound | Local application socket connections and payload streaming |
| Local DNS Server | DNS (UDP/TCP port 53) | Outbound | Resolution of internal Application Segment domain names and SRV records |
| Local Systemd / Host | POSIX signals / IPC | Inbound | Process lifecycle management, graceful shutdown, and service supervision |

## Key design decisions
- **Transport protocol to Edge**: Proposed: Outbound mTLS over HTTP/2 or QUIC with multiplexed binary data streams, providing protocol standard compliance and middlebox traversal. Alternative: Outbound WireGuard tunnel mesh with userspace routing tables terminating at the Edge.
- **Application traffic binding level**: Proposed: Layer 4 stream-level Microtunnel proxying (terminating TCP/UDP and dialing locally per session) to enforce strict per-application zero trust isolation. Alternative: Layer 3 network routing using GRE or GENEVE overlays bridging entire subnet ranges into the fabric.
- **Packaging and deployment formats**: Proposed: Single statically linked Linux Go binary distributed as a native systemd unit, an OCI container image, and cloud VM images (AMI/OVA). Alternative: Dedicated appliance operating system distribution (JeOS ISO) managed exclusively via a locked console.
- **High availability coordination model**: Proposed: Decentralized Edge-coordinated scheduling where Edges dynamically route Microtunnels across healthy connectors in the Connector Group without connector-to-connector clustering. Alternative: Distributed consensus clustering (Raft or Gossip) running locally between Connectors in the same group.
- **Application health probing architecture**: Proposed: Integrated background health checking loop periodically testing configured Application Segments and publishing status over the existing edge control stream. Alternative: External health monitoring daemon reporting reachability to an independent control plane API.
- **Microtunnel flow control strategy**: Proposed: End-to-end window updates mapped between local TCP sockets and HTTP/2 or QUIC stream credits to prevent memory bloat during speed mismatches. Alternative: Unbounded userspace ring buffers with aggressive TCP packet dropping when thresholds are exceeded.

## Security considerations
- Zero inbound network exposure: Connector opens no listening TCP or UDP ports on external or internal interfaces, eliminating perimeter attack surfaces.
- All communications with Edges and the Control Plane require mutual TLS (mTLS) with short-lived x509 certificates and automated in-memory rotation.
- Process privilege minimization: Runs as an unprivileged dedicated service user (`appconnector`) with Linux capabilities restricted to `CAP_NET_BIND_SERVICE` dropped.
- Cryptographic isolation: Every Microtunnel dispatch frame includes signed tenant metadata; connectors reject flows not matching their enrolled tenant identity.
- Provisioning Keys are single-use or time-bound, immediately invalidated upon successful enrollment, and revoked if reused.
- Local memory handling: Payload buffers are sanitized after session termination to mitigate memory leak vulnerabilities across multi-user sessions.
- Secure local storage: Enrolled certificates, private keys, and cached configs are stored in root-owned, mode 0600 file paths or in-memory tmpfs mounts.

## Failure modes & HA
- **Connector instance crash**: Edges detect broken multiplexed connections via heartbeat loss and automatically re-route subsequent Microtunnels to alternate members in the Connector Group.
- **Edge PoP outage**: Outbound transport maintains active tunnels to multiple diverse Edges; if one PoP becomes unreachable, traffic routes through surviving edge tunnels.
- **Internal application unreachable**: Local health checking detects down targets and notifies Edges, which instantly fail over or return descriptive HTTP/TCP errors to the Client.
- **Local DNS failure**: Intermittent DNS resolution failures trigger immediate negative acknowledgments back to the Edge, preventing hung client connection states.
- **Control Plane disconnection**: Connectors continue processing Microtunnels from Edges uninterrupted using cached Application Segment configurations.
- **Network congestion / backpressure**: Stream-level HTTP/2 or QUIC window exhaustion applies immediate backpressure upstream to prevent connector memory exhaustion.
- **Certificate expiry during network partition**: Retains an automated grace period on cached valid certificates while continuing background retry attempts against the tenant CA.

## MVP scope vs later
- **MVP**:
  - Linux binary (systemd) and Docker container deployments.
  - Automated enrollment using a one-time Provisioning Key and mTLS certificate issuance.
  - Outbound multiplexed mTLS over HTTP/2 to multiple Edges.
  - Microtunnel setup and bidirectional proxying for TCP Application Segments.
  - Membership in a Connector Group for active-active redundancy.
  - Configurable TCP connect and HTTP status synthetic health checks.
  - Structured JSON logging and OpenTelemetry metric reporting.
- **Later**:
  - Full UDP proxying support for voice, video, and custom enterprise UDP protocols.
  - QUIC / HTTP/3 transport implementation to mitigate TCP head-of-line blocking on lossy WAN links.
  - Pre-packaged VM appliance images (AWS AMI, Azure VHD, VMware OVA) with cloud-init bootstrap support.
  - Server-initiated connection flows enabling bidirectional support for datacenter-to-user workflows.
  - Zero-downtime auto-update supervisor with graceful connection handoff and automated rollback.
  - Active-passive standby pairing options for resource-constrained branch locations.

## Open questions
- Should HTTP/2 or QUIC be the mandatory default transport for connector-to-edge multiplexing in the initial implementation?
- How should high-bandwidth TCP window scaling and backpressure be managed across multiplexed streams during bursty transfers?
- What is the most effective approach for supporting server-initiated flows without compromising the outbound-only firewall posture?
- Should local health checks be delegated to an independent worker process to isolate application failure handling from data forwarding?
- How should DNS caching and TTL enforcement be handled when local corporate DNS returns short-lived round-robin records?

## Effort drivers
- Implementing robust stream multiplexing, flow control, backpressure handling, and buffer management over long-lived mTLS connections.
- Managing reliable zero-downtime process handovers and graceful connection draining during software updates.
- Achieving low-latency UDP session tracking and packet replication over stream-based edge tunnels.
- Handling complex enterprise DNS configurations, including search domains, split-horizon DNS, and transient resolution timeouts.
- Ensuring rock-solid stability and memory containment under heavy concurrent connection loads and slow application backends.
