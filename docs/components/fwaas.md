# Firewall as a Service (FWaaS)

## Purpose
OpenSASE Firewall as a Service (FWaaS) provides centralized L3/L4 network security and stateful connection filtering for all traffic routed through the Edge via Client or Workload Gateway tunnels. It enforces bidirectional access policies using standard 5-tuple criteria enriched with tenant, user, group, and device posture identity context. Additionally, FWaaS governs outbound internet traffic via secure DNS inspection, source NAT, and dedicated per-tenant egress IP allocation.

## Responsibilities
- Intercept and inspect all incoming IP packets terminating from WireGuard tunnels across Clients and Workload Gateways.
- Evaluate stateful L3/L4 Firewall Rules matching on protocol, source/destination IP, source/destination port, user identity, group membership, and posture attributes.
- Provide secure DNS resolution (DNS-over-HTTPS / DoH) with threat intelligence domain filtering, category blocking, and split-horizon private DNS routing.
- Maintain stateful connection tracking tables for TCP, UDP, and ICMP sessions with configurable idle and TCP teardown timeouts.
- Execute Source Network Address Translation (SNAT) for internet-bound flows using shared or dedicated per-tenant public egress IPs.
- Forward flows destined for private Application Segments to the ZTNA microtunnel broker subsystem within the Edge.
- Steer eligible HTTP/HTTPS sessions into the local SWG proxy pipeline for Layer 7 TLS interception and inspection.
- Enforce bandwidth shaping and per-flow rate limiting to protect shared edge infrastructure from abusive traffic patterns.
- Emit flow telemetry records (session start, end, duration, bytes, packets, drop reasons) to the OpenTelemetry logging pipeline.
- Maintain policy enforcement parity across public multi-tenant Edges and single-tenant Private Edges.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Client / Workload Gateway | WireGuard (UDP) | Inbound to FWaaS | Ingress tunnel carrying raw L3 packets from endpoints and VPC workloads |
| Control Plane (Policy Compiler) | gRPC / Policy Snapshot | Inbound to FWaaS | Distribute compiled firewall rule tables, DNS domain blocklists, and egress IP mappings |
| SWG Proxy (Edge) | In-process / Loopback | Outbound from FWaaS | Hand off classified HTTP/HTTPS sessions for L7 inspection and filtering |
| ZTNA Broker (Edge) | In-process | Outbound from FWaaS | Hand off private traffic destined for Connector Groups |
| Upstream DNS / Threat Intel | DoH / DNS (UDP 53) | Outbound from FWaaS | Query recursive resolvers and synchronize domain category feeds |
| Internet / Destination | IP / SNAT | Outbound from FWaaS | Transmit permitted outbound non-HTTP packets to external destinations |
| Observability (OTel Collector) | OTLP (gRPC) | Outbound from FWaaS | Export session logs, flow drops, DNS queries, and network metrics |

## Key design decisions
- **Proposed:** Userspace packet filtering and stateful tracking implemented via gVisor netstack integration in the Go Edge binary.
  *Alternative:* Host-level Linux kernel eBPF (XDP/tc) or nftables filtering, which offers higher raw throughput but complicates multi-tenant context propagation and cross-platform deployment.
- **Proposed:** Integrated caching DNS-over-HTTPS (DoH) resolver embedded directly in Edge to intercept UDP 53 and DoH traffic, evaluating category rules prior to IP routing.
  *Alternative:* Chaining to an external standalone DNS daemon (e.g., CoreDNS or Unbound), which introduces inter-process overhead and separate configuration channels.
- **Proposed:** Egress IP pooling using Linux iptables/nftables IP masquerade alongside policy-based routing (PBR) on Edge nodes for per-tenant dedicated egress IPs.
  *Alternative:* BGP EVPN / overlay routing with tenant-specific egress gateway appliances, which requires specialized network fabric support.
- **Proposed:** In-line identity tagging where WireGuard inner IP addresses map to ephemeral session tables populated during Client tunnel establishment.
  *Alternative:* Per-packet encapsulation headers carrying user UUIDs (e.g., Geneve metadata), which reduces MTU and requires custom network driver support.
- **Proposed:** Decision table compilation converting human-authored firewall rules into pre-computed bitmask match matrices for sub-microsecond rule evaluation.
  *Alternative:* Evaluating rules sequentially in linear array passes, which introduces linear latency degradation as ruleset size grows.

## Security considerations
- Enforce strict default-deny policy for all flows not explicitly matched by an active Rule in the tenant Policy Snapshot.
- Mitigate IP spoofing by validating that inner packet source IPs strictly match the assigned tunnel lease in the Client / Workload Gateway session.
- Protect the internal DNS resolver against DNS amplification, cache poisoning, and rebinding attacks through query rate limiting and source port randomization.
- Ensure strict multi-tenant egress separation so that one tenant's noisy or abusive egress traffic does not pollute or black-list another tenant's dedicated egress IP.
- Defend against TCP state exhaustion attacks (SYN floods) through syncookies and aggressive embryonic connection pruning.
- Validate cryptographic signatures on distributed Policy Snapshots before updating active in-memory firewall rule tables.

## Failure modes & HA
- **Edge failover:** Clients detect dead Edge peers via WireGuard handshake timeouts and fail over to secondary PoPs; connection state tables are re-established.
- **DNS resolver failure:** In the event of upstream resolver degradation, the local cache serves unexpired records; critical internal Application Segment synthetic DNS remains unaffected.
- **State table exhaustion:** When connection limits are reached under SYN flood or heavy UDP traffic, early eviction of idle sessions prevents kernel/userspace memory exhaustion.
- **Control plane disconnection:** The FWaaS engine operates autonomously on the cached local Policy Snapshot, continuing to filter flows and perform NAT without interruption.
- **Egress IP unreachability:** Health checks on public egress gateways trigger automated failover to alternate egress interface routes within the PoP.
- **ICMP black-holing prevention:** Respond with appropriate ICMP Fragmentation Needed / Packet Too Big messages to prevent Path MTU discovery black holes.

## MVP scope vs later
### MVP
- L3/L4 stateful 5-tuple filtering (IP, CIDR, port, protocol: TCP, UDP, ICMP).
- Identity-aware rule matching using user and group attributes resolved from client sessions.
- Embedded DNS proxy with domain blocklists, category filtering, and synthetic DNS for ZTNA.
- Source NAT (SNAT) with shared multi-tenant public egress IP on Edge nodes.
- Session flow logging (allow, drop, byte/packet counts) exported via OTel.

### Later
- Dedicated per-tenant static egress IP addresses and egress IP reservation pools.
- Intrusion Prevention System (IPS) via Suricata integration or deep packet inspection rules.
- Geo-IP and autonomous system number (ASN) rule criteria.
- FQDN-based dynamic network filtering for non-HTTP protocols with automatic DNS snooping.
- Workload Gateway route orchestration for automated VPC default-route failover.
- Hardware-accelerated packet forwarding utilizing DPDK or AF_XDP bypass for multi-gigabit throughput.

## Open questions
- What is the maximum throughput and packet-per-second limit of gVisor netstack when filtering large file transfers compared to kernel-level eBPF?
- How should per-tenant egress IP failover be coordinated between multiple Edge instances in the same PoP without BGP Anycast complexity?
- What TTL strategy should be used for synthetic IPs assigned to private Application Segments to prevent client-side cache poisoning?
- Should non-HTTP protocols (e.g., SSH, RDP) support protocol validation to prevent port-hopping evasion through FWaaS?

## Effort drivers
- Maintaining high-throughput, low-latency stateful connection tracking in userspace without incurring excessive Go garbage collector pauses.
- Synchronizing fast-changing threat intelligence domain feeds and large category databases into low-latency memory lookup structures.
- Handling complex MTU and fragmentation issues inherent in double-encapsulated WireGuard tunnels and overlay networks.
- Implementing robust connection migration when Clients switch networks (e.g., Wi-Fi to cellular) without dropping long-lived TCP sessions.
- Managing Linux routing tables, network namespaces, and SNAT iptables dynamically for thousands of concurrent tenant egress requirements.
