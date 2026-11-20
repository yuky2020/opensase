# Workload Gateway

## Purpose
The Workload Gateway is a customer-managed data-plane component deployed within public cloud environments (AWS, Azure, GCP) to secure non-user workload egress and cross-workload communication. Deployed via declarative Terraform modules inside autoscaling groups behind cloud-native gateway load balancers, it intercepts traffic from VPC and VNet subnets without requiring agent software on individual workload instances. It forwards internet-bound traffic to Edges for SWG and FWaaS inspection and routes workload-to-private-app flows into the fabric via ZTNA. By mapping cloud topology and resource metadata to workload identities, it enforces centralized policies while preserving traffic statefulness and flow symmetry.

## Current implementation (ADR-0015)

The first slice is the headless Linux Client in gateway mode. It runs on any Linux host or VM
that the workloads use as their default route:

```
opensase-client -gateway 10.30.0.0/24 -enroll -control https://cp:9443 -key-file /run/secrets/pk -state /var/lib/opensase-gw
```

- The gateway enrolls as a device of a service user. The workloads get that user's policy, enforced
  on the gateway and at the Edge.
- Subnet traffic is NATed into the PQ WireGuard tunnel, with TCP MSS clamped.
- Workload DNS (port 53) is diverted to the Edge resolver, so DNS policy and private app names
  (ZTNA) work for workloads.
- Fail closed: forwarded traffic can only leave through the tunnel, and after shutdown a kill
  switch keeps blocking the subnets.
- Needs `iptables` and the `net.ipv4.ip_forward` sysctl. IPv6 forwarding stays off.

Not yet built:
- GENEVE behind a cloud gateway load balancer;
- per-workload identity (flows currently carry the gateway's device ID);
- cloud metadata;
- autoscaling hooks and Terraform.

## Responsibilities
- Intercept outbound and east-west workload traffic using cloud-native gateway load balancing primitives (AWS GWLB with GENEVE encapsulation, Azure Gateway LB).
- Decapsulate cloud gateway framing, extract inner IP payload headers, and ensure symmetric forward and return routing for active connections.
- Discover and ingest cloud infrastructure metadata (VPC/VNet IDs, subnet IDs, route tables, and instance tags) through cloud provider APIs.
- Correlate source IP addresses with cloud metadata to assign rich workload identity attributes to forwarded connection flows.
- Establish and maintain redundant, encrypted WireGuard or IPsec tunnels to designated public or private Edges.
- Forward external internet and SaaS egress flows to Edges for URL categorization, TLS inspection, and FWaaS rule enforcement.
- Forward workload-to-private-application flows into Edges for ZTNA policy brokering and Microtunnel routing.
- Provide transparent DNS proxying and conditional forwarding for workload DNS queries, mapping Application Segment names to synthetic addresses.
- Participate in cloud autoscaling groups, gracefully draining connections in response to scale-in lifecycle hooks and spot instance notices.
- Perform continuous health checks against upstream Edges and report connector operational health to cloud load balancers.
- Manage path MTU discovery and TCP MSS clamping to prevent packet fragmentation across layered network encapsulations.
- Export comprehensive OpenTelemetry metrics, connection flow logs, and diagnostic telemetry to the Control Plane.

## Interfaces
| Peer | Protocol | Direction | Purpose |
|---|---|---|---|
| Cloud Gateway LB (GWLB) | GENEVE over UDP 6081 | Inbound | Reception and reflection of raw workload packet streams with metadata |
| Cloud Metadata / IAM API | HTTPS (REST / Cloud SDK) | Outbound | Querying VPC topology, subnet CIDRs, and instance tags |
| Control Plane | gRPC over mTLS | Outbound | Component enrollment, Policy Snapshot delivery, health reporting, and telemetry export |
| Edge | WireGuard (or IPsec) over UDP | Outbound | Encrypted transport for steered workload egress and ZTNA traffic |
| Internal Cloud Workloads | Native IP (TCP/UDP/ICMP) | Bidirectional | Transparent forwarding of inspected packets back to cloud route targets |
| Cloud DNS Resolvers | DNS (UDP/TCP port 53) | Outbound | Upstream recursive DNS resolution for non-intercepted domain queries |
| Cloud Monitoring / CloudWatch | HTTPS / Cloud API | Outbound | Native cloud metrics publishing and instance lifecycle signaling |

## Key design decisions
- **Traffic interception model**: Proposed: Cloud-native transparent load balancers (AWS Gateway Load Balancer with GENEVE encapsulation, Azure Gateway LB) placed inline via subnet routing table next-hops. Alternative: Traditional NAT Gateway replacement or explicit proxy configuration via environment variables on workload instances.
- **Tunnel transport to Edge**: Proposed: WireGuard tunnel mesh supporting high throughput and rapid rekeying across cloud egress interfaces. Alternative: Route-based IPsec (IKEv2) tunnels with BGP dynamic routing sessions.
- **Workload identity attribution mechanism**: Proposed: Asynchronous polling and caching of cloud provider metadata (VPC, subnet, security groups, instance tags) mapped to source IP allocations, injecting identity tags into edge session headers. Alternative: Distributed SPIFFE/SPIRE agent sidecars issuing cryptographic x509 SVIDs per individual workload process.
- **Cluster statefulness and symmetric routing**: Proposed: Stateless forwarding architecture relying on cloud load balancer 5-tuple sticky hashing to guarantee symmetric forward and reverse packet paths through the same connector instance. Alternative: Distributed in-memory conntrack state synchronization across connector nodes using eBPF and multicast clustering.
- **DNS interception for workloads**: Proposed: Local transparent DNS forwarder intercepting port 53 traffic routed through the connector, synthesizing CGNAT IPs for Application Segments. Alternative: Integration with cloud private DNS resolver rules (e.g., AWS Route 53 Resolver outbound endpoints).
- **Egress encapsulation framing**: Proposed: Dynamic TCP MSS clamping on ingress to accommodate GENEVE and WireGuard header overhead without fragmentation. Alternative: Forcing Jumbo Frames across the transit VPC and relying on PMTUD packet generation.

## Security considerations
- Workload Gateway instances reside within dedicated transit or security inspection VPCs/subnets, strictly isolated from customer application workloads.
- Cloud IAM roles attached to connectors follow strict least-privilege policies, limited to read-only metadata enumeration and autoscaling lifecycle actions.
- Source IP to workload identity mappings enforce short cache TTLs and reconcile against cloud network attachment events to mitigate IP reuse spoofing.
- Outbound tunnels to Edges mandate mutual authentication and encryption using keys enrolled via single-use Provisioning Keys.
- GENEVE packet decapsulation and TLV option parsing logic execute with strict boundary checks to protect against malformed packet attacks and memory corruptions.
- Administrative access to connector instances is disabled by default, utilizing immutable base images without persistent SSH or remote interactive access.
- Local system memory holding routing state and workload metadata is isolated from host debug logging mechanisms.

## Failure modes & HA
- **Connector instance failure**: Cloud Gateway Load Balancer health checks detect unresponsive instances within seconds and immediately redirect active flows to surviving pool nodes.
- **Edge unavailability**: Connectors continuously probe primary and secondary Edges; traffic automatically switches to alternative PoP tunnels upon packet loss.
- **Asymmetric routing anomalies**: Flow hash mismatches or network topology shifts that break symmetry trigger TCP resets to force clients to cleanly re-establish synchronized sessions.
- **Autoscaling events (scale-in)**: Cloud lifecycle hooks notify connector instances to initiate graceful connection draining, allowing existing sessions to complete before instance termination.
- **Control Plane disconnection**: Data-plane forwarding continues uninterrupted based on locally cached Policy Snapshots and pre-negotiated edge tunnel keys.
- **Cloud API throttling**: Workload identity cache falls back to last-known-good metadata mappings with exponential backoff on cloud SDK rate limits.
- **AZ isolation / network partition**: Cloud load balancers cross-zone load balancing distributes traffic across healthy connectors across remaining available availability zones.

## MVP scope vs later
- **MVP**:
  - AWS support utilizing Gateway Load Balancer (GWLB) with GENEVE packet decapsulation.
  - Production-ready Terraform module deploying autoscaling Workload Gateway groups behind AWS GWLB.
  - WireGuard tunnel establishing encrypted transit to nearest Edge.
  - Static and subnet-based workload identity mapping (VPC ID, Subnet ID, availability zone).
  - Transparent forwarding for HTTP/HTTPS workload egress to Edge for SWG/FWaaS enforcement.
  - Transparent DNS forwarding and synthetic IP synthesis for private Application Segments.
  - OpenTelemetry structured flow logging and metrics export.
- **Later**:
  - Microsoft Azure (Azure Gateway Load Balancer) and Google Cloud Platform (Packet Mirroring / Network Connectivity Center) modules.
  - Real-time dynamic workload identity tagging using cloud instance tag polling and event-driven webhook notifications.
  - IPsec (IKEv2) transport with dynamic BGP peering for hybrid multicloud interconnects.
  - Workload-to-workload micro-segmentation policies enforced directly within the cloud fabric.
  - eBPF/XDP fast-path acceleration for GENEVE decapsulation and packet forwarding.
  - Cross-VPC transit network integration modules for AWS Transit Gateway and Azure Virtual WAN.

## Open questions
- Should workload identity metadata be injected inline into data packets via custom WireGuard header extensions or transmitted via out-of-band signaling?
- How can cloud provider API rate limits be mitigated when reconciling instance tags across dynamic environments with thousands of short-lived containers?
- What MTU clamping and MSS adjustment strategy best minimizes packet fragmentation across nested VPC MTU, GENEVE framing, and WireGuard tunnels?
- Should Workload Gateway allow optional direct local internet breakout for trusted non-inspected traffic categories, or mandate edge steering for all flows?
- How should multi-account and cross-VPC transit architectures (e.g., AWS Transit Gateway) interface with the connector pool?

## Effort drivers
- Parsing, validating, and encapsulating GENEVE protocol framing and variable-length TLV metadata in the high-performance packet path.
- Guaranteeing deterministic packet symmetry and connection statefulness across autoscale events without introducing inter-node cluster dependencies.
- Managing nested network overhead, TCP MSS clamping, and MTU discovery across layered cloud and tunnel encapsulations.
- Developing, testing, and maintaining automated Terraform modules across differing cloud network constructs (AWS GWLB vs. Azure Gateway LB vs. GCP NCC).
- Handling rapid IP churn and avoiding race conditions in workload identity attribution within ephemeral container and serverless environments.
