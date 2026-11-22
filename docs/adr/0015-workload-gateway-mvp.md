# ADR-0015: Workload Gateway, first slice (routed subnet gateway)

Status: accepted (2026-11-20)

## Context

`docs/components/workload-gateway.md` describes the full Workload Gateway:
- cloud gateway load balancers (GENEVE);
- cloud metadata for workload identity;
- autoscaling;
- encrypted transport to the Edges.

Workloads such as servers, containers and VMs run no Client, but their egress and their access to
private apps must still go through Edge policy. We need a first slice that works on any Linux
host, in any VPC or on premises, without cloud-specific code.

## Decision

The Workload Gateway is the headless Linux Client (`cmd/opensase-client`) in gateway mode:

```
opensase-client -gateway 10.30.0.0/24[,CIDR...] -enroll -control URL -key-file FILE ...
```

- **Identity and policy.**
  - The gateway enrolls like a device, with a provisioning key of a service user (for example
    `svc-vpc-prod`). It gets the same PQ WireGuard tunnel (ADR-0002), the same signed snapshot and
    the same on-device firewall.
  - Policy for the workloads is that user's policy, enforced on the gateway and again at the Edge.
- **Forwarding.**
  - With IPv4 forwarding on, traffic from the gateway CIDRs leaving through the tunnel is
    masqueraded to the gateway's tunnel address. The Edge sees an ordinary device, so Edge code is
    unchanged and anti-spoofing still holds.
  - TCP MSS is clamped to the path MTU on the tunnel.
- **DNS.**
  - UDP and TCP port 53 from the gateway CIDRs is DNAT-ed to the Edge resolver (`100.64.0.1`).
    DNS policy therefore applies to workloads.
  - Private app names resolve to synthetic addresses, so workloads reach private apps through the
    Edge broker and the Connector (ADR-0013), subject to the service user's entitlement.
- **Fail closed.**
  - Forwarded traffic from the gateway CIDRs may leave only through the tunnel. Anything else is
    dropped, as is unsolicited traffic from the tunnel into the subnet.
  - IPv6 forwarding is never enabled.
- **Rules live in their own chains** (`OSASE_GW_*` in filter, nat and mangle). They are installed
  after the tunnel is up. On shutdown the NAT, DNS and MSS rules are removed, but the filter chain
  keeps dropping traffic from the subnets (a kill switch): workloads never fall back to direct
  egress while the gateway is down.
- **Where traffic reaches the gateway.** Workloads use the gateway as their default route: a route
  table next hop, a DHCP router option or a static route.

## Consequences

- Flow records and decisions carry the gateway's device ID, not the individual workload: the
  source address is lost to the NAT. Per-workload identity is the next step:
  - either the Edge routes the gateway CIDRs as AllowedIPs (no NAT), with source validation per
    peer;
  - or the gateway tags flows out of band.
- Still to come for the cloud: GENEVE ingress behind a cloud gateway load balancer, metadata-based
  identity, autoscaling and draining hooks, and Terraform modules.
- A single gateway is a single point of failure. HA for now is several gateways, each with its own
  device identity, behind the network's own redundancy (for example two route next hops with
  health checks).

## Addendum: GENEVE ingress (issue #21, slice A)

To support placement behind a cloud gateway load balancer that delivers workload traffic encapsulated in GENEVE (RFC 8926, UDP port 6081), `cmd/opensase-client` adds GENEVE ingress and health checking capabilities.

### Flags
- `-geneve-listen ADDR` (e.g. `:6081`): starts a UDP listener for GENEVE-encapsulated traffic and creates a dedicated TUN interface named `osase-gnv` (MTU 1400).
- `-health-listen ADDR` (e.g. `:8080`): serves an HTTP health check endpoint (`GET /healthz`) answering 200 `ok` while the tunnel is up (`connected`) and 503 otherwise.
- Both flags require `-gateway` and are rejected if `-gateway` is not provided.

### Packet Path and Flow Table
1. **Receive Path:**
   - A cloud gateway load balancer delivers GENEVE datagrams to `-geneve-listen`.
   - The ingress parser validates GENEVE version 0 and accepts only inner protocol `0x0800` (IPv4).
   - The inner IPv4 packet source must fall within one of the `-gateway` CIDRs; otherwise it is dropped.
   - The flow table records a mapping from the inner 5-tuple (`protocol`, `src`, `dst`, `sport`, `dport`; ports 0 for non-TCP/UDP) to the sender UDP address and the preserved GENEVE header (VNI and variable-length options, copied).
   - The inner packet is written to the `osase-gnv` TUN device, where the Linux kernel forwards it into the OpenSASE WireGuard tunnel via existing iptables forwarding rules.
2. **Return Path:**
   - Ingress routes (`ip route replace <cidr> dev osase-gnv`) route return traffic for the gateway subnets to `osase-gnv` (and are removed upon gateway teardown).
   - Return packets read from `osase-gnv` are parsed for their 5-tuple.
   - The flow table looks up the reversed 5-tuple. If found, the return packet is encapsulated with the saved GENEVE header (same VNI and options) and transmitted back to the saved sender UDP address.
   - Unknown or expired return flows are dropped and counted.

### Flow Lifecycle and Limits
- **Expiry:** Flow entries expire after 5 minutes of idle time for TCP connections, or 60 seconds for other protocols.
- **Capacity:** At most 65,536 active flow entries are retained; the oldest entries are evicted when capacity is reached.
- **Monitoring:** Flow and drop counters (accepted, dropped by reason, unknown return) are logged once per minute at `Info` level without logging packet contents or IP addresses.
- **Current Limits:**
  - IPv4 only: IPv6 forwarding remains disabled.
  - NAT still applies on the tunnel interface: the Edge sees the gateway device's tunnel address.
  - Per-workload identity is deferred to slice B.
