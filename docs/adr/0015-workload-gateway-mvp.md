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
