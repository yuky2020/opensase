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
- `-geneve-cidrs PREFIXES`: comma-separated IPv4 prefixes (e.g. `10.31.0.0/24`) routed via the GENEVE ingress. Required when `-geneve-listen` is set; every prefix must also be in `-gateway` (or contained in one). Directly attached subnets must not be routed into the GENEVE TUN: routing them into `osase-gnv` would cause their return traffic (HTTPS replies, `/healthz`, GENEVE replies) to enter the GENEVE TUN and be dropped as unknown flows. Only `-geneve-cidrs` prefixes receive routes via `osase-gnv`; other `-gateway` subnets keep normal routing.
- `-health-listen ADDR` (e.g. `:8080`): serves an HTTP health check endpoint (`GET /healthz`) answering 200 `ok` while the tunnel is up (`connected`) and 503 otherwise.
- `-geneve-listen` and `-health-listen` require `-gateway` and are rejected if `-gateway` is not provided.

### Packet Path and Flow Table
1. **Receive Path:**
   - A cloud gateway load balancer delivers GENEVE datagrams to `-geneve-listen`.
   - The ingress parser validates GENEVE version 0 and accepts only inner protocol `0x0800` (IPv4).
   - The inner IPv4 packet source must fall within one of the `-geneve-cidrs` subnets; otherwise it is dropped.
   - The flow table records a mapping from the inner 5-tuple (`protocol`, `src`, `dst`, `sport`, `dport`; ports 0 for non-TCP/UDP) to the sender UDP address and the preserved GENEVE header (VNI and variable-length options, copied).
   - The inner packet is written to the `osase-gnv` TUN device, where the Linux kernel forwards it into the OpenSASE WireGuard tunnel via existing iptables forwarding rules.
2. **Return Path:**
   - Ingress routes (`ip route replace <cidr> dev osase-gnv`) route return traffic for the `-geneve-cidrs` subnets to `osase-gnv` (and are removed upon gateway teardown). Gateway CIDRs not listed in `-geneve-cidrs` keep normal routing.
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

## Addendum: Routed mode (issue #21, slice B)

In standard gateway mode, the gateway MASQUERADEs workload subnets to its own tunnel address, obscuring individual workload source addresses in Edge firewall decisions and flow records.

Routed mode enables per-workload identity: workloads retain their real source addresses through the WireGuard tunnel and Edge processing.

### Control Plane Authorization

- **Authorized CIDRs:** Administrators authorize CIDR ranges per gateway device via the Control Plane Admin API:
  - `GET /v1/admin/tenants/{tenant}/devices/{device}/routes`
  - `PUT /v1/admin/tenants/{tenant}/devices/{device}/routes` with body `{"cidrs": ["10.30.0.0/24"]}`
  - Managed via CLI: `opensasectl device-routes get -tenant T -device D` and `opensasectl device-routes set -tenant T -device D -cidr C [-cidr ...]` (an empty set clears).
- **Validation:** Only IPv4 RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) with prefix lengths 16 to 32 are allowed. The CGNAT carrier range `100.64.0.0/10` (used for Edge tunnel addressing) is rejected.
- **Global No-Overlap Rule:** Across all tenants and devices, no two devices may have overlapping CIDR ranges. All Edges share a single address space for return routing. Conflicting allocations return HTTP 409 Conflict.
- **Auditing and Roles:** Only tenant administrators (`admin` role) can update device routes. All changes are recorded in the audit log.

### Edge Enforcement and Flow Records

- **Peer Feed:** The Control Plane distributes authorized routes to Edges in the peer feed (`Routes []string`).
- **WireGuard AllowedIPs:** The Edge appends the peer's authorized CIDRs to its WireGuard allowed IPs alongside its tunnel IP (`100.64.0.x/32`, `fd7a:5a5e::x/128`). Cryptokey routing guarantees that traffic for authorized subnets is routed to and from the assigned gateway device only. Routes removed from the peer feed are removed from WireGuard allowed IPs at the next peer sync.
- **Anti-Spoofing:** The Edge accepts packets from a peer only if the source IP matches the peer's tunnel address or falls within one of its authorized routes. Any other source address is dropped.
- **Return Routing & Outbound NAT:** Inbound replies destined for workload addresses within an authorized route are forwarded through the tunnel to the owning gateway peer. When outbound traffic leaves the Edge toward the internet via the WAN interface, workload addresses are masqueraded identically to tunnel addresses.
- **Workload Flow Identity:** Packet sources retain real workload IP addresses in connection tracking and flow logs. Flow records reflect individual workload addresses instead of the gateway tunnel IP.

### Client Gateway Configuration

- **Flag `-gateway-routed`:** Used in conjunction with `-gateway`:
  ```
  opensase-client -gateway 10.30.0.0/24 -gateway-routed ...
  ```
- **Masquerade Omission:** In routed mode, `cmd/opensase-client` omits the `MASQUERADE` iptables rule in its gateway chain, forwarding packets with their original workload source IP intact. Forwarding and kill-switch filter rules remain enforced.
- **Startup Warning:** If `-gateway-routed` is enabled, the client logs a warning reminding administrators that the subnets must be authorized on the Control Plane (`opensasectl device-routes`), otherwise the Edge will drop the traffic.

### Limits

- **IPv4 only:** Workload routing supports IPv4 subnets only; IPv6 forwarding remains disabled.
- **Single gateway per CIDR:** Each CIDR may be assigned to exactly one gateway device at a time.
- **No high availability pair:** Redundant gateway active/passive pairs are not yet supported for the same CIDR.

## Addendum: End-to-end check (issue #21, slice C)

The dev stack e2e test verifies GENEVE ingress and routed mode using `test/tools/geneve-probe`. The gateway runs with `-gateway 10.30.0.0/24,10.31.0.0/24 -geneve-cidrs 10.31.0.0/24`, keeping normal routing for the directly attached workload subnet (`10.30.0.0/24`) while routing GENEVE traffic via `osase-gnv` (`10.31.0.0/24`). The probe sends a GENEVE-encapsulated DNS A query for `example.com` (VNI 4242, option class 0x0103, type 0x01, data 0xdeadbeef) from inner source 10.31.0.99 to destination 100.64.0.1 via UDP port 6081 on the gateway. It validates that the reply datagram parses as GENEVE with the same VNI and option, carries an inner IPv4 UDP response from 100.64.0.1:53 to 10.31.0.99, and contains a valid DNS response with at least one answer. The e2e suite also checks gateway health via HTTP `/healthz` (200 OK while the tunnel is connected), configures authorized device routes on the Control Plane (`opensasectl device-routes set`) for both subnets, and confirms that flow records in routed mode preserve workload source addresses without NAT.
