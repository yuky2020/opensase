# ADR-0034: Device mesh

Status: accepted (2026-11-26)

## Context

Decision #47 (issue #61) asks that enrolled devices can reach each other:

- directly, when they can see each other (same LAN, or NATs that allow UDP hole punching);
- through the Edge otherwise.

Today the Edge blocks device-to-device traffic: a device can reach the Internet, private
apps through Connectors, and routed workload subnets, but not another device's tunnel
address.

Two properties already exist and make this possible:

- every device has stable tunnel addresses on every Edge (issue #70);
- devices have DNS names in the tenant zone (issue #62).

## Decision

### Policy

- Device-to-device traffic is off by default.
- A tenant enables it with mesh rules in the tenant policy: `mesh.rules`, each with
  `from` and `to` selectors (all devices, a user, a group (once #68 adds groups), or device
  tags), ports and protocols.
- Mesh rules are compiled into every device's signed snapshot: a device knows which peers may
  reach it, and on which ports.

### Through the Edge (always available)

- The Edge forwards a packet from device A to device B's tunnel address when:
  - A and B are in the same tenant;
  - a mesh rule allows the flow;
  - B has a session on this Edge.
- If B is on another Edge, the packet is dropped. Cross-Edge relaying is a 1.x item.
- Flow records are written as for any other flow.
- This path needs no change on the clients.

### Direct tunnels (when the devices can see each other)

**Discovery through the Control Plane.**

- Each client reports its endpoint candidates (`POST /v1/mesh/candidates`):
  - its LAN addresses with the port of its mesh WireGuard listener;
  - the public address and port the Edge observed for its WireGuard session.
- `GET /v1/mesh/peers` returns the peers the policy lets this device talk to, with their
  candidates and mesh WireGuard public keys.

**Handshake and keys.**

- A direct link is a second WireGuard peer on the client's device: the other device, with
  allowed IPs set to that device's tunnel addresses only. The mesh listener uses its own
  WireGuard key, separate from the Edge session key.
- The pre-shared key of a direct link comes from the same post-quantum exchange as the Edge
  sessions:
  - the initiating device opens a TLS 1.3 connection with X25519MLKEM768 and mutual device
    certificates, to the peer's candidate address (port `mesh+1`);
  - both sides derive the PSK with the session exporter (`pqsession`);
  - both sides verify that the peer's certificate is in the same tenant and that the policy
    allows the pair.
- Links rotate like Edge sessions.

**Path choice.**

- The client tries LAN candidates first, then public ones, sending to both ends at the same
  time (UDP hole punching).
- If no candidate answers within 5 seconds, traffic keeps going through the Edge.
- The client retries direct paths every 2 minutes.
- Symmetric NAT and carrier-grade NAT stay on the Edge path; there is no port prediction in
  1.0.

### Enforcement on the receiving client

On a direct link the Edge does not see the traffic, so:

- the receiving client enforces the mesh rules of its snapshot on inbound packets of a
  direct link;
- both clients write flow records for direct-link flows (where `device-mesh`).

Direct links carry only traffic between the two tunnel addresses, never Internet traffic.

### Names

- `<device>.<user>.<zone>` resolves to the device's tunnel address on every path (issue #62).
- Applications use names or tunnel addresses. They never use LAN addresses, so the path can
  change without the application noticing.

## Consequences

- The client becomes an enforcement point. A compromised client can already send anything
  through its own tunnel; what changes is that it can now also accept anything on its direct
  links. The threat model gains this threat, with its mitigations:
  - the receiving client enforces the policy;
  - the other client still enforces its own policy on what it sends;
  - the Edge path stays the default for tenants that need inspection;
  - a tenant setting `mesh.directLinks: false` keeps all mesh traffic on the Edge.
- Inspection (TLS, DLP, malware scanning) does not apply to direct links. Tenants that need
  it keep `directLinks` off.
- Work order:
  1. policy schema and the Edge path (no client change);
  2. discovery API;
  3. direct links in the client core (Linux and Windows first, then Android);
  4. e2e with two clients on one network and one behind the Edge only.
- Checks: unit tests for the mesh rule compiler and the Edge forwarding check; e2e for both
  paths; a sectest that a device outside the rule cannot reach a peer on either path.
