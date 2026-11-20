# OpenSASE — Domain Glossary

Use these terms exactly in code, docs and UI. One term per concept.

- **Tenant** — an isolated customer organization. Every object belongs to exactly one tenant.
- **Control Plane** — the cloud services that hold configuration, compile policy, issue certificates and collect telemetry. Never forwards user traffic.
- **Data Plane** — any component that forwards traffic: Edge, Client, Connector, Workload Gateway.
- **Edge** — data-plane node that terminates tunnels and enforces policy. *Public* = provider-run, multi-tenant. *Private* = customer-run, single-tenant.
- **PoP** — a location hosting one or more Edges.
- **Client** — agent on a user device. Not "agent", not "VPN client".
- **Connector** — customer-run component that makes private applications reachable through outbound tunnels.
- **Connector Group** — set of Connectors serving the same apps; unit of load balancing and HA.
- **Workload Gateway** — customer-run component that forwards workload (non-user) traffic from a VPC/VNet into the fabric.
- **Application Segment** — a private application defined by FQDN/IP patterns plus ports, served by one or more Connector Groups.
- **Policy** — an ordered set of **Rules**. Kinds: Access (ZTNA), Internet (SWG), Firewall, CASB, DLP, Forwarding.
- **Policy Snapshot** — immutable, versioned, signed compiled form of a tenant's policies, delivered to data-plane nodes.
- **Posture** — device-state facts (OS version, disk encryption, EDR running, certificate present) reported by the Client.
- **Enrollment** — process by which a component exchanges a one-time **Provisioning Key** for an mTLS identity certificate.
- **Microtunnel** — per-user, per-application stream stitched by the Edge between a Client and a Connector.
- **Steering** — the decision on the client of which traffic goes to which Edge, and which goes direct.
- **CASB inline** — SaaS controls enforced in the SWG path (tenant restrictions, activity controls). **CASB API** — out-of-band scanning of SaaS tenants via vendor APIs.
