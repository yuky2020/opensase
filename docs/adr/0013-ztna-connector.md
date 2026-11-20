# ADR-0013: ZTNA private access through Connectors

- Status: Accepted (2026-11-20)
- Related: ADR-0002 (PQ transport), ADR-0012 (Android first). Contract: `pkg/api/types.go`, `pkg/policy/types.go`.

## Context

Users must reach private applications, such as an intranet in a customer data centre, without
any inbound port at the customer and without network-level access to the data-centre LAN.
The established pattern is outbound-only connectors with per-application access, not
per-subnet access.

## Decision

```
phone ──WG/PQ──▶ Edge ── DNS: intranet.acme.internal → 100.96.0.5 (synthetic)
                  │  iptables REDIRECT 100.96.0.0/12 tcp → broker listener :15001
                  │  SO_ORIGINAL_DST → (tenant, name) → entitlement check
                  ▼
          HTTP/2 stream POST /v1/dial  ◀── one TLS conn dialled OUTBOUND by the connector
                                             (connector = TLS client, HTTP/2 server)
                                                   │
                                            Connector ── dials intranet.acme.internal:443
```

1. **Apps are published by name only.**
   - A `PrivateApp` has `Domains`, TCP `Ports` and a `ConnectorGroup`.
   - The Edge resolver answers an entitled name with a synthetic IPv4 address from
     `100.96.0.0/12`. It keeps a sticky `(tenant, name)` mapping, idles it out after 24h, and
     answers AAAA with an empty NOERROR.
   - Users never learn real private IPs, and overlapping customer address spaces don't matter.
   - Apps addressed by CIDR, and UDP, are out of scope (see "Later").
2. **Entitlement is in the snapshot.**
   - The Control Plane compiles into each device's snapshot only the apps that user is
     entitled to (`TenantPrivateApp.Users`, empty meaning everyone).
   - The device firewall allows matching flows at layer `ztna`, after the tenant, user, app
     and lockdown layers and before the default. Tenant rules can therefore still block a
     private app, and lockdown keeps its meaning.
3. **The Edge is the enforcement point.**
   - A single static rule, `iptables -t nat -A PREROUTING -i wg0 -d 100.96.0.0/12 -p tcp -j REDIRECT --to-ports 15001`,
     sends private-app connections to the broker listener.
   - The listener recovers the original destination (`SO_ORIGINAL_DST`), the device (from the
     source tunnel IP) and the name (from the synthetic map).
   - It re-checks `PrivateAppAccess(name, port)` on that device's snapshot and picks a live
     connector of the tenant and group.
   - Anything else is closed with RST and logged as a flow with `layer=ztna`.
4. **Connectors are outbound-only.**
   - The Connector enrols with a single-use connector provisioning key and gets a 24h
     tenant-CA certificate with URI `spiffe://opensase/tenant/<t>/connector/<id>`, renewed at 50%.
   - It fetches `ConnectorConfig` (long-poll), then keeps one TLS 1.3 PQ connection to every
     Edge's `BrokerAddr`.
   - Edges accept only connectors listed in `EdgePeers.Connectors`, so revocation takes
     effect within one peer sync. They report live connectors in `EdgeSessions.ConnectorIDs`.
5. **Inverted HTTP/2, no new dependency.**
   - Over the connector-dialled connection the Edge runs `http2.Transport.NewClientConn` and
     the connector runs `http2.Server.ServeConn` (`golang.org/x/net`, already a dependency).
   - Each brokered TCP connection is a full-duplex `POST /v1/dial` stream, which gives
     multiplexing, flow control and health (HTTP/2 PING) for free.
6. **The connector is a second enforcement point.**
   - It dials only `name:port` pairs present in its own `ConnectorConfig.Apps`, so a
     compromised Edge cannot use it to scan the LAN.
   - It resolves names with its local resolver, and refuses link-local and loopback results
     unless `-allow-loopback` is set (tests only).

## Consequences

- Zero inbound ports at the customer, per-app least privilege, and revocation within about 10s.
- The Edge needs `CAP_NET_ADMIN` for the REDIRECT rule; it already has it for wg0.
- A Private Edge (single-tenant Edge on premises) runs the same broker, so private apps
  keep working when the cloud is down, as long as the snapshot cache is warm.

## Later

CIDR-addressed apps (per-tenant TPROXY tables), UDP (HTTP/3 datagrams / MASQUE CONNECT-UDP),
connector selection by latency, app discovery from connector DNS.
