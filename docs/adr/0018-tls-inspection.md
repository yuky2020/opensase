# ADR-0018: TLS inspection at the Edge (opt-in per tenant)

Status: accepted (2026-11-21)

## Context

ADR-0017 controls web traffic by hostname alone. Some controls need the request itself:
- blocking a path (`/admin`, an upload endpoint) while allowing the rest of a site;
- blocking a method (uploads with `POST`/`PUT`);
- setting a request header, for example one that limits a SaaS login to the company's own
  account;
- later, DLP and malware scanning of request and response bodies.

All of that needs the Edge to decrypt TLS. Decryption is intrusive: devices must trust a CA
that can vouch for any name, and some apps pin certificates. So it must be opt-in, per tenant,
with a way to exempt domains.

## Decision

### Policy: `web` in the tenant policy and the snapshot

`TenantPolicy.web` (`policy.WebPolicy`) is copied into every device snapshot of the tenant, so
the Edge gets it signed, cached offline (ADR-0014) and per device. User rules cannot change it.

```json
"web": {
  "inspect": true,
  "bypass": ["*.bank.example"],
  "rules": [
    {"id": "no-admin", "domains": ["app.example"], "pathPrefixes": ["/admin"], "action": "block"},
    {"id": "no-upload", "domains": ["*.files.example"], "methods": ["POST", "PUT"], "action": "block"}
  ],
  "headers": [
    {"domains": ["*.saas.example"], "name": "X-Allowed-Tenant", "value": "acme"}
  ]
}
```

- **inspect** turns TLS interception on. Without it, `rules` and `headers` apply to plain HTTP
  only; HTTPS keeps the hostname control of ADR-0017.
- **bypass** lists domains never decrypted (pinned apps, banking, health).
- **rules** are matched in order on every request: host (same domain syntax as firewall rules),
  optional methods, optional path prefixes. The first match decides; no match allows.
  - Paths are normalized before matching: dot segments are resolved, duplicate slashes
    collapsed, and the comparison ignores case. So `/x/../ADMIN//users` matches `/admin`. The
    request is forwarded unchanged.
  - A prefix is a prefix: `/admin` also matches `/administrator`; write `/admin/` to match only
    the directory (which also matches `/admin` itself).
- **headers** are set on every request to a matching host and replace any value the client
  sent. Headers that frame the request or the connection (`Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Upgrade`, …) cannot be set, nor can values with control
  characters.

`policy.Compile` validates the section, so the Control Plane refuses an invalid one with the
offending field.

### Certificates: a separate inspection root per tenant, short intermediates per Edge

- Each tenant gets its own **inspection root** (`pki.Authority.InspectionCA`), stored next to the
  tenant CA. It is deliberately separate from the provider root and the tenant CA:
  - devices install it as a web trust anchor, so it must not be able to vouch for OpenSASE
    identities;
  - the mTLS PKI must not be able to mint web certificates.

  Both inspection CAs carry only the ServerAuth extended key usage.
- The admin downloads the root with `GET /v1/admin/tenants/{t}/inspection-ca`
  (`opensasectl inspection-ca -tenant T -o FILE`, or the portal's Web inspection page) and
  installs it on the tenant's devices (MDM, system trust store).
- **The root key never leaves the Control Plane.** Each Edge generates its own P-256 key in
  memory and asks for an intermediate with `POST /v1/edge/inspection-ca` (edge mTLS, a CSR).
  The Control Plane signs it only if:
  - the Edge serves the tenant (a Private Edge only its own, ADR-0014);
  - the tenant has `web.inspect` on.

  The intermediate has path length 0 and is valid for 7 days. The Edge renews it at half its
  lifetime and keeps a valid one if a renewal fails. A compromised Edge can therefore mint
  certificates for at most a week, and only for tenants it serves.
- Leaf certificates are made on the fly for the SNI, valid for 24 hours, cached per host, and
  share one key per tenant.

### Data path

The Edge's packet filter is unchanged: it still decides every flow on its address, and then on
its SNI or Host (ADR-0017), before anything else. With `edge -inspect-listen ADDR` (in the dev
compose: `EDGE_INSPECT_PORT`, default 15002), the kernel REDIRECTs tunnel TCP to ports 80 and
443 (synthetic ZTNA addresses excluded) to the inspection listener. For each connection the Edge
reads the ClientHello or request head, then:

| Case | What happens |
|---|---|
| inspection off for the device's tenant, bypassed host, no SNI, not TLS or HTTP | bytes spliced unchanged to the original destination |
| TLS, inspection on | TLS terminated with a leaf for the SNI; requests checked and proxied over the Edge's own TLS connection to the original destination |
| plain HTTP with web rules or headers | requests checked and proxied |

On the inspected path:
- **Every request must be for the connection's host.** A request whose `Host` differs from the
  SNI (or from the first request's `Host` on plain HTTP) gets `421` and is recorded as
  `web:host-mismatch`. Otherwise one connection opened for an allowed name could carry requests
  for a blocked one.
- A blocked request gets a `403` page and a flow record with layer `web` and rule
  `url:<rule id>`.
- The upstream certificate is verified against the system roots for the SNI. If it fails, the
  request gets `502` and is recorded as `web:upstream-certificate`: the Edge never hides an
  invalid server certificate from a user who can no longer see it.
- **Fail closed.** If the Edge has no valid intermediate (Control Plane unreachable at the first
  connection, inspection turned off at the Control Plane but not yet in the snapshot), the
  connection is reset and recorded as `web:inspection-unavailable`. A tenant that asked for
  inspection never gets uninspected HTTPS.
- **No escape routes.** For devices whose policy has web inspection or rules, the filter refuses
  QUIC (UDP 443, `web:quic`) and IPv6 web traffic (`web:ipv6`), which the listener does not
  handle. Browsers fall back to TCP over IPv4.
- No `X-Forwarded-For` or similar header is added: servers see the Edge's egress address, as
  with the NAT path.

ALPN is limited to HTTP/1.1 on both sides; WebSocket upgrades pass through.

The browser-facing and server-facing TLS cannot go through `pqsession.Harden`: they talk to
arbitrary browsers and servers. Both still offer and prefer X25519MLKEM768 (Go's default), so a
PQ-capable browser and server keep a post-quantum key exchange on both legs.

## Consequences

- With the listener on, all tunnel web traffic of that Edge passes through a userspace proxy,
  even for tenants that do not inspect (they get a splice). Inspection is therefore an Edge
  flag, off by default, as well as a tenant opt-in. Per-device redirection with dynamic kernel
  rules is a possible optimization.
- The listener waits up to 10 seconds for the client's first bytes. A protocol on port 80 or
  443 where the server speaks first does not work through an Edge with the listener on.
- Devices that do not trust the inspection root fail the TLS handshake on inspected sites.
  That is the intended result, but rolling inspection out needs the root installed first.
  Android apps ignore user-installed CAs unless they opt in, so on Android inspection is
  practical for browsers and managed apps; pinned or unmanaged apps belong in `bypass`.
- The intermediate is held in memory only. A Private Edge restarted while the Control Plane is
  down cannot inspect until it gets one, and refuses inspected connections meanwhile (fail
  closed).
- Not covered yet:
  - HTTP/2 to the client or the server (HTTP/1.1 only);
  - URL categories, DLP and malware scanning of bodies;
  - per-request flow records for allowed requests: only blocks are recorded, and paths are not
    stored in flow records.
