# ADR-0030: ECH and HTTP/3

Status: accepted (2026-11-22)

## Context

ADR-0017 inspects the Server Name Indication (SNI) in TLS ClientHello messages and HTTP Host headers without decrypting traffic. With Encrypted Client Hello (ECH), the client encrypts the inner ClientHello—containing the actual destination hostname—using a public key published in DNS HTTPS and SVCB records (RFC 9460). The outer ClientHello carries only a generic outer SNI. Consequently, hostname-based policies, SaaS controls, and categorization at the Edge cannot see or enforce policy on the real destination server name.

In addition, QUIC / HTTP/3 traffic is refused for inspecting tenants (ADR-0018) because the Edge terminates and inspects TCP TLS/HTTP flows, but does not operate an HTTP/3 terminating proxy.

## Decision

### Policy: `web.blockECH`

We introduce a tenant policy option, `web.blockECH: true`, which is compiled into the device snapshot (`Compiled.BlockECH()`). It works whether or not TLS inspection (`web.inspect`) is enabled.

When `web.blockECH` is true for a device, the Edge DNS resolver strips ECH configuration parameters (`dns.SVCB_ECHCONFIG`) from all DNS HTTPS and SVCB resource records in both Answer and Extra sections before returning responses to the client.

Without ECH parameters in DNS answers, browsers and clients fall back to standard TLS handshakes, sending the actual destination server name in the clear ClientHello SNI. This allows the Edge to retain visibility and policy control over connection hostnames.

### DNS Enforcement Scope

ECH stripping functions exclusively when DNS queries pass through the Edge resolver:
- All device traffic goes through the tunnel, and the built-in Edge rules refuse plain DNS to any server but the Edge resolver, so devices get the stripped answers.
- The built-in Edge rules refuse DNS-over-TLS (TCP/853) to third-party resolvers.
- DNS-over-HTTPS is ordinary HTTPS and is not refused by default. A tenant that needs `blockECH` to hold should also block the DoH resolvers its browsers use (domain rules or web categories), or manage the browsers' DNS settings.

### HTTP/3 Handling

There is no terminating HTTP/3 listener at the Edge at this time. For tenants enabling web inspection or rules, UDP port 443 (QUIC) remains refused, causing browsers to fall back to TCP (HTTP/1.1 or HTTP/2). This decision will be revisited when the Go standard library provides native HTTP/3 server support.

## Consequences

- If a client has already cached an ECH configuration or uses a hard-coded ECH key, it will still hide the inner server name; the Edge then evaluates the flow based on the outer SNI, as before.
- For tenants that do not enable `blockECH`, DNS HTTPS/SVCB responses are returned untouched, maintaining standard ECH behavior without changes to user privacy.
- Stripping ECH configs preserves existing hostname-based firewalling, SaaS controls, and web categorization without requiring TLS decryption keys or client-side CA root certificates.
