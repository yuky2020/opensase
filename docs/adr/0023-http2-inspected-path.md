# ADR-0023: HTTP/2 on the inspected path

Status: accepted (2026-11-21)

## Context

The first inspection slice (ADR-0018) offered only HTTP/1.1 through ALPN, on both legs. That
works, because browsers fall back, but it costs:
- browsers open several connections per site;
- head-of-line blocking returns;
- HTTP/2-only services (gRPC-Web gateways, some APIs) degrade or fail.

HTTP/2 also changes one security property. A browser may reuse one HTTP/2 connection for
several hosts (connection coalescing). The per-connection host pinning of ADR-0018 must still
hold.

## Decision

- **Browser leg.** The Edge offers `h2` and `http/1.1` by ALPN. The per-connection HTTP server
  runs on the standard library's HTTP/2 support (`http.Server.Protocols`), with at most 250
  concurrent streams. Every stream is one request through the same handler, so URL rules,
  header injection, DLP and malware scanning apply per stream exactly as per HTTP/1.1 request.
- **Host pinning.** A stream whose `:authority` is not the connection's SNI gets
  `421 Misdirected Request`. That is the HTTP/2 signal to the browser to open a new connection
  for that host, which then goes through the SNI checks of ADR-0017 and gets its own leaf. The
  leaf certificate names only the SNI host, so browsers do not try to coalesce in the first
  place.
- **Server leg.** The upstream transport attempts HTTP/2 (`ForceAttemptHTTP2`) whatever the
  browser negotiated, and falls back to HTTP/1.1 when the server does not offer `h2`. Upgrade
  requests (WebSocket) keep using HTTP/1.1 end to end.
- **Unchanged:** plain HTTP stays HTTP/1.1 (no `h2c`), and HTTP/3 is still refused (`web:quic`,
  ADR-0018), so browsers fall back to HTTP/2 over TCP.

## Consequences

- Fewer connections per site through the Edge.
- WebSocket over HTTP/2 (RFC 8441 extended CONNECT) is not offered: browsers use WebSocket over
  HTTP/1.1, which passes.
- gRPC needs HTTP/2 on both legs. It works when the server supports it, which gRPC servers do.
- Checks: `internal/edge` tests (both legs, 20 concurrent streams, upgrade), the e2e (HTTP/2
  negotiated with the device, URL rule over HTTP/2) and SEC-DP-127 (`:authority` switch and path
  tricks over HTTP/2).
