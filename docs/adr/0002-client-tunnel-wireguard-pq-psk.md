# ADR-0002: Client tunnel — WireGuard with post-quantum hybrid PSK

- Status: Accepted (2026-11-18)
- Scope: Client ↔ Edge data-plane tunnel

## Context

The Client needs an L3 tunnel to the Edge. WireGuard is simple, fast,
audited and available on every target OS (wireguard-go, Wintun, NetworkExtension).
Its key exchange (Noise IK over X25519) is not quantum safe: traffic recorded today can be
decrypted later by a quantum adversary ("harvest now, decrypt later").

WireGuard's handshake mixes an optional 32-byte pre-shared key (PSK) into the key schedule.
If the PSK is secret and derived from a post-quantum key exchange, session keys stay
confidential as long as **either** X25519 **or** the PQ KEM is unbroken.

## Options considered

1. **Plain WireGuard.** Not quantum safe. Rejected.
2. **PQ-WireGuard fork** (academic proposals that replace Noise IK with KEMs). Protocol fork,
   no OS kernel/userspace support, high maintenance. Rejected.
3. **Rosenpass** (formally analysed protocol, ML-KEM + Classic McEliece, rotates the PSK
   about every 2 minutes, separate UDP daemon written in Rust). Strong option, but it adds a
   second daemon and protocol on every endpoint and a Rust dependency to the Go codebase.
   Kept as the fallback if option 4 fails review.
4. **PSK derived from a hybrid PQ TLS 1.3 session to the Edge.** Chosen.

## Decision

Before (and periodically during) a WireGuard session, the Client opens a
**session-setup channel** to the Edge: TLS 1.3 on port 443, key exchange
**X25519MLKEM768** (hybrid, Go `crypto/tls` default since Go 1.24). The client authenticates
with its device certificate (mTLS) and sends the user's OIDC token.

That channel already has to exist, because it registers the client's WireGuard public key
with the Edge and returns the peer config (Edge public key, endpoint, allowed IPs, synthetic
DNS range). On the same channel, both sides derive the PSK with the TLS 1.3 exporter
(RFC 8446 §7.5, Go `ConnectionState.ExportKeyingMaterial`):

```
psk = TLS-Exporter(
        label   = "EXPORTER-opensase-wg-psk-v1",
        context = client_wg_pubkey || edge_wg_pubkey || session_id || epoch,
        length  = 32)
```

- The context binds the PSK to the exact pair of WireGuard keys and to one session/epoch,
  so a PSK cannot be reused for another peer.
- The PSK is installed through wireguard-go's UAPI (`preshared_key=`) on both ends before
  the first WireGuard handshake. No traffic ever flows under a classic-only handshake.
- **Rotation:** a new epoch every 10 minutes (configurable) and on every reconnect.
  Each epoch runs a fresh TLS handshake, so each PSK comes from a fresh ML-KEM
  encapsulation (forward secrecy per epoch). The old PSK is wiped from memory.
- **Fail-closed:** if the setup channel cannot negotiate X25519MLKEM768, no tunnel is
  created. There is no downgrade to plain WireGuard. Classic TLS is refused on this endpoint.

## Scope of quantum safety

| Property | Status in this ADR |
|---|---|
| Confidentiality of tunnel traffic against harvest-now-decrypt-later | **Covered**: hybrid X25519 + ML-KEM-768 |
| Active MITM by a quantum adversary at connection time (authentication) | Not covered yet: X25519 static keys and classic certificate signatures. Needs ML-DSA certificates, see follow-ups. Lower urgency, because the attacker needs a quantum computer *at connection time* |
| Connector ↔ Edge and Control Plane gRPC | Same rule: TLS 1.3 restricted to X25519MLKEM768 (see ADR-0003, ADR-0008) |

## Consequences

- No WireGuard fork: standard wireguard-go everywhere, and kernel WireGuard on Linux Edges still works.
- One extra TLS round trip at session start and every epoch. This is negligible.
- The session-setup channel becomes security-critical. It gets its own threat model section and fuzzing.
- Clients on networks that block UDP still need the fallback transport (MASQUE, Phase 2).
  MASQUE runs over the same hybrid TLS, so it is quantum safe as well.
- Extra effort: about **+1–1.5 person-months** in Phase 0/1 (exporter, rotation, UAPI
  integration, interop and downgrade tests).

## Follow-ups

- ADR-0008 (PKI): hybrid signatures for component certificates and Policy Snapshots
  (Ed25519 + ML-DSA-65). Use stdlib if Go provides ML-DSA by then, otherwise `cloudflare/circl`.
- Crypto agility: the `v1` label and KEM choice are versioned so ML-KEM-1024 or an extra KEM
  can be introduced without breaking clients.
- External cryptographic review of the setup-channel design before 1.0.
