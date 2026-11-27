# Device mesh

Enrolled devices of a tenant can reach each other when a mesh rule allows it (ADR-0034).
Without rules, device-to-device traffic is blocked.

```json
"mesh": {
  "rules": [
    {"id": "it-ssh", "from": {"users": ["it-admin"]}, "to": {"all": true},
     "protocol": "tcp", "ports": [{"from": 22}]},
    {"id": "nas", "from": {"all": true}, "to": {"devices": ["<nas device id>"]},
     "protocol": "tcp", "ports": [{"from": 445}]}
  ]
}
```

- Each rule allows flows from the `from` devices to the `to` devices. A selector picks
  `all` devices of the tenant, the devices of some `users`, or some `devices`.
- `protocol` is `tcp`, `udp`, `icmp` or `icmpv6`; empty means any (`icmp` matches both
  ICMPv4 and ICMPv6). `ports` empty means any port.
- Replies of an allowed flow always pass. A rule from A to B does not let B open flows to A.

## How traffic flows

- Every device keeps the same tunnel addresses (IPv4 and IPv6) on every Edge (issue #70).
- With an internal DNS zone, every device has a name `<device>.<user>.<zone>` (see
  [DNS security](dns-security.md#internal-dns)) with both `A` and `AAAA` records when IPv6
  is enabled on the Edge.
- In 1.0 mesh traffic goes through the Edge, which checks the target device's rules and
  records the flow.
  - Both devices must be connected to the same Edge.
  - Supports IPv4 (`100.64.0.0/10`) and, when IPv6 forwarding is enabled on the Edge, IPv6
    (`fd7a:5a5e::/64`).
- Direct links between devices that see each other (`mesh.directLinks`) follow ADR-0034 and
  are not enabled yet.
