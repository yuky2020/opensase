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
- `protocol` is `tcp`, `udp` or `icmp`; empty means any. `ports` empty means any port.
- Replies of an allowed flow always pass. A rule from A to B does not let B open flows to A.

## How traffic flows

- Every device keeps the same tunnel address on every Edge (issue #70).
- With an internal DNS zone, every device has a name `<device>.<user>.<zone>` (see
  [DNS security](dns-security.md#internal-dns)).
- In 1.0 mesh traffic goes through the Edge, which checks the target device's rules and
  records the flow.
  - Both devices must be connected to the same Edge.
  - IPv4 only.
- Direct links between devices that see each other (`mesh.directLinks`) follow ADR-0034 and
  are not enabled yet.
