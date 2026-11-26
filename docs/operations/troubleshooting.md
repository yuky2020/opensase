# Troubleshooting

This guide details common operational failures across OpenSASE components, their symptoms, real log
messages from the codebase, diagnostic checks, and remediation steps.

---

## 1. Edge not reachable

### Symptoms

- Client displays `Error: handshake with <host>: ...` or connection timeout.
- CLI status shows `State: connecting` or `State: error`.
- Handshake verification tool fails: `opensasectl pq-check -edge-id <id>`.

### Common log messages and errors

- `handshake with <host>: dial tcp <ip>:8443: connect: connection refused`
- `post-quantum TLS required` (HTTP 426 returned if client lacks post-quantum hybrid key exchange)
- `x509: certificate signed by unknown authority`
- `edge: PKI bundle not loaded yet`

### Diagnostic checks

1. **Verify Edge listener ports:**
   Confirm the Edge is listening on the session port (`-listen`, default `8443` TCP) and WireGuard
   port (`-wg-port`, default `51820` UDP):

    ```bash
    curl -k https://<edge-host>:8443/
    ```

2. **Verify post-quantum TLS support:**
   Test the post-quantum TLS handshake using `opensasectl`:

    ```bash
    opensasectl -url https://<edge-host>:8443 -ca /path/to/root.crt pq-check -edge-id <edge-id>
    ```

    Successful output confirms post-quantum key exchange:

    ```text
    <host>:443: TLS 1.3, key exchange X25519MLKEM768, cipher TLS_AES_128_GCM_SHA256, server OpenSASE Edge <edge-id>
    ```

3. **Check Edge registration:**
   The Edge must be registered in the Control Plane. Query registered Edges with `opensasectl`:

    ```bash
    opensasectl edge list
    ```

    If the Edge is missing, register it (`opensasectl edge add -id <edge-id>`).

4. **Inspect Edge readiness:**
   Query the Edge readyz endpoint:

    ```bash
    curl -i http://<edge-ops-listen>/readyz
    ```

    If the Edge reports `no peer feed or cached state yet`, verify connectivity between the Edge and
    the Control Plane.

---

## 2. Enrolment refused

### Symptoms

- Device enrollment fails during `opensase enroll`.
- Admin portal returns an error when generating user enrollment keys or QR codes.

### Common log messages and errors

- `HTTP 403: provisioning key invalid, expired or used up`
- `HTTP 429: too many failed enrollment attempts; retry later` (metric `opensase_cp_enroll_failures_total`)
- SSO enrolment: an "Access Denied" page saying the account is deactivated in this organisation

### Diagnostic checks

1. **Check provisioning key validity:**
   Provisioning keys have an expiration time and a usage limit (`max_uses`). Issue a fresh key
   with `opensasectl`:

    ```bash
    opensasectl bootstrap -tenant <tenant> -user-id <user> -email <email> -control-url https://<controlplane>:9443
    ```

2. **Verify user status:**
   Deactivated users cannot enrol devices. In the admin portal, open **Users** and verify that the user
   is marked `Active`. If using SCIM or OIDC, ensure the user account has not been suspended.

3. **Check enrollment rate limits:**
   The Control Plane enforces a rate limit on enrollment attempts (`DefaultEnrollRate = 30` per minute
   per source IP, metric `opensase_cp_enroll_failures_total`). If exceeded, wait for the window to reset.

4. **Verify root CA pin:**
   The enrollment URI includes a certificate pin (`#sha256=<fingerprint>`). Verify that the fingerprint
   matches the root certificate:

    ```bash
    opensasectl info
    ```

    Compare the output `root sha256` against the fingerprint in your enrollment URL or QR code.

---

## 3. Tunnel down

### Symptoms

- Client reports `State: connected`, but traffic cannot reach the internet or private apps.
- `opensase status` oscillates between `connected` and `connecting`.
- Packet drops on the tunnel interface.

### Common log messages and errors

- `edge: create TUN wg0: operation not permitted`
- `edge: IPv4 forwarding is disabled in the Edge network namespace (net.ipv4.ip_forward=0): ...`
- `session certificate superseded; removing peer` (ST-10)
- `device was removed` or `unknown or revoked device`
- `no such session; start a new one with epoch 0`

### Diagnostic checks

1. **Check Edge container privileges:**
   The Edge requires Linux capabilities `NET_ADMIN`, `NET_BIND_SERVICE`, `SETUID`, `SETGID`, and
   access to `/dev/net/tun`. In Docker, verify flags:

    ```bash
    --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --device /dev/net/tun
    ```

2. **Verify kernel IP forwarding:**
   The Edge host and pod must enable IPv4 forwarding:

    ```bash
    sysctl net.ipv4.ip_forward
    # Output must be: net.ipv4.ip_forward = 1
    ```

3. **Check UDP port reachability:**
   WireGuard requires UDP communication on port `51820`. Ensure firewalls, network security groups,
   and cloud load balancers permit UDP ingress to the Edge `-wg-endpoint`.

4. **Verify device revocation status:**
   Check if the device was revoked by an administrator:

    ```bash
    opensasectl devices -tenant <tenant>
    ```

    If `REVOKED` is `true`, the Edge drops the WireGuard peer during peer synchronization. The device
    must be unenrolled and re-enrolled with a new provisioning key.

5. **Check certificate renewal:**
   Device certificates expire after 24 hours. The desktop daemon (`opensased`) automatically renews
   certificates via `POST /v1/renew` at 12 hours. If the daemon was stopped, restart it to renew:

    ```bash
    sudo systemctl restart opensased
    ```

---

## 4. DNS not resolving

### Symptoms

- Internet hosts do not resolve over the tunnel.
- DNS queries return `NXDOMAIN` unexpectedly.
- Private application domains fail to resolve.

### Common log messages and errors

- `builtin-dns-bypass` (layer `edge`, rule `builtin-dns-bypass`)
- `Decision.Action = block`, `Layer = dns`
- `ipv6 dns listener failed`
- Metric `opensase_edge_blocks_total{layer="dns"}` increasing rapidly.

### Diagnostic checks

1. **Verify Edge resolver listener:**
   Test direct query resolution to the Edge resolver address (`100.64.0.1:53`):

    ```bash
    dig @100.64.0.1 example.com
    ```

    If queries time out, confirm the Edge has bound port 53 and `CAP_NET_BIND_SERVICE` is granted.

2. **Check upstream DNS reachability:**
   The Edge forwards public queries to `-upstream-dns` (default `1.1.1.1:53`). Ensure the Edge host
   can reach the upstream resolver.

3. **Inspect DNS bypass rules:**
   By default, the Edge drops DNS queries directed to external third-party resolvers (port 53, DoT
   on 853, and DoH endpoints) to prevent policy bypasses (`builtin-dns-bypass`).
   If endpoint applications use hard-coded resolvers, configure `redirectQueries: true` in tenant policy:

    ```json
    "dns": {
      "blockResponse": "nxdomain",
      "redirectQueries": true
    }
    ```

4. **Check blocklists and categories:**
   Inspect tenant policy blocklists and web category settings:

    ```bash
    opensasectl policy get -tenant <tenant>
    ```

    Check `blockDomains`, `customLists`, `builtinLists`, and `categories` for rules matching the domain.

---

## 5. Kill switch blocking traffic

### Symptoms

- Complete loss of network connectivity when disconnected from the Edge.
- Physical network adapter cannot reach the internet or local gateway.

### Common log messages and errors

- Linux: `nftables` table `inet opensase_killswitch` active and dropping non-tunnel outbound packets.
- Windows: Wintun split default routes (`0.0.0.0/1`, `128.0.0.0/1`) remain installed.
- Client state displays `State: stopped` or `State: error`.

### Diagnostic checks and recovery

1. **Understand normal behavior:**
   By default, the Linux and Windows clients enforce a fail-closed kill switch ([Linux client](../user/linux.md),
   [Windows client](../user/windows.md)). Only bypass routes to the Control Plane and Edge remain active
   outside the tunnel.

2. **Normal disconnection:**
   Always disconnect using the client tool to cleanly tear down routes and firewall tables:

    ```bash
    opensase disconnect
    ```

3. **Emergency recovery on Linux:**
   If the daemon was abruptly terminated, manually delete the kill switch nftables table:

    ```bash
    sudo nft delete table inet opensase_killswitch
    ```

4. **Emergency recovery on Windows:**
   Restart the background service:

    ```powershell
    net stop OpenSASE
    net start OpenSASE
    ```

5. **Policy setting:**
   To disable the fail-closed kill switch across all fleet devices, set `"disableKillSwitch": true`
   in the tenant policy.

---

## 6. Leader not elected

### Symptoms

- Snapshot re-signing, old flow pruning, and audit retention do not execute.
- The Prometheus metric `opensase_cp_leader` is `0` across all Control Plane replicas.
- Alert `NoLeader` triggers.

### Common log messages and errors

- `leadership changed leader=false`
- `connect to PostgreSQL: dial tcp <ip>:5432: connect: connection refused`
- `database unreachable` on `/readyz`

### Diagnostic checks

1. **Verify database connectivity:**
   Confirm all Control Plane replicas can connect to PostgreSQL:

    ```bash
    curl -i http://127.0.0.1:9090/readyz
    # If failing: returns HTTP 503 "database unreachable"
    ```

2. **Inspect PostgreSQL advisory locks:**
   The leader replica holds a session-level advisory lock ([ADR-0033](../adr/0033-postgresql-and-replicas.md)).
   Check active advisory locks in PostgreSQL:

    ```sql
    SELECT pid, locktype, mode, granted FROM pg_locks WHERE locktype = 'advisory';
    ```

3. **Check single-node SQLite:**
   In SQLite deployments, the single Control Plane process is unconditionally the leader
   (`opensase_cp_leader` reports `1`). If reporting `0`, verify that the database file is writable.

---

## 7. CA key missing or misconfigured

### Symptoms

- Control Plane fails to start.
- Creating a tenant fails.
- Signing policy snapshots or issuing device certificates fails.

### Common log messages and errors

- `load root CA: open .../root.key: no such file or directory`
- `load server certificate: open .../controlplane.key: no such file or directory`
- `wrong key encryption key or tampered row`
- `pki: snapshot signing key is required`
- `pki: certificate is not a CA`

### Diagnostic checks

1. **Verify file permissions:**
   All private keys (`root.key`, `controlplane.key`, `snapshot.key`, `ca-kek.key`, `edge.key`) must
   be readable by the process user and have permissions `0600`.

2. **Verify component PKI separation:**
   Check required files per component (see [Certificates](certificates.md)):
    - **Control Plane requires:** `root.crt`, `root.key`, `controlplane.crt`, `controlplane.key`,
      `snapshot.key`, `ca-kek.key`, and `edges.json`.
    - **Edge requires only:** `pki/edge/root.crt`, `edge.crt`, `edge.key`, and `edge-wg.key`.
    - The Edge must **never** mount `root.key` or `ca-kek.key`.
    - The Control Plane must **never** mount `pki/edge`.

3. **Check key encryption key (ca-kek.key):**
   In multi-replica deployments, tenant intermediate CAs in the database are encrypted with `ca-kek.key`.
   If a replica uses a different or newly generated `ca-kek.key`, it fails with:

    ```text
    pki: open tenant CA key of "<tenant>": wrong key encryption key or tampered row
    ```

   Verify that all Control Plane replicas mount the identical 32-byte `ca-kek.key` file.
