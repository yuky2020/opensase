# Command-line interface (CLI) reference

This page documents the flags and subcommands for the OpenSASE command-line binaries:
`opensasectl`, `controlplane`, `edge`, and `opensase`.

---

## `opensasectl`

`opensasectl` is the administrative and operational CLI for OpenSASE.

### Global flags

These flags apply to all `opensasectl` subcommands. They default to the environment variables shown.

| Flag | Default | Description |
|---|---|---|
| `-url URL` | `$OPENSASE_URL` or `https://localhost:9443` | Control Plane URL. |
| `-ca PATH` | `$OPENSASE_CA` or `deploy/dev/pki/root.crt` | Root CA PEM certificate file. |
| `-token TOKEN` | `$OPENSASE_ADMIN_TOKEN` | Admin bearer token. Visible in process listings; prefer `-token-file` or the environment variable. |
| `-token-file PATH` | | Path to a file holding the admin token. File permissions must be `0600`. |
| `-timeout DUR` | `15s` | Request timeout. |

### Commands

#### `pki init`

Initialises a development PKI directory with a root CA, server certificates, private keys, and `edges.json`.

```bash
opensasectl pki init [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-dir DIR` | `deploy/dev/pki` | PKI target directory. Edge material is placed in `DIR/edge`. |
| `-edge-id ID` | `edge-1` | Identifier for the initial Edge. |
| `-session-url URL` | `https://edge:8443` | Edge session setup URL returned to clients. |
| `-wg-endpoint HOST:PORT` | `edge:51820` | Edge WireGuard UDP endpoint returned to clients. |
| `-broker-addr HOST:PORT` | `edge:8444` | Edge broker address dialed by Connectors. Empty disables. |
| `-region REGION` | `dev` | Region label for the Edge. |
| `-cp-san SANS` | *(dev defaults)* | Comma-separated DNS names and IP addresses for the Control Plane TLS certificate. |
| `-edge-san SANS` | *(dev defaults)* | Comma-separated DNS names and IP addresses for the Edge TLS certificate. |

#### `pki export-ca`

Exports the certificate authority bundle published by the Control Plane.

```bash
opensasectl pki export-ca [-o FILE]
```

| Flag | Default | Description |
|---|---|---|
| `-o FILE` | *(stdout)* | Write the CA PEM bundle to this file instead of stdout. |

#### `bootstrap`

Creates an initial tenant, a user, and a device provisioning key.

```bash
opensasectl bootstrap -tenant ID [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `acme` | Tenant identifier. |
| `-tenant-name NAME` | *(same as ID)* | Human-readable tenant name. |
| `-user-id ID` | `user-1` | User identifier. |
| `-email EMAIL` | `user@example.com` | User email address. |
| `-name NAME` | `Dev User` | Human-readable user name. |
| `-max-uses N` | `5` | Maximum device enrolments allowed for the provisioning key. |
| `-valid-for DUR` | `24h` | Validity duration of the provisioning key. |
| `-control-url URL` | *(same as -url)* | Control Plane URL as reachable by client devices. |
| `-edge-id ID` | `edge-1` | Edge ID to register during bootstrap. Empty disables. |

#### `policy get`

Fetches and prints the active JSON security policy of a tenant.

```bash
opensasectl policy get [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |

#### `policy set`

Replaces the tenant security policy from a JSON file.

```bash
opensasectl policy set [-tenant ID] -f FILE
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-f FILE` | | Path to the JSON policy file ([Tenant policy](policy.md)). |

#### `flows`

Queries recent traffic flow records for a tenant.

```bash
opensasectl flows [-tenant ID] [-limit N] [-json]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-limit N` | `50` | Maximum number of records to return. |
| `-json` | `false` | Output raw JSON instead of a formatted table. |

#### `devices`

Lists all enrolled devices belonging to a tenant.

```bash
opensasectl devices [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |

#### `revoke`

Revokes a client device registration.

```bash
opensasectl revoke [-tenant ID] -device ID
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-device ID` | | Device identifier to revoke. |

#### `device-routes get`

Prints the authorized routed CIDRs for a gateway device.

```bash
opensasectl device-routes get [-tenant ID] -device ID [-json]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-device ID` | | Device identifier. |
| `-json` | `false` | Output raw JSON. |

#### `device-routes set`

Sets the authorized routed CIDRs for a gateway device. Passing no `-cidr` flags clears all routes.

```bash
opensasectl device-routes set [-tenant ID] -device ID [-cidr PREFIX ...]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-device ID` | | Device identifier. |
| `-cidr PREFIX` | | Authorized IPv4 or IPv6 CIDR prefix. Repeatable. |

#### `edge add`

Registers an Edge identifier with the Control Plane.

```bash
opensasectl edge add -id ID [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-id ID` | | Edge identifier matching the certificate SPIFFE ID (`spiffe://opensase/edge/<id>`). |
| `-tenant ID` | | Bind the Edge exclusively to this tenant ([ADR-0014](../adr/0014-private-edge.md)). Empty makes it a public multi-tenant Edge. |

#### `edge list`

Lists all registered public and private Edges. Requires the super-admin role.

```bash
opensasectl edge list
```

#### `edge revoke`

Permanently revokes an Edge registration. Requires the super-admin role.

```bash
opensasectl edge revoke -id ID
```

| Flag | Default | Description |
|---|---|---|
| `-id ID` | | Edge identifier to revoke. |

#### `connector add`

Creates a new private application Connector and outputs its one-time provisioning key ([ADR-0013](../adr/0013-ztna-connector.md)).

```bash
opensasectl connector add [-tenant ID] -name NAME [-group GROUP] [-key-out FILE]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-name NAME` | | Descriptive name for the Connector. |
| `-group GROUP` | `default` | Connector group identifier. |
| `-key-out FILE` | | Write the one-time provisioning key to this file with mode `0600`. File must not already exist. |

#### `connector list`

Lists all Connectors configured for a tenant.

```bash
opensasectl connector list [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |

#### `connector revoke`

Revokes a Connector registration.

```bash
opensasectl connector revoke [-tenant ID] -id ID
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-id ID` | | Connector identifier to revoke. |

#### `app set`

Replaces the tenant's private application definitions (ZTNA) from a JSON file.

```bash
opensasectl app set [-tenant ID] -file FILE
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-file FILE` | | Path to JSON file containing an array of `api.TenantPrivateApp` objects. |

#### `app list`

Lists all private applications defined for a tenant.

```bash
opensasectl app list [-tenant ID] [-json]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-json` | `false` | Output raw JSON accepted by `app set`. |

#### `admin-token add`

Issues a scoped admin bearer token for a tenant ([ADR-0027](../adr/0027-tenant-roles.md)). The raw token is displayed only once.

```bash
opensasectl admin-token add [-tenant ID] -name NAME [-role ROLE] [-valid-for DUR] [-token-out FILE]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-name NAME` | | Description of who or what uses this token. |
| `-role ROLE` | `admin` | Permission role: `admin`, `policy-editor`, or `viewer`. |
| `-valid-for DUR` | `90d` | Token validity duration (maximum 365 days). |
| `-token-out FILE` | | Write the token string to this file with mode `0600`. File must not already exist. |

#### `admin-token list`

Lists all admin tokens issued for a tenant.

```bash
opensasectl admin-token list [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |

#### `admin-token revoke`

Revokes an admin token by identifier.

```bash
opensasectl admin-token revoke [-tenant ID] -id ID
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-id ID` | | Admin token identifier to revoke. |

#### `whoami`

Queries and prints the identity and role associated with the current admin token.

```bash
opensasectl whoami
```

#### `audit`

Queries the administrative audit log.

```bash
opensasectl audit [-tenant ID] [-limit N] [-json]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | | Tenant identifier. Omit to query across all tenants (super-admin only). |
| `-limit N` | `100` | Maximum number of audit records (maximum `1000`). |
| `-json` | `false` | Output raw JSON. |

#### `audit verify`

Verifies the cryptographic integrity of the admin audit hash chain ([ADR-0028](../adr/0028-audit-hash-chain.md)).

```bash
opensasectl audit verify [-id N -hash HASH]
```

| Flag | Default | Description |
|---|---|---|
| `-id N` | `0` | Sequence ID of an audit head entry published earlier. |
| `-hash HASH` | | Expected SHA-256 hash published for entry `-id`. |

#### `info`

Displays the pinned Control Plane URL (including the root CA SHA-256 fingerprint), server version, and enabled features.

```bash
opensasectl info
```

#### `dlp-dataset put`

Uploads values or documents for exact data match DLP inspection ([ADR-0029](../adr/0029-dlp-exact-data-match.md)). Raw data is read locally and sent once; the Control Plane stores only keyed cryptographic hashes.

```bash
opensasectl dlp-dataset put [-tenant ID] -name NAME [-kind KIND] -file PATH [-file PATH ...]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-name NAME` | | Name of the dataset. |
| `-kind KIND` | `values` | Dataset kind: `values` (one line per entry) or `document`. |
| `-file PATH` | | Path to file containing values or document content. Repeatable. |

#### `dlp-dataset list`

Lists exact data match DLP datasets configured for a tenant.

```bash
opensasectl dlp-dataset list [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |

#### `dlp-dataset delete`

Deletes a DLP dataset by name.

```bash
opensasectl dlp-dataset delete [-tenant ID] -name NAME
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-name NAME` | | Name of the dataset to delete. |

#### `oidc get`

Prints the OpenID Connect (OIDC) identity provider configuration for a tenant ([ADR-0031](../adr/0031-portal-oidc-sign-in.md)).

```bash
opensasectl oidc get [-tenant ID] [-json]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-json` | `false` | Output raw JSON. |

#### `oidc set`

Configures or updates the OIDC identity provider integration for a tenant.

```bash
opensasectl oidc set [-tenant ID] -issuer URL -client-id ID [-client-secret-file FILE] -group G=ROLE ...
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-issuer URL` | | HTTPS issuer URL of the identity provider. |
| `-client-id ID` | | Client ID registered with the identity provider. |
| `-client-secret-file FILE` | | Path to file containing the client secret with mode `0600`. |
| `-group G=ROLE` | | Map an IdP group name to a tenant role (`admin`, `policy-editor`, or `viewer`). Repeatable. |

#### `oidc delete`

Removes the OIDC identity provider configuration for a tenant.

```bash
opensasectl oidc delete [-tenant ID]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |

#### `categories`

Lists the web categories loaded into the Control Plane from the public UT1 archive ([ADR-0022](../adr/0022-web-categories-ut1.md)).

```bash
opensasectl categories [-json]
```

| Flag | Default | Description |
|---|---|---|
| `-json` | `false` | Output raw JSON. |

#### `inspection-ca`

Downloads the tenant's TLS inspection root CA certificate ([ADR-0018](../adr/0018-tls-inspection.md)) to install as a trusted root on client devices.

```bash
opensasectl inspection-ca [-tenant ID] [-o FILE]
```

| Flag | Default | Description |
|---|---|---|
| `-tenant ID` | `$OPENSASE_TENANT` or `acme` | Tenant identifier. |
| `-o FILE` | *(stdout)* | Path to write the inspection CA PEM file. |

#### `pq-check`

Performs a TLS handshake against the Control Plane or an Edge and prints the negotiated post-quantum key exchange parameters.

```bash
opensasectl pq-check [-edge-id ID]
```

| Flag | Default | Description |
|---|---|---|
| `-edge-id ID` | | Verify the SPIFFE identity of an Edge (`spiffe://opensase/edge/<id>`) instead of the Control Plane. |

#### `store backup`

Performs a consistent live backup of a SQLite Control Plane database ([Backup and restore](../operations/backup.md)).

```bash
opensasectl store backup -db DB_FILE -o OUT_FILE
```

| Flag | Default | Description |
|---|---|---|
| `-db DB_FILE` | | Path to the active SQLite database file. |
| `-o OUT_FILE` | | Destination path for the backup file. |

#### `store restore`

Restores a SQLite database from a backup file after verifying the audit hash chain.

```bash
opensasectl store restore -from BACKUP_FILE -to DB_FILE
```

| Flag | Default | Description |
|---|---|---|
| `-from BACKUP_FILE` | | Path to the backup file. |
| `-to DB_FILE` | | Target database path to create. |

#### `store migrate`

Migrates data from a stopped SQLite database into a target PostgreSQL database ([ADR-0033](../adr/0033-postgresql-and-replicas.md)).

```bash
opensasectl store migrate -from DB_FILE [-to POSTGRES_URL]
```

| Flag | Default | Description |
|---|---|---|
| `-from DB_FILE` | | Source SQLite database file of the stopped Control Plane. |
| `-to POSTGRES_URL` | `$OPENSASE_DB` | Destination `postgres://` connection URL. |

---

## `controlplane`

`controlplane` runs the multi-tenant Control Plane service.

### Environment variables

- `OPENSASE_ADMIN_TOKEN`: Required. Secret super-admin token compared in constant time (minimum 16 characters).
- `OPENSASE_DB`: Default database connection string when `-db` is not supplied.
- `OPENSASE_PORTAL_DIR`: Default directory path for the static web admin portal.

### Command-line flags

| Flag | Default | Description |
|---|---|---|
| `-listen ADDR` | `:9443` | HTTPS listen address. |
| `-db PATH_OR_URL` | `$OPENSASE_DB` or `controlplane.db` | SQLite database file path, or `postgres://` URL for multi-replica setups ([ADR-0033](../adr/0033-postgresql-and-replicas.md)). |
| `-pki DIR` | `pki` | Directory holding PKI files (`root.crt`, `root.key`, `controlplane.crt`, `controlplane.key`, `snapshot.key`, `edges.json`). |
| `-ca-kek-file PATH` | `<pki>/ca-kek.key` | Path to the 32-byte Key Encryption Key (KEK) used to seal tenant CA keys in the database. Created if missing. Must be identical across all replicas. |
| `-edges PATH` | `<pki>/edges.json` | JSON file containing array of `api.EdgeInfo` structures returned at device enrollment. |
| `-control-url URL` | `https://controlplane:9443` | Control Plane URL returned to client devices during enrollment. |
| `-max-conns N` | `4096` | Maximum number of concurrent network connections. |
| `-flow-retention DUR` | `168h0m0s` (7 days) | Retention window for flow records before automated cleanup. |
| `-flow-rate N` | `1000` | Maximum flow records accepted per device per minute. |
| `-categories-file PATH` | | Cached UT1 category archive file (`blacklists.tar.gz`) ([ADR-0022](../adr/0022-web-categories-ut1.md)). |
| `-categories-url URL` | | URL from which to download and refresh the UT1 category archive daily. |
| `-portal-dir PATH` | `$OPENSASE_PORTAL_DIR` | Directory containing the static Flutter web admin portal (`index.html`) served at `/admin/`. |
| `-backup-dir PATH` | | Directory where scheduled SQLite backups (database copy and PKI archive) are written. Empty disables automated backups. |
| `-backup-every DUR` | `24h0m0s` | Interval between scheduled backups. |
| `-backup-keep N` | `7` | Number of scheduled backups to retain. |
| `-ops-listen ADDR` | | Plain HTTP listen address for `/metrics`, `/healthz`, and `/readyz` ([Monitoring](../operations/monitoring.md)). |
| `-debug` | `false` | Enable verbose debug-level logging. |

---

## `edge`

`edge` runs the OpenSASE Edge data plane service. It requires Linux with `CAP_NET_ADMIN` and access to `/dev/net/tun`.

### Command-line flags

| Flag | Default | Description |
|---|---|---|
| `-control-url URL` | `https://controlplane:9443` | Control Plane API endpoint. |
| `-pki DIR` | `pki/edge` | Edge PKI directory containing `root.crt`, `edge.crt`, `edge.key`, and `edge-wg.key`. |
| `-listen ADDR` | `:8443` | HTTPS session-setup listener address. |
| `-wg-port PORT` | `51820` | WireGuard UDP listen port. |
| `-wg-endpoint HOST:PORT` | `edge:51820` | WireGuard endpoint advertised to client devices. |
| `-tun NAME` | `wg0` | TUN network interface name. |
| `-mtu N` | `1280` | Network MTU for the tunnel interface. |
| `-upstream-dns ADDR` | `1.1.1.1:53` | Upstream DNS resolver used for external query resolution. |
| `-rotate DUR` | `10m0s` | WireGuard PSK rotation interval returned to client devices. |
| `-deny-cidrs CIDRS` | | Comma-separated list of destination CIDRs blocked from tunnel traffic, in addition to standard private ranges. |
| `-allow-private` | `false` | Permit tunnel clients to reach RFC 1918, CGNAT, and IPv6 ULA ranges. Link-local, loopback, multicast, and Edge local IPs remain blocked. |
| `-allow-doh` | `false` | Disable the built-in blocking of external DNS-over-HTTPS resolver endpoints. |
| `-ocr URL` | | OCR service endpoint for DLP inspection on images ([ADR-0024](../adr/0024-dlp-legacy-office-ocr.md)), e.g. `http://ocr:8090`. |
| `-icap URL` | | ICAP service URL (`icap://host[:port]/service`) for malware scanning on inspected traffic. Alternative to `-clamd`. |
| `-clamd ADDR` | | ClamAV daemon address (`host:port`) for malware scanning on inspected traffic ([ADR-0020](../adr/0020-malware-scanning.md)). |
| `-inspect-listen ADDR` | `off` | Local listener address for decrypted TLS inspection traffic redirected by kernel iptables/nftables (`off` disables) ([ADR-0018](../adr/0018-tls-inspection.md)). |
| `-ztna-listen ADDR` | `0.0.0.0:15001` | Local listener address for ZTNA private application traffic redirected from `100.96.0.0/12` (`off` disables). |
| `-broker-listen ADDR` | `:8444` | Inbound mTLS listener port for ZTNA Connectors (`ALPN opensase-broker/1`; `off` disables). |
| `-tenant ID` | | Scope the Edge exclusively to this tenant (Private Edge, [ADR-0014](../adr/0014-private-edge.md)). Must match Control Plane registration. |
| `-state-dir PATH` | | Directory used to cache the last good Control Plane peer state for offline startup. |
| `-flow-log PATH` | | Path to a local JSONL file where flow records are appended (automatically rotated to `FILE.1` at 64 MiB). |
| `-ops-listen ADDR` | | Plain HTTP listen address for `/metrics`, `/healthz`, and `/readyz` ([Monitoring](../operations/monitoring.md)). |
| `-debug` | `false` | Enable verbose debug-level logging. |

---

## `opensase` (desktop CLI)

`opensase` controls the background desktop daemon (`opensased` on Linux or `OpenSASE` service on Windows) via its local API ([ADR-0032](../adr/0032-windows-client.md)).

### Global flags

| Flag | Default | Description |
|---|---|---|
| `-socket PATH` | `/run/opensase/opensased.sock` | Path to the local Unix domain socket (Linux / macOS). |
| `-pipe PATH` | `\\.\pipe\opensase` | Path to the local named pipe (Windows). |
| `-json` | `false` | Output responses in structured JSON format. |
| `-timeout DUR` | `15s` | Command execution timeout. |

### Commands

#### `status`

Displays the current daemon connection state, enrolled status, connected Edge, negotiated post-quantum key exchange, and active policy version.

```bash
opensase status
```

#### `connect`

Brings up the secure VPN tunnel through the nearest available Edge.

```bash
opensase connect
```

#### `disconnect`

Brings down the VPN tunnel and restores standard routing.

```bash
opensase disconnect
```

#### `enroll`

Enrolls the client device with the Control Plane. Modifies device certificates and requires elevated root or administrator privileges.

```bash
opensase enroll -control URL [-name NAME] [-key-file FILE | -sso TENANT]
```

| Flag | Default | Description |
|---|---|---|
| `-control URL` | | Control Plane URL including the root CA certificate SHA-256 fingerprint fragment (`#sha256=<hash>`). Required. |
| `-name NAME` | *(hostname)* | Device name registered in the tenant directory. |
| `-key-file FILE` | | Path to file containing the one-time device provisioning key. |
| `-sso TENANT` | | Authenticate via the tenant's configured OIDC identity provider in the browser. |

If neither `-key-file` nor `-sso` is provided, `opensase` checks the `OPENSASE_PROVISIONING_KEY` environment variable or prompts for the key interactively on stdin.

#### `unenroll`

Unenrolls the device, deleting local client certificates and cryptographic keys.

```bash
opensase unenroll [-yes]
```

| Flag | Default | Description |
|---|---|---|
| `-yes` | `false` | Confirm unenrollment without prompting. Required in non-interactive terminals. |

#### `flows`

Displays recent network traffic flows evaluated by the local policy engine.

```bash
opensase flows [-n N]
```

| Flag | Default | Description |
|---|---|---|
| `-n N` | `50` | Maximum number of flow records to display. |

#### `events`

Streams real-time policy engine events from the background daemon.

```bash
opensase events [-f]
```

| Flag | Default | Description |
|---|---|---|
| `-f` | `false` | Follow event stream indefinitely until interrupted. |

#### `version`

Prints the compiled client binary version.

```bash
opensase version
```
