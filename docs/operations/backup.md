# Backup and restore

This page explains how to back up and restore the OpenSASE Control Plane state for SQLite and
PostgreSQL, how to configure scheduled automated backups, how to migrate from SQLite to
PostgreSQL, and which PKI keys must be preserved.

## What to back up

A full backup of OpenSASE requires two components:

1. **The database:**
   The Control Plane database (SQLite database file `controlplane.db`, or PostgreSQL database)
   stores tenants, users, user groups, devices, provisioning keys, policies, user rules, policy
   snapshots, flow records, audit logs, registered Edges, Connectors, DLP dataset hashes, and
   sealed CA private keys.
2. **The PKI directory (`-pki`, default `pki`):**
   The directory containing the root CA, server certificates, snapshot signing keys, and key
   encryption key:
    - `root.crt` and `root.key`: Provider root CA certificate and private key.
    - `controlplane.crt` and `controlplane.key`: Control Plane server TLS certificate and private key.
    - `snapshot.key`: Ed25519 signing key used to sign Policy Snapshots.
    - `ca-kek.key`: 32-byte AES key used to seal tenant intermediate CAs and web inspection CAs
      in the database.
    - `edges.json`: Edge directory containing public keys and endpoints.

!!! important "Back up ca-kek.key with the database"
    Tenant intermediate CAs and web inspection CAs stored in the database are encrypted with
    `ca-kek.key` (AES-256-GCM, [Certificates](certificates.md)). If you restore a database
    without the corresponding `ca-kek.key`, the Control Plane cannot decrypt tenant CAs and
    will fail to start or issue certificates (`wrong key encryption key or tampered row`).

---

## Scheduled backups (Control Plane flags)

The Control Plane can automatically create scheduled SQLite backups and PKI archives
(issue #67). Configure these flags on `controlplane`:

| Flag | Default | Description |
|---|---|---|
| `-backup-dir` | `""` | Directory to write scheduled backups. Empty string disables scheduled backups. |
| `-backup-every` | `24h` | Interval between scheduled backups. |
| `-backup-keep` | `7` | Number of recent backups to keep before pruning older files. |
| `-pki` | `pki` | PKI directory to archive alongside the database. |

When enabled, the leader Control Plane replica periodically writes two files to `-backup-dir`:

- `controlplane-<UTC-timestamp>.db`: Consistent SQLite snapshot created using `VACUUM INTO` (mode `0600`).
- `pki-<UTC-timestamp>.tar.gz`: Gzip tar archive containing regular files from the PKI directory (mode `0600`).

Older backups exceeding `-backup-keep` are pruned automatically.

!!! note "Scheduled backups are for SQLite"
    Scheduled backups via `-backup-dir` are supported on SQLite only. For PostgreSQL deployments,
    the Control Plane logs a notice and relies on PostgreSQL tools (`pg_dump`).

---

## SQLite backup and restore with opensasectl

### Online backup (`opensasectl store backup`)

`opensasectl store backup` writes a consistent snapshot of an active SQLite database using
SQLite's `VACUUM INTO` command. It is safe to run while the Control Plane is operating:

```bash
opensasectl store backup -db /data/controlplane.db -o /backups/controlplane-backup.db
```

The output file is created with mode `0600` because it contains tenant policies and credentials.
Back up the `pki/` directory at the same time:

```bash
tar -czf /backups/pki-backup.tar.gz -C /path/to/pki .
```

### Restore (`opensasectl store restore`)

`opensasectl store restore` verifies that a SQLite backup opens, applies pending migrations, and
validates the cryptographic audit hash chain before restoring the database.

1. Stop the Control Plane process or container.
2. Move the existing database file aside:

    ```bash
    mv /data/controlplane.db /data/controlplane.db.corrupt
    ```

3. Restore and verify the backup file:

    ```bash
    opensasectl store restore -from /backups/controlplane-backup.db -to /data/controlplane.db
    ```

    If the audit chain in the backup has been altered, the command fails and prints the corrupted
    entry ID:

    ```text
    opensasectl: store: backup check: audit chain broken at entry 42: ...
    ```

4. Restore the matching PKI directory:

    ```bash
    tar -xzf /backups/pki-backup.tar.gz -C /path/to/pki
    ```

5. Start the Control Plane.

---

## PostgreSQL backup and restore

For multi-replica deployments using PostgreSQL (`-db postgres://...`, [ADR-0033](../adr/0033-postgresql-and-replicas.md)):

### Back up with pg_dump

Create a custom-format dump of the database:

```bash
pg_dump -Fc -d "$OPENSASE_DB" -f opensase-postgres.dump
```

Archive the shared PKI directory:

```bash
tar -czf pki-postgres-backup.tar.gz -C /path/to/pki .
```

### Restore with pg_restore

1. Stop all Control Plane replicas.
2. Restore the database:

    ```bash
    pg_restore --clean --if-exists -d "$OPENSASE_DB" opensase-postgres.dump
    ```

3. Ensure the identical `pki/` directory, including `ca-kek.key`, is mounted on all replicas.
4. Start the Control Plane replicas.

---

## Migrating SQLite to PostgreSQL (`opensasectl store migrate`)

To migrate an existing single-replica SQLite installation to PostgreSQL ([ADR-0033](../adr/0033-postgresql-and-replicas.md)):

1. Stop the Control Plane. The SQLite database must not change during migration.
2. Create an empty PostgreSQL database and user.
3. Run `opensasectl store migrate`:

    ```bash
    OPENSASE_DB="postgres://user:password@pg.example.com:5432/opensase?sslmode=verify-full" \
      opensasectl store migrate -from /data/controlplane.db
    ```

    You can also pass the destination URL via `-to postgres://...`. Using `$OPENSASE_DB` keeps
    database credentials out of process listings (`ps`).

### What store migrate does

1. Connects to the target PostgreSQL database and runs schema migrations (`migrations/postgres/*.sql`).
2. Checks that the PostgreSQL database is empty (`SELECT COUNT(*) FROM tenants` returns 0).
3. Copies all tables in foreign-key dependency order within a single transaction:
   `tenants`, `users`, `devices`, `provisioning_keys`, `tenant_policy`, `user_rules`,
   `snapshot_versions`, `flows`, `edges`, `edge_sessions`, `connectors`,
   `connector_provisioning_keys`, `admin_tokens`, `admin_audit`, `audit_anchor`, `dlp_datasets`,
   `tenant_oidc`, `device_routes`, `oidc_pending`, `cas`, `edge_reports`, `user_groups`,
   `scim_groups`, and `scim_tokens`.
4. Updates PostgreSQL identity sequences (`setval`) to match copied IDs.
5. Verifies row counts between SQLite and PostgreSQL for every table.
6. Verifies the integrity of the cryptographic audit hash chain on PostgreSQL.

### Post-migration configuration

1. Ensure all Control Plane replicas share the same PKI directory containing `ca-kek.key`.
2. Configure the Control Plane with `-db "$OPENSASE_DB"` (or the `OPENSASE_DB` environment variable).
3. Start the Control Plane replicas. Verify leader election via the Prometheus metric
   `opensase_cp_leader` (see [Monitoring](monitoring.md)).
