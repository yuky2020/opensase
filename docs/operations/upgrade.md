# Upgrading

This page describes how to upgrade OpenSASE components in place across Docker Compose,
Kubernetes with Helm, and client packages.

## Upgrade principles

OpenSASE commits to semantic versioning starting at v1.0 ([Release quality bar](../release-quality-bar.md)).

- **Stable baseline:** Central components (Control Plane, Edges, Connectors) and client software
  run the same release version across your deployment. Do not run mixed versions in steady state.
- **Forward-only migrations:** State and database formats are internal. Schema migrations run
  automatically at startup when a new binary or container image boots.
- **In-place upgrades:** Upgrades proceed in place without re-enrolling devices and without
  losing PKI state or tenant policies.
- **Backup first:** Always back up the database and PKI directory before upgrading (see
  [Backup and restore](backup.md)).

---

## Upgrading Docker Compose

For standalone deployments using Docker Compose:

1. Back up the database and PKI directory:

    ```bash
    docker exec controlplane opensasectl store backup -db /data/controlplane.db -o /data/controlplane-backup.db
    tar -czf pki-backup.tar.gz pki/
    ```

2. Pull the new container image versions:

    ```bash
    docker compose pull
    ```

3. Update image version tags in `docker-compose.yml` or your `.env` file to the target version.
4. Restart the services:

    ```bash
    docker compose down
    docker compose up -d
    ```

5. The Control Plane runs database migrations automatically on startup before accepting requests.
6. Verify service health and readiness:

    ```bash
    curl -f http://127.0.0.1:9090/readyz
    curl -f http://127.0.0.1:9091/readyz
    ```

---

## Upgrading Kubernetes with Helm

OpenSASE provides two Helm charts: `opensase-controlplane` and `opensase-edge` (see
[Install on Kubernetes](../kubernetes.md)).

### SQLite deployments

Single-replica Control Plane deployments using SQLite (`database.type=sqlite`) use the `Recreate`
deployment strategy on a `ReadWriteOnce` persistent volume.

1. Back up your SQLite volume and PKI secret (see [Backup and restore](backup.md)).
2. Upgrade the Control Plane chart:

    ```bash
    helm upgrade cp deploy/helm/opensase-controlplane -n opensase \
      --set image.tag=<new-version> \
      --reuse-values
    ```

3. Upgrade each Edge chart:

    ```bash
    helm upgrade edge1 deploy/helm/opensase-edge -n opensase-edge \
      --set image.tag=<new-version> \
      --reuse-values
    ```

4. Wait for the rollouts to complete:

    ```bash
    kubectl rollout status deployment/cp-opensase-controlplane -n opensase
    kubectl rollout status deployment/edge1-opensase-edge -n opensase-edge
    ```

### PostgreSQL deployments

Multi-replica Control Plane deployments using PostgreSQL (`database.type=postgres`, [ADR-0033](../adr/0033-postgresql-and-replicas.md))
support rolling updates.

1. Back up the PostgreSQL database with `pg_dump` and back up the PKI secret.
2. Upgrade the Control Plane release:

    ```bash
    helm upgrade cp deploy/helm/opensase-controlplane -n opensase \
      --set image.tag=<new-version> \
      --reuse-values
    ```

3. The first pod to start acquires a transaction-level advisory lock (`pg_advisory_xact_lock`)
   and executes any pending schema migrations from `migrations/postgres/*.sql`. Subsequent pods
   wait for the lock, detect that migrations are applied, and proceed to serve.
4. Upgrade each Edge release:

    ```bash
    helm upgrade edge1 deploy/helm/opensase-edge -n opensase-edge \
      --set image.tag=<new-version> \
      --reuse-values
    ```

5. Monitor the rollout status:

    ```bash
    kubectl rollout status deployment/cp-opensase-controlplane -n opensase
    kubectl rollout status deployment/edge1-opensase-edge -n opensase-edge
    ```

---

## Upgrading client packages

Enrolled devices keep their keys, certificates, and cached policy snapshots across software updates.
Devices do not need to re-enrol after an upgrade.

### Linux (.deb)

1. Download the new `.deb` package from the release page ([Download](../download.md)) and verify
   it ([Verify a download](../verify.md)).
2. Install the package:

    ```bash
    sudo apt install ./opensase_<version>_amd64.deb
    ```

3. Restart the background daemon:

    ```bash
    sudo systemctl restart opensased
    ```

4. Verify tunnel status:

    ```bash
    opensase status
    ```

### Windows (.msi)

1. Download the updated MSI installer from the release page ([Download](../download.md)) and verify
   it ([Verify a download](../verify.md)).
2. Run the MSI installer with administrator privileges.
3. The installer updates `opensased.exe`, `opensase.exe`, and the desktop application, preserving
   credentials in `%ProgramData%\OpenSASE`.
4. If updating standalone binaries manually, stop the service, replace the files, and restart:

    ```powershell
    net stop OpenSASE
    # replace opensased.exe, opensase.exe, and wintun.dll in C:\Program Files\OpenSASE
    net start OpenSASE
    opensase.exe status
    ```

### Android (.apk)

1. Download the new release APK or distribute it via your mobile management system.
2. Install the update over the existing installation:

    ```bash
    adb install -r opensase-<version>-android.apk
    ```

3. Launch OpenSASE. Stored credentials and policy snapshots in application storage remain intact.

---

## Post-upgrade verification

Verify the deployment health after upgrading:

1. **Check version and features:**

    ```bash
    opensasectl info
    ```

    The output displays the active version and enabled features.

2. **Check liveness and readiness:**
   Query `/healthz` and `/readyz` on the ops listener (`-ops-listen`):

    ```bash
    curl -i http://127.0.0.1:9090/readyz
    curl -i http://127.0.0.1:9091/readyz
    ```

3. **Check Prometheus metrics:**
   Verify that metrics report normal status (see [Monitoring](monitoring.md)):
    - `opensase_cp_audit_chain_ok` reports `1`.
    - `opensase_edge_peer_sync_failures_total` is not increasing.
    - `opensase_edge_sessions` matches expected active client sessions.

4. **Verify client connectivity:**
   Run `opensase status` on an enrolled client to confirm the tunnel state is `connected` and
   post-quantum key exchange (`X25519MLKEM768`) is established.
