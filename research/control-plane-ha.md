# Research: Control Plane high availability (issue #39)

Question: what does it take to run more than one Control Plane replica? Should OpenSASE keep
SQLite (with a backup or replication tool such as Litestream, or a consensus layer such as
rqlite or dqlite) or move to PostgreSQL? How do the hash-chained audit log, PKI signing and
policy snapshot versions stay consistent? Which leader election options exist in Go without
heavy new dependencies?

Target user: a small company (10-200 people, one admin) that runs Docker Compose and also
wants Kubernetes.

Researched 2026-11-24. Repository state as read from the working tree at
`/home/matt/claude/opensase`.

---

## 1. Current state in the code (what assumes a single process)

### Persistence

- `pkg/store/store.go`: SQLite through `modernc.org/sqlite` v1.62.0 (pure Go, no cgo). The DSN
  sets `journal_mode(WAL)`, `busy_timeout(5000)`, `foreign_keys(1)` and `_txlock=immediate`,
  and the code calls `db.SetMaxOpenConns(1)` ("SQLite allows one writer").
- There are 11 embedded migrations (`pkg/store/migrations/0001..0011`), applied at `Open` and
  recorded in `schema_migrations`. Nothing makes two processes skip each other while they
  migrate. With SQLite this is safe only because the file is local and writes are serialized.
- SQLite-specific SQL: `?` placeholders (about 76 across `pkg/store/*.go`), 4×
  `INTEGER PRIMARY KEY AUTOINCREMENT`, 10× `BLOB`, 4× `RETURNING`, 6× `ON CONFLICT`,
  1× `LastInsertId`, and integer Unix timestamps. Every one has a direct PostgreSQL equivalent
  (`$n`, `bigint GENERATED ... AS IDENTITY`, `bytea`, `RETURNING`, `ON CONFLICT`). Only
  `LastInsertId` must become `RETURNING id`, because pgx/PostgreSQL does not support it.
- `docs/architecture.md` already lists **PostgreSQL** as the planned "Primary DB", with no
  alternatives. The SQLite store is the MVP implementation.

### Hash-chained audit log (ADR-0028, `pkg/store/audit.go`)

- `hash = SHA-256(prev_hash ‖ id ‖ at ‖ actor ‖ tenant_id ‖ method ‖ path ‖ status)`.
- `AddAudit` reads the head (`SELECT hash ... ORDER BY id DESC LIMIT 1`), inserts the row,
  then sets its hash, all in one transaction. The append is serialized by
  `Store.auditMu sync.Mutex` **plus** the single-writer SQLite transaction. ADR-0028 says
  so: "Appends are serialised, by a mutex plus the single-writer SQLite transaction, so the
  chain never forks."
- `DeleteAuditBefore` (retention) and `chainLegacyAudit` take the same mutex.
- **Multi-replica impact:** the mutex is per process. On a shared database that allows
  concurrent writers, two replicas can read the same head and write two entries with the
  same `prev_hash`, which forks the chain. `VerifyAudit` would then report the second entry
  as bad. Under the default PostgreSQL isolation (Read Committed) nothing prevents this
  ([PG docs: transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html)).

### PKI (`pkg/pki/dir.go`, `pkg/pki/pki.go`)

- The root CA, the Control Plane certificate, the snapshot signing key (`snapshot.key`,
  Ed25519) and `edges.json` are **files**, mounted read-only in Compose
  (`deploy/dev/docker-compose.yml`).
- Tenant CAs are created **lazily** by `Authority.TenantCA` and written to
  `pki/tenants/<id>/ca.{crt,key}`, a writable volume ("tenant CAs are created on demand").
  They are guarded by `Authority.mu`, which is also per process.
- `OpenAuthority` loads the tenant CAs only at start-up. `BundlePEM` and `ClientCAPool` are
  served from that in-memory map.
- Certificate serials are 127-bit random (`pki.go:260`). They need no coordination.
- **Multi-replica impact:** if two replicas each meet a new tenant for the first time, each
  generates a **different** tenant CA key. Without a shared writable directory, each replica
  keeps its own. Devices enrolled on replica A then fail mTLS on replica B. Even with a
  shared directory, the two replicas race (last write wins on disk, while each keeps its own
  copy in memory). A replica also never sees a tenant CA that another replica created after
  it started.
- The signing key and the root CA are read-only and identical on every replica. They are
  safe as long as the same files (or the same Secret) are mounted everywhere.

### Policy snapshot versions (`pkg/store/store.go` `SaveSnapshot`, `internal/controlplane/snapshot.go`)

- `snapshot_versions.version INTEGER PRIMARY KEY AUTOINCREMENT` is a **global** counter.
  `SaveSnapshot` reserves the next version, calls `build(version)` to compile and sign inside
  the same transaction, then stores the envelope.
- `tenant_policy.version` is bumped with `version = version + 1` inside an
  `ON CONFLICT DO UPDATE`. That is atomic in any SQL database.
- Policy writes use optimistic concurrency (If-Match, issue #19). The read-check-write is
  serialized by `Server.policyMu sync.Mutex` (`handlers.go:569`), which is per process.
  **Multi-replica impact:** two replicas can both pass the ETag check and both write, which
  loses an update. The fix is a conditional write in SQL (`UPDATE ... WHERE version = $old`),
  or `SELECT ... FOR UPDATE`.
- Long-poll wake-ups use an in-memory `notifier` (`snapshot.go:351`). If replica A compiles
  a new snapshot, a device long-polling replica B is not woken. It only sees the snapshot
  when its poll times out.
- `compiledCache` and `decide` are per-process caches keyed by `version`. They are safe
  because a stale entry is detected by its version number, at the cost of duplicated memory.

### Other per-process state

- `oidcPending map[string]pendingOIDCLogin` (`oidc.go:254`): the OIDC state/nonce of a portal
  sign-in. A callback that lands on another replica fails. This needs sticky sessions, or the
  state must move into the database or a signed cookie.
- `pollLimiter`, `flowLimit`, `enrollLimit` (`hardening.go`): the limits become per replica
  (N replicas means N× the limit). That is acceptable for a small deployment, but should be
  documented.
- `maintain()` (`server.go:337`, every 10 minutes): it re-signs expiring snapshots, prunes
  snapshots, and applies flow and audit retention, and the category list refreshes daily.
  These are **singleton jobs**. If every replica runs them, the work is duplicated, and the
  audit retention (which rewrites the anchor) races with appends from other replicas.

**Summary:** everything that must be serialized is serialized by in-process mutexes, and that
is correct only while there is one process. HA therefore means more than a database question.
At least five mutexes or maps have to become database-level or leader-only.

---

## 2. Option A: keep SQLite

### A1. SQLite on a shared volume (NFS or a cloud file share), several replicas

**Not viable.**
- WAL mode: "All processes using a database must be on the same host computer; WAL does not
  work over a network filesystem", because the wal-index lives in shared memory
  ([sqlite.org/wal.html](https://www.sqlite.org/wal.html)).
- On network filesystems, "SQLite relies on exclusive locks for write operations, and those
  have been known to operate incorrectly for some network filesystems. This has led to
  database corruption" ([sqlite.org/useovernet.html](https://www.sqlite.org/useovernet.html)).
  The page recommends a client/server engine such as PostgreSQL instead.

### A2. Litestream (WAL streaming to object storage or a file replica)

- How it works: Litestream is a separate process that "continuously copies write-ahead log
  pages from disk to a replica". It takes over checkpointing and needs WAL mode
  ([how it works](https://litestream.io/how-it-works/), [tips](https://litestream.io/tips/)).
- RPO: replication is asynchronous, every second by default, and "a catastrophic crash on
  your server will result in the loss of data in that time window". "Synchronous replication
  is on the Litestream roadmap but has not yet been implemented" ([tips](https://litestream.io/tips/)).
- Single writer: "Litestream does not currently support multiple live replicas"; "Litestream
  only allows a single node at a time in a StatefulSet" (`replicas: 1`), and an init
  container restores the database before start-up
  ([Kubernetes guide](https://litestream.io/guides/kubernetes/)). Users must make sure "you
  do not have multiple applications replicating concurrently" ([tips](https://litestream.io/tips/)).
- There is a read-only VFS that can serve reads from replica storage
  ([how it works](https://litestream.io/how-it-works/)). It does not help write paths.
- **What it buys:** disaster recovery and fast rebuilds with roughly 1 s of possible loss.
  It gives **no** active-active setup and no automatic failover: recovery time equals pod
  reschedule plus restore. Our requirements already fit it: `busy_timeout` is already 5 s,
  which is what Litestream recommends, and WAL is already on. **It needs no code changes**,
  because it runs as a sidecar.
- Risk to the audit chain: a restore to a point before the last ≤1 s loses the newest
  entries. The chain still verifies, but a previously published head hash
  (`AuditHashAt`) would no longer exist. That is detectable, and it is the honest behavior.

Note: the SQLite project's own guidance is that a server-side, application-specific database
server using SQLite works well when "requests are serialized in the server"
([whentouse](https://www.sqlite.org/whentouse.html)), which is exactly today's design.

### A3. rqlite (Raft cluster of SQLite nodes, separate server process)

- Raft gives one authoritative copy. Only the Leader changes the database, and other nodes
  forward writes. A write costs "two round trips from a Leader to a quorum of nodes", and
  "rqlite is distributed primarily for high availability and fault tolerance, not for
  performance" ([FAQ](https://rqlite.io/docs/faq/)).
- Access is through an **HTTP API**. The Go clients (`rqlite-go-http`, `gorqlite`) are listed
  without any claim of `database/sql` support
  ([client libraries](https://rqlite.io/docs/api/client-libraries/)).
- **Transactions:** "using BEGIN, COMMIT, and ROLLBACK is officially unsupported" ([FAQ](https://rqlite.io/docs/faq/)).
  Only a single request with `?transaction` is atomic ([API](https://rqlite.io/docs/api/api/)).
  That **breaks** `SaveSnapshot` (read the version, sign in Go, write in one tx) and
  `AddAudit` (read the head, hash in Go, insert in one tx). Both interleave Go code with
  SQL inside a transaction.
- Non-determinism: `RANDOM()` and `datetime('now')` are rewritten, but "rqlite doesn't
  currently rewrite parameters for non-deterministic functions", and column defaults and
  triggers are evaluated per node ([non-deterministic](https://rqlite.io/docs/api/non-deterministic/)).
  OpenSASE passes timestamps from Go, so this matters less.
- Read consistency defaults to *Weak*: a deposed leader "may briefly return stale data".
  *Linearizable* costs a quorum round trip ([read consistency](https://rqlite.io/docs/api/read-consistency/)).
- You need 3 nodes for fault tolerance (Raft quorum). That is one more stateful service to
  run, which is a lot for a single admin.

### A4. dqlite (embedded Raft SQLite, `go-dqlite`)

- `go-dqlite` provides "bindings for the dqlite C library". You need "the dqlite C library
  installed on your system, along with its dependencies", and the install instructions are
  Debian/Ubuntu packages. `app.New(...)` plus `app.Open(...)` returns a `*sql.DB`.
  License: Apache-2.0 ([go-dqlite README](https://github.com/canonical/go-dqlite)).
- It is embedded, so there is no extra service. But it brings **cgo and a C dependency
  chain**. That contradicts the current pure-Go `modernc.org/sqlite` choice and the static
  distroless-style images, and it makes the Windows and macOS dev builds harder. You still
  need 3 voting nodes.

---

## 3. Option B: PostgreSQL

### Driver
- `github.com/jackc/pgx/v5`: "a pure Go driver and toolkit for PostgreSQL", with a
  `database/sql` adapter in `stdlib`, under the MIT license
  ([pkg.go.dev](https://pkg.go.dev/github.com/jackc/pgx/v5)). It keeps the build cgo-free.

### PostgreSQL HA itself
- Streaming replication "is asynchronous by default", and the lag is "typically under one
  second". Synchronous replication is set with `synchronous_standby_names` and
  `synchronous_commit` (`on`, `remote_write`, `remote_apply`), at the cost of commit latency
  ([warm-standby](https://www.postgresql.org/docs/current/warm-standby.html)).
- "PostgreSQL does not provide the system software required to identify a failure on the
  primary and notify the standby". You need an external tool, and fencing (STONITH) so that
  the old primary knows it is no longer primary
  ([failover](https://www.postgresql.org/docs/current/warm-standby-failover.html)).
- On Kubernetes, **CloudNativePG** (CNCF Incubating, Apache-2.0) manages streaming replicas
  and, "If the primary instance fails, the operator elects a new primary"
  ([README](https://github.com/cloudnative-pg/cloudnative-pg)).
- On Docker Compose, nothing built in does failover. A small company would realistically run
  **one** PostgreSQL container with WAL archiving and backups, which makes the database
  itself a single point of failure (as SQLite is today). The gain is that the
  **application** tier can have N replicas, and PostgreSQL can be run or hosted separately.

### What PostgreSQL gives the consistency problems
- **Audit chain:** `SELECT pg_advisory_xact_lock(<audit-key>)` at the start of the
  `AddAudit` and `DeleteAuditBefore` transactions serializes appends across all replicas.
  It is released automatically at commit or rollback ([advisory lock functions](https://www.postgresql.org/docs/current/functions-admin.html),
  [explicit locking §13.3.5](https://www.postgresql.org/docs/current/explicit-locking.html)).
  An equivalent is `SELECT ... FROM audit_anchor WHERE id=1 FOR UPDATE` on a one-row head
  table. A `UNIQUE (prev_hash)` constraint is a cheap safety net: a fork then becomes a
  constraint error instead of silent corruption.
- **Snapshot versions:** an identity/sequence column stays globally unique, but "PostgreSQL
  sequence objects cannot be used to obtain 'gapless' sequences"
  ([sequence functions](https://www.postgresql.org/docs/current/functions-sequence.html)).
  Values are handed out without waiting for other transactions, so commit order can differ
  from number order (an inference from the docs). OpenSASE only needs "latest by
  `MAX(version)` per device" and monotonicity per device. That holds if compiling one
  device's snapshot is serialized, for example with
  `pg_advisory_xact_lock(hashtext(device_id))`, or done only by the leader.
- **Policy If-Match:** replace `policyMu` with a conditional
  `UPDATE tenant_policy ... WHERE tenant_id=$1 AND version=$2`, and treat 0 rows as 412.
  This also works on SQLite, so it can be done now.
- **Cross-replica long-poll wake-up:** `LISTEN`/`NOTIFY`, which notifies "all the sessions
  currently listening" and fires on commit ([LISTEN](https://www.postgresql.org/docs/current/sql-listen.html)).
  This replaces the in-memory `notifier` without NATS. (NATS is listed in
  `architecture.md`, but it would be one more service.)
- **Migrations:** wrap `migrate()` in a session advisory lock so that only one replica
  migrates at start-up.
- Higher isolation levels need retry logic for SQLSTATE `40001`
  ([transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html)).
  Explicit locks under Read Committed avoid that.

### PKI with PostgreSQL
- Move the tenant CA (certificate and **encrypted** private key) into a table. Insert it with
  `ON CONFLICT (tenant_id) DO NOTHING`, then re-read, so all replicas converge on the
  winner's key. Replicas refresh their in-memory map on a miss, or on a `NOTIFY`. Better
  still, create tenant CAs **eagerly** in `CreateTenant` instead of lazily.
- The root CA and snapshot signing keys stay as identical read-only files or a Kubernetes
  Secret mounted in every replica. Signing is a stateless Ed25519/ECDSA operation, so N
  replicas can sign in parallel. Snapshots signed by different replicas verify against the
  same `SigningKeyID`.
- Storing CA keys in the database widens the blast radius of a database dump. That argues
  for envelope encryption with a key from a file or Secret, which was out of scope for dev
  so far (`InitDir` comment: "encryption at rest is out of scope for dev").

---

## 4. Leader election in Go (for singleton jobs: `maintain()`, retention, category refresh)

| Mechanism | Dependency | Guarantee | Works in Compose | Works in K8s |
|---|---|---|---|---|
| PostgreSQL session advisory lock (`pg_try_advisory_lock`) on a dedicated connection | none beyond pgx | Held "until explicitly released or the session ends". Returns `true`/`false` without waiting ([docs](https://www.postgresql.org/docs/current/functions-admin.html)) | yes | yes |
| Kubernetes Lease (`coordination.k8s.io/v1`), via `client-go/tools/leaderelection` | `k8s.io/client-go` (large module tree) | "does not guarantee that only one client is acting as a leader (a.k.a. fencing)". Tolerates clock skew, not skew *rate* ([pkg.go.dev](https://pkg.go.dev/k8s.io/client-go/tools/leaderelection)) | no | yes |
| Kubernetes Lease via plain HTTPS PUT with `resourceVersion` | none (net/http plus a service-account token) | API server returns `409 Conflict` on a stale `resourceVersion` ([API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)). Lease fields: `holderIdentity`, `leaseDurationSeconds`, `renewTime`, `leaseTransitions` ([Lease v1](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/lease-v1/)) | no | yes |
| Raft (rqlite or dqlite built-in leader) | the cluster itself | Raft leader | yes (3 nodes) | yes |
| None: run only one replica (`replicas: 1`) | none | trivial | yes | yes |

Notes:
- Kubernetes documents Leases for custom workloads: "You define a Lease so that the
  controller replicas can select or elect a leader", with a product-prefixed name such as
  `opensase-controlplane` ([Leases](https://kubernetes.io/docs/concepts/architecture/leases/)).
- Docker Compose `deploy.replicas` only sets "the number of containers that should be
  running". It offers `vip`/`dnsrr` endpoint modes and nothing for leader election
  ([Compose deploy spec](https://docs.docker.com/reference/compose-file/deploy/)). So a
  mechanism that must work in **both** Compose and Kubernetes has to live in the database.
  The PostgreSQL advisory lock is the only listed option that needs no extra dependency and
  works in both.
- Fencing: with an advisory lock, the leader loses the lock when its connection drops, but
  it may not notice right away. Leader-only jobs should therefore be idempotent, or
  re-check the lock inside their own transaction (`pg_try_advisory_xact_lock` on the same
  key as part of the job's transaction). The jobs here (re-sign, prune, retention) are
  already idempotent, except the audit retention, which the per-transaction audit lock
  above covers.

---

## 5. Comparison

| | SQLite + Litestream (1 replica) | rqlite | dqlite | PostgreSQL (N app replicas) |
|---|---|---|---|---|
| Active-active Control Plane | no | yes (writes via leader) | yes | yes |
| Automatic failover | reschedule + restore | Raft | Raft | app: yes; DB: CloudNativePG on K8s, manual on Compose |
| Data loss on node loss | ≤ ~1 s (async) | none (quorum) | none (quorum) | none (single DB on durable disk) / async lag with replicas unless synchronous |
| Code change | none | large (no interactive tx, HTTP API) | medium (driver swap, cgo) | medium (driver, SQL dialect, replace 5 mutexes, PKI to DB) |
| New dependencies | sidecar binary | 3-node service | C library + cgo | DB server + pgx |
| Ops burden for one admin | lowest | high | medium | low on Compose (1 container), low-medium on K8s with operator |
| Fits architecture.md | interim | no | no | yes ("Primary DB: PostgreSQL") |

---

## Implications for OpenSASE

These are inputs to a decision, not a decision.

**The real HA risk is in the code, not the database.** Per-process mutexes (`auditMu`,
`policyMu`, `Authority.mu`), in-memory maps (`oidcPending`, `notifier`, lazily created tenant
CAs) and unguarded singleton jobs (`maintain()`) make a second replica incorrect on *any*
shared database. Also, the data plane already keeps working on the last good signed snapshot
while the Control Plane is down (design principle 4). That makes Control Plane downtime a
**control-path** outage: no new enrollments, policy edits or portal sign-ins. It is not a
traffic outage. For a 10-200 person company with one admin, minutes of recovery time are
usually acceptable.

**Options:**

1. **Stay at one replica, add Litestream (or a periodic `VACUUM INTO` / online backup,
   [sqlite.org/backup.html](https://www.sqlite.org/backup.html)) and fast restart.** This
   needs zero code changes and the same story in Compose and Kubernetes (StatefulSet
   `replicas: 1`). Trade-offs: about 1 s RPO, recovery time equal to restart plus restore,
   and no rolling upgrades without a short gap. The PKI directory and `tenants/` still need
   their own backup, because they are outside the database.
2. **Move to PostgreSQL and allow N stateless app replicas.** Trade-offs: a medium refactor
   (pgx, dialect, advisory-lock audit append, conditional policy write, tenant CAs in the
   database with encrypted keys, `LISTEN`/`NOTIFY` wake-ups, OIDC state in the database,
   advisory-lock leader for `maintain()`). The database itself is HA only on Kubernetes with
   CloudNativePG. On Compose it is one container, but app replicas and rolling upgrades
   become possible. This matches `architecture.md`.
3. **rqlite or dqlite.** Not recommended. rqlite's lack of interactive transactions breaks
   the core sign-inside-transaction patterns (`SaveSnapshot`, `AddAudit`). dqlite brings
   cgo and a C library, and both need 3 nodes, which is too much for one admin.

**Recommendation (for discussion):** do (1) now, as the supported mode for Compose and small
installs. Then make the code **HA-ready on its own merits**, which helps under SQLite too:
- the conditional `UPDATE ... WHERE version=?` for If-Match;
- eager, database-stored tenant CAs;
- a `UNIQUE(prev_hash)` guard on the audit table;
- OIDC state in the database or a signed cookie;
- a `Store` interface seam so that a PostgreSQL backend can be added behind it.

Then offer (2), PostgreSQL via pgx, with the PostgreSQL advisory lock as the *single* leader
election mechanism for both Compose and Kubernetes. Make it opt-in for operators who need
active-active or rolling upgrades, with CloudNativePG as the documented Kubernetes path. Avoid
`client-go`: if Kubernetes Leases are ever needed, a roughly 100-line HTTPS Lease client with
`resourceVersion` conflicts is enough. Record the outcome as an ADR (ADR-0028 needs an update,
because its "single-writer SQLite transaction" guarantee would change).
