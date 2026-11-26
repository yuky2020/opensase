# ADR-0033: PostgreSQL store and several Control Plane replicas

Status: accepted (2026-11-26)

## Context

The Control Plane keeps its state in one SQLite database. One process owns it, and several
invariants relied on that process being the only one:

- the If-Match policy check;
- the audit hash chain;
- the tenant CAs;
- pending OIDC sign-ins;
- the periodic jobs;
- the long-poll wake-ups.

The v1.0 decision #50 asks for several active Control Plane replicas on PostgreSQL. SQLite
stays the default for single-node installs (Compose, the quick start, a one-replica Helm
release). Research #39 listed what breaks with a second replica.

Issue #66 already moved the per-process invariants into the database:

- conditional policy write in one transaction;
- `oidc_pending` table;
- unique `prev_hash` on the audit chain;
- tenant and inspection CAs in the `cas` table, keys sealed with a shared key.

## Decision

### One store, two dialects

- `store.Open(ctx, dsn)` selects the backend from the DSN:
  - a path or `:memory:` selects SQLite (unchanged);
  - `postgres://…` or `postgresql://…` selects PostgreSQL through the pgx `database/sql`
    driver.
- The store keeps one set of queries, written with `?` placeholders. A thin wrapper over
  `*sql.DB` and `*sql.Tx` rewrites them to `$1, $2, …` for PostgreSQL.
- The SQL used is the subset both engines accept:
  - `INSERT … ON CONFLICT … DO UPDATE/NOTHING`;
  - `RETURNING`;
  - partial indexes;
  - integer Unix timestamps.
  - No `LastInsertId`: inserts that need the new id use `RETURNING id`.
- Migrations live in two directories with the same file names:
  - `migrations/` (SQLite) and `migrations/postgres/`;
  - PostgreSQL starts at `0014` with the schema equal to SQLite after `0014`;
  - every later change adds a file to both directories.
- Migrations run in one transaction under the write lock below; replicas that start at
  the same time wait for it and then find nothing to apply.
- Types: `BLOB` maps to `BYTEA`, `INTEGER PRIMARY KEY AUTOINCREMENT` to
  `BIGINT GENERATED ALWAYS AS IDENTITY`, and `INTEGER` to `BIGINT`.
- Errors: a unique violation (SQLite text, PostgreSQL code `23505`) maps to
  `store.ErrConflict`; a foreign key violation (`23503`) maps to `store.ErrNotFound`, as
  today.

### Serialisation

Every store transaction holds a database-wide write lock from its first statement, on both
engines, so a read-check-write transaction (policy If-Match, audit append, certificate
renewal, provisioning key use) never interleaves with another:

- SQLite: `BEGIN IMMEDIATE` (the DSN's `_txlock=immediate`).
- PostgreSQL (READ COMMITTED): `pg_advisory_xact_lock` on one fixed key at the start of each
  transaction, released at commit or rollback.

Single statements outside a transaction are atomic and take no lock. Writes are therefore
serialised as with SQLite; the extra replicas add availability and read capacity, not write
throughput, which is enough for the target (a small company). The unique index on
`admin_audit.prev_hash` stays as a second line of defence.

### Singleton jobs

- Retention, snapshot re-signing and audit head logging run on one replica: the leader.
  Each replica downloads the category list into its own cache file.
- The leader holds a session-level advisory lock on a dedicated connection. The others retry
  every 15 seconds, so a new leader takes over within about 15 seconds of a crash (the lock
  is released when the session ends).
- SQLite: the single process is always the leader.

### Cross-replica wake-ups and caches

- Long-poll wake-ups are published with `NOTIFY opensase, '<key>'` in addition to the local
  notifier. Every replica `LISTEN`s and wakes its local waiters. A replica that loses the
  listener connection reconnects and wakes every waiter once, so clients re-poll and do not
  miss a change.
- The decide cache stores the tenant policy version it was built from, and checks the
  version on each use, so no invalidation message is needed. The compiled snapshot cache is
  already keyed by snapshot version.
- Each new tenant CA reaches the client CA pool of the other replicas within 30 seconds
  (issue #66).
- Rate limiters stay per replica: the effective limit is N times the configured one, which
  is acceptable for abuse protection.

### Migration from SQLite

`opensasectl store migrate -from <sqlite path> -to <postgres dsn>` copies every table in
dependency order inside one PostgreSQL transaction, then checks the row counts and the audit
chain. The Control Plane is stopped during the copy.

### Shared files

All replicas mount the same PKI directory (a Kubernetes Secret), including:

- the root CA;
- the Control Plane certificate;
- the snapshot signing key;
- `ca-kek.key`.

The PostgreSQL URL is read from `$OPENSASE_DB` (or `-db`), so the password stays off the
command line.

## Consequences

- One code path for queries: every store test runs against both backends in CI (PostgreSQL
  as a service container); a query that only one engine accepts fails there.
- SQLite remains the simplest install; PostgreSQL is opt-in with `-db postgres://…`.
- Rolling upgrades of several replicas require backward-compatible migrations; the v1.0
  promise is a stable baseline with the same release everywhere (#44), so an upgrade still
  restarts all replicas on the new version.
- Checks: store tests on both engines; an e2e job with two Control Plane replicas behind one
  address and PostgreSQL, where a device enrolled through one replica polls the other and a
  policy change made on one wakes a long-poll held by the other.
