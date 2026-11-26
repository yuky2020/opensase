// Package store is the Control Plane persistence layer (SQLite via modernc.org/sqlite).
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/tunneladdr"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	_ "modernc.org/sqlite"             // registers the "sqlite" driver
)

//go:embed migrations/*.sql migrations/postgres/*.sql
var migrations embed.FS

var (
	// ErrNotFound is returned when a row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned on a uniqueness violation.
	ErrConflict = errors.New("store: already exists")
	// ErrKeyInvalid is returned when a provisioning key is unknown, expired or used up.
	ErrKeyInvalid = errors.New("store: provisioning key invalid, expired or used up")
)

// Store wraps the SQLite database. It is safe for concurrent use.
type Store struct {
	db      *dbh
	leader  atomic.Bool // PostgreSQL: this replica holds the leader lock (ADR-0033)
	auditMu sync.Mutex  // serialises audit appends so the hash chain never forks
}

// Open opens the database and applies migrations. dsn is a SQLite file path (created if
// needed), ":memory:" for tests, or a PostgreSQL URL (postgres://… or postgresql://…) for
// several Control Plane replicas (ADR-0033).
func Open(ctx context.Context, dsn string) (*Store, error) {
	if IsPostgres(dsn) {
		return openPostgres(ctx, dsn)
	}
	path := dsn
	if path != ":memory:" {
		if err := restrictDBFiles(path); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite allows one writer; a single connection also keeps ":memory:" databases shared.
	db.SetMaxOpenConns(1)
	return finishOpen(ctx, &Store{db: &dbh{DB: db}})
}

// IsPostgres reports whether dsn selects the PostgreSQL backend.
func IsPostgres(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

func openPostgres(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: connect to PostgreSQL: %w", err)
	}
	return finishOpen(ctx, &Store{db: &dbh{DB: db, pg: true}})
}

func finishOpen(ctx context.Context, s *Store) (*Store, error) {
	if err := s.migrate(ctx); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	if err := s.chainLegacyAudit(ctx); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	if err := s.assignTunnelOffsets(ctx); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	return s, nil
}

// Postgres reports whether the store runs on PostgreSQL.
func (s *Store) Postgres() bool { return s.db.pg }

// restrictDBFiles creates the database file 0600 (SQLite gives the -wal and -shm files the
// mode of the main file) and tightens existing files: the store holds every tenant's
// policies and flows (ST-09).
func restrictDBFiles(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: operator-configured DB path
	if err != nil {
		return fmt.Errorf("store: open: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("store: chmod %s: %w", p, err)
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	pattern := "migrations/*.sql"
	if s.db.pg {
		pattern = "migrations/postgres/*.sql"
	}
	names, err := fs.Glob(migrations, pattern)
	if err != nil {
		return err
	}
	sort.Strings(names)
	return s.tx(ctx, func(tx *txh) error {
		// One replica migrates; the others wait for the write lock (BeginTx), then find
		// nothing to do.
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)`); err != nil {
			return fmt.Errorf("store: migrations table: %w", err)
		}
		for _, n := range names {
			var x int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE name = ?`, n).Scan(&x)
			if err == nil {
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: check migration %s: %w", n, err)
			}
			body, err := migrations.ReadFile(n)
			if err != nil {
				return err
			}
			if _, err := tx.Tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("store: apply migration %s: %w", n, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)`, n, time.Now().Unix()); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) tx(ctx context.Context, fn func(*txh) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case isUniqueViolation(err), strings.Contains(err.Error(), "PRIMARY KEY constraint failed"):
		return ErrConflict
	case strings.Contains(err.Error(), "FOREIGN KEY constraint failed"), pgCode(err) == "23503":
		return ErrNotFound
	}
	return err
}

// affected maps a write that touched no row (e.g. a missing parent) to ErrNotFound.
func affected(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Tenant is a row of the tenants table.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// CreateTenant inserts a tenant.
func (s *Store) CreateTenant(ctx context.Context, t Tenant) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO tenants(id, name, created_at) VALUES (?, ?, ?)`, t.ID, t.Name, time.Now().Unix())
	return mapErr(err)
}

// GetTenant returns a tenant by ID.
func (s *Store) GetTenant(ctx context.Context, id string) (Tenant, error) {
	var t Tenant
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, created_at FROM tenants WHERE id = ?`, id).Scan(&t.ID, &t.Name, &ts)
	t.CreatedAt = time.Unix(ts, 0)
	return t, mapErr(err)
}

// ListTenants returns every tenant, ordered by ID.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		var ts int64
		if err := rows.Scan(&t.ID, &t.Name, &ts); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(ts, 0)
		out = append(out, t)
	}
	return out, rows.Err()
}

// User is a row of the users table.
type User struct {
	ID       string
	TenantID string
	Email    string
	Name     string
}

// CreateUser inserts a user. The tenant must exist.
func (s *Store) CreateUser(ctx context.Context, u User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id, tenant_id, email, name, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.TenantID, u.Email, u.Name, time.Now().Unix())
	return mapErr(err)
}

// GetUser returns a user of a tenant.
func (s *Store) GetUser(ctx context.Context, tenantID, userID string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, tenant_id, email, name FROM users WHERE tenant_id = ? AND id = ?`, tenantID, userID).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.Name)
	return u, mapErr(err)
}

// ListUsers returns the users of a tenant, ordered by email.
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, tenant_id, email, name FROM users WHERE tenant_id = ? ORDER BY email, id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.Name); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ProvisioningKey is a row of provisioning_keys. Hash is SHA-256 of the secret key.
type ProvisioningKey struct {
	Hash      []byte
	TenantID  string
	UserID    string
	MaxUses   int
	ExpiresAt time.Time
}

// CreateProvisioningKey stores the hash of a new key. MaxUses < 1 means single use.
func (s *Store) CreateProvisioningKey(ctx context.Context, k ProvisioningKey) error {
	if len(k.Hash) != 32 {
		return errors.New("store: provisioning key hash must be 32 bytes")
	}
	if k.MaxUses < 1 {
		k.MaxUses = 1
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO provisioning_keys(key_hash, tenant_id, user_id, max_uses, expires_at, created_at)
		SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND tenant_id = ?)`,
		k.Hash, k.TenantID, k.UserID, k.MaxUses, k.ExpiresAt.Unix(), time.Now().Unix(), k.UserID, k.TenantID)
	return affected(res, err)
}

// Enrollment is the device created by Enroll.
type Enrollment struct {
	TenantID string
	UserID   string
}

// Device is a row of the devices table.
type Device struct {
	ID         string
	TenantID   string
	UserID     string
	Name       string
	Platform   string
	CertSerial string
	// PrevCertSerial is the serial replaced by the last renewal; it is valid only for
	// retrying POST /v1/renew.
	PrevCertSerial string
	Revoked        bool
	CreatedAt      time.Time
	// TunnelOffset is the device's host offset in the tunnel prefixes (pkg/tunneladdr),
	// the same on every Edge (issue #70).
	TunnelOffset uint32
}

// nextTunnelOffset returns the next unassigned tunnel offset. Offsets only grow, so a
// revoked device's addresses are never given to another device. Callers run it inside a
// write transaction.
func nextTunnelOffset(ctx context.Context, tx *txh) (uint32, error) {
	var last int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(tunnel_offset), 1) FROM devices`).Scan(&last); err != nil {
		return 0, err
	}
	off := tunneladdr.NextUsable(uint32(last) + 1) //nolint:gosec // G115: offsets are below 2^22
	if off == 0 {
		return 0, errors.New("store: tunnel address pool exhausted")
	}
	return off, nil
}

// assignTunnelOffsets gives an offset to every device that has none (devices enrolled before
// migration 0015).
func (s *Store) assignTunnelOffsets(ctx context.Context) error {
	return s.tx(ctx, func(tx *txh) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM devices WHERE tunnel_offset = 0 ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		for _, id := range ids {
			off, err := nextTunnelOffset(ctx, tx)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET tunnel_offset = ? WHERE id = ?`, off, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// Enroll atomically consumes one use of the provisioning key with the given hash and
// creates the device returned by mkDevice (called inside the transaction with the key's
// tenant and user). If mkDevice fails, the key use is not consumed.
func (s *Store) Enroll(ctx context.Context, hash []byte, now time.Time, mkDevice func(Enrollment) (Device, error)) (Device, error) {
	var d Device
	err := s.tx(ctx, func(tx *txh) error {
		var e Enrollment
		err := tx.QueryRowContext(ctx, `UPDATE provisioning_keys SET uses = uses + 1
			WHERE key_hash = ? AND uses < max_uses AND expires_at > ? RETURNING tenant_id, user_id`, hash, now.Unix()).
			Scan(&e.TenantID, &e.UserID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrKeyInvalid
		}
		if err != nil {
			return err
		}
		d, err = mkDevice(e)
		if err != nil {
			return err
		}
		if d.TunnelOffset, err = nextTunnelOffset(ctx, tx); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO devices(id, tenant_id, user_id, name, platform, cert_serial, created_at, tunnel_offset) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			d.ID, e.TenantID, e.UserID, d.Name, d.Platform, d.CertSerial, now.Unix(), d.TunnelOffset)
		d.TenantID, d.UserID, d.CreatedAt = e.TenantID, e.UserID, now
		return err
	})
	if errors.Is(err, ErrKeyInvalid) {
		return Device{}, err
	}
	return d, mapErr(err)
}

const deviceCols = `id, tenant_id, user_id, name, platform, cert_serial, prev_cert_serial, revoked, created_at, tunnel_offset`

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var ts int64
	err := sc.Scan(&d.ID, &d.TenantID, &d.UserID, &d.Name, &d.Platform, &d.CertSerial, &d.PrevCertSerial, &d.Revoked, &ts, &d.TunnelOffset)
	d.CreatedAt = time.Unix(ts, 0)
	return d, err
}

// GetDevice returns a device by ID.
func (s *Store) GetDevice(ctx context.Context, id string) (Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
	return d, mapErr(err)
}

// DeviceFilter selects devices in ListDevices. Empty fields match everything.
type DeviceFilter struct {
	TenantID       string
	UserID         string
	IncludeRevoked bool
}

// ListDevices lists devices matching f, ordered by creation.
func (s *Store) ListDevices(ctx context.Context, f DeviceFilter) ([]Device, error) {
	q := `SELECT ` + deviceCols + ` FROM devices WHERE (? = '' OR tenant_id = ?) AND (? = '' OR user_id = ?) AND (? OR revoked = 0) ORDER BY created_at, id`
	rows, err := s.db.QueryContext(ctx, q, f.TenantID, f.TenantID, f.UserID, f.UserID, f.IncludeRevoked)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice marks a device of a tenant as revoked.
func (s *Store) RevokeDevice(ctx context.Context, tenantID, deviceID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET revoked = 1 WHERE tenant_id = ? AND id = ?`, tenantID, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetTenantPolicy returns the tenant layer. ErrNotFound if none was set.
func (s *Store) GetTenantPolicy(ctx context.Context, tenantID string) (api.TenantPolicy, error) {
	var raw string
	var p api.TenantPolicy
	if err := s.db.QueryRowContext(ctx, `SELECT policy FROM tenant_policy WHERE tenant_id = ?`, tenantID).Scan(&raw); err != nil {
		return p, mapErr(err)
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, fmt.Errorf("store: decode tenant policy: %w", err)
	}
	return p, nil
}

// PutTenantPolicy replaces the tenant layer.
func (s *Store) PutTenantPolicy(ctx context.Context, tenantID string, p api.TenantPolicy) error {
	_, err := s.UpdateTenantPolicy(ctx, tenantID, func(api.TenantPolicy, bool) (api.TenantPolicy, error) { return p, nil })
	return err
}

// UpdateTenantPolicy reads the tenant layer, passes it to update and stores the result, in
// one transaction (issue #66). exists is false when no policy was set; cur is then the zero
// policy. An error from update aborts the write and is returned unchanged.
//
// The transaction takes the database write lock when it begins (the DSN sets
// _txlock=immediate), so two Control Plane replicas cannot interleave a read and a write:
// this is what makes If-Match safe without a per-process mutex.
func (s *Store) UpdateTenantPolicy(ctx context.Context, tenantID string, update func(cur api.TenantPolicy, exists bool) (api.TenantPolicy, error)) (api.TenantPolicy, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.TenantPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var cur api.TenantPolicy
	var raw string
	exists := true
	switch err := tx.QueryRowContext(ctx, `SELECT policy FROM tenant_policy WHERE tenant_id = ?`, tenantID).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
		exists = false
	case err != nil:
		return api.TenantPolicy{}, err
	default:
		if err := json.Unmarshal([]byte(raw), &cur); err != nil {
			return api.TenantPolicy{}, fmt.Errorf("store: decode tenant policy: %w", err)
		}
	}
	next, err := update(cur, exists)
	if err != nil {
		return api.TenantPolicy{}, err
	}
	b, err := json.Marshal(next)
	if err != nil {
		return api.TenantPolicy{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_policy(tenant_id, policy, updated_at, version) VALUES (?, ?, ?, 1)
		ON CONFLICT(tenant_id) DO UPDATE SET policy = excluded.policy, updated_at = excluded.updated_at, version = tenant_policy.version + 1`,
		tenantID, string(b), time.Now().Unix()); err != nil {
		return api.TenantPolicy{}, mapErr(err)
	}
	return next, mapErr(tx.Commit())
}

// TenantPolicyVersion returns the number of times the tenant policy was written (0 if never).
// It increases with every PutTenantPolicy.
func (s *Store) TenantPolicyVersion(ctx context.Context, tenantID string) (uint64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, `SELECT version FROM tenant_policy WHERE tenant_id = ?`, tenantID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return uint64(v), err
}

// GetUserRules returns the user layer. ErrNotFound if none was set.
func (s *Store) GetUserRules(ctx context.Context, tenantID, userID string) (api.UserRules, error) {
	var raw string
	var r api.UserRules
	if err := s.db.QueryRowContext(ctx, `SELECT rules FROM user_rules WHERE tenant_id = ? AND user_id = ?`, tenantID, userID).Scan(&raw); err != nil {
		return r, mapErr(err)
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return r, fmt.Errorf("store: decode user rules: %w", err)
	}
	return r, nil
}

// PutUserRules replaces the user layer of a user.
func (s *Store) PutUserRules(ctx context.Context, tenantID, userID string, r api.UserRules) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO user_rules(user_id, tenant_id, rules, updated_at)
		SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND tenant_id = ?)
		ON CONFLICT(user_id) DO UPDATE SET rules = excluded.rules, updated_at = excluded.updated_at`,
		userID, tenantID, string(raw), time.Now().Unix(), userID, tenantID)
	return affected(res, err)
}

// SnapshotRecord is a stored signed snapshot.
type SnapshotRecord struct {
	Version   uint64
	DeviceID  string
	Envelope  []byte // JSON policy.Envelope
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SaveSnapshot reserves the next global version for deviceID, calls build with it (to
// compile and sign the snapshot), and stores the result, all in one transaction.
func (s *Store) SaveSnapshot(ctx context.Context, deviceID string, issued, expires time.Time, build func(version uint64) ([]byte, error)) (SnapshotRecord, error) {
	rec := SnapshotRecord{DeviceID: deviceID, IssuedAt: issued, ExpiresAt: expires}
	err := s.tx(ctx, func(tx *txh) error {
		var v int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO snapshot_versions(device_id, issued_at, expires_at) VALUES (?, ?, ?) RETURNING version`,
			deviceID, issued.Unix(), expires.Unix()).Scan(&v); err != nil {
			return err
		}
		rec.Version = uint64(v)
		env, err := build(rec.Version)
		if err != nil {
			return err
		}
		rec.Envelope = env
		_, err = tx.ExecContext(ctx, `UPDATE snapshot_versions SET envelope = ? WHERE version = ?`, env, v)
		return err
	})
	return rec, mapErr(err)
}

// LatestSnapshot returns the newest snapshot of a device.
func (s *Store) LatestSnapshot(ctx context.Context, deviceID string) (SnapshotRecord, error) {
	var r SnapshotRecord
	var iss, exp int64
	err := s.db.QueryRowContext(ctx, `SELECT version, device_id, envelope, issued_at, expires_at FROM snapshot_versions
		WHERE device_id = ? AND envelope IS NOT NULL ORDER BY version DESC LIMIT 1`, deviceID).
		Scan(&r.Version, &r.DeviceID, &r.Envelope, &iss, &exp)
	r.IssuedAt, r.ExpiresAt = time.Unix(iss, 0), time.Unix(exp, 0)
	return r, mapErr(err)
}

// ActiveSnapshot pairs a non-revoked device with its newest snapshot.
type ActiveSnapshot struct {
	Device   Device
	Snapshot SnapshotRecord
}

// ActiveSnapshots returns every non-revoked device that has a snapshot, with the newest one.
func (s *Store) ActiveSnapshots(ctx context.Context) ([]ActiveSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, d.tenant_id, d.user_id, d.name, d.platform, d.cert_serial, d.revoked, d.created_at, d.tunnel_offset,
			sv.version, sv.envelope, sv.issued_at, sv.expires_at
		FROM devices d JOIN snapshot_versions sv ON sv.version =
			(SELECT MAX(version) FROM snapshot_versions WHERE device_id = d.id AND envelope IS NOT NULL)
		WHERE d.revoked = 0 ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActiveSnapshot
	for rows.Next() {
		var a ActiveSnapshot
		var ts, iss, exp int64
		d := &a.Device
		if err := rows.Scan(&d.ID, &d.TenantID, &d.UserID, &d.Name, &d.Platform, &d.CertSerial, &d.Revoked, &ts, &d.TunnelOffset,
			&a.Snapshot.Version, &a.Snapshot.Envelope, &iss, &exp); err != nil {
			return nil, err
		}
		d.CreatedAt = time.Unix(ts, 0)
		a.Snapshot.DeviceID = d.ID
		a.Snapshot.IssuedAt, a.Snapshot.ExpiresAt = time.Unix(iss, 0), time.Unix(exp, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneSnapshots deletes all but the newest keep snapshots per device.
func (s *Store) PruneSnapshots(ctx context.Context, keep int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM snapshot_versions WHERE version IN (
		SELECT version FROM (SELECT version, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY version DESC) AS rn FROM snapshot_versions) WHERE rn > ?)`, keep)
	return err
}

// InsertFlows stores flow records of a tenant.
func (s *Store) InsertFlows(ctx context.Context, tenantID string, recs []api.FlowRecord) error {
	if len(recs) == 0 {
		return nil
	}
	return mapErr(s.tx(ctx, func(tx *txh) error {
		st, err := tx.PrepareContext(ctx, `INSERT INTO flows(tenant_id, device_id, where_, start, record) VALUES (?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, r := range recs {
			raw, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := st.ExecContext(ctx, tenantID, r.DeviceID, r.Where, r.Start.Unix(), string(raw)); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ListFlows returns the newest flow records of a tenant, newest first.
func (s *Store) ListFlows(ctx context.Context, tenantID string, limit int) ([]api.FlowRecord, error) {
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM flows WHERE tenant_id = ? ORDER BY id DESC LIMIT ?`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []api.FlowRecord{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r api.FlowRecord
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, fmt.Errorf("store: decode flow: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
