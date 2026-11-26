package store

import (
	"context"
	"database/sql"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// The store writes every query once, with ? placeholders, in the SQL subset that SQLite and
// PostgreSQL both accept (ADR-0033). dbh and txh rewrite the placeholders for PostgreSQL.

type dbh struct {
	*sql.DB
	pg bool
}

type txh struct {
	*sql.Tx
	pg bool
}

func (d *dbh) q(query string) string { return rebind(d.pg, query) }

func (d *dbh) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, d.q(query), args...)
}

func (d *dbh) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, d.q(query), args...)
}

func (d *dbh) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, d.q(query), args...)
}

// Query, QueryRow and Exec are used by tests only.
func (d *dbh) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(d.q(query), args...)
}

func (d *dbh) QueryRow(query string, args ...any) *sql.Row { return d.DB.QueryRow(d.q(query), args...) }

func (d *dbh) Exec(query string, args ...any) (sql.Result, error) {
	return d.DB.Exec(d.q(query), args...)
}

// BeginTx starts a transaction with the same guarantee on both engines: it holds the
// database-wide write lock from the start, so read-check-write transactions never interleave
// (ADR-0033). SQLite gets it from BEGIN IMMEDIATE (_txlock=immediate in the DSN); on
// PostgreSQL the transaction takes a transaction-scoped advisory lock, released at commit or
// rollback. Single statements outside a transaction are atomic and take no lock.
func (d *dbh) BeginTx(ctx context.Context, opts *sql.TxOptions) (*txh, error) {
	tx, err := d.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	t := &txh{Tx: tx, pg: d.pg}
	if err := t.lock(ctx, "write"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return t, nil
}

func (t *txh) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, rebind(t.pg, query), args...)
}

func (t *txh) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, rebind(t.pg, query), args...)
}

func (t *txh) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, rebind(t.pg, query), args...)
}

func (t *txh) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return t.Tx.PrepareContext(ctx, rebind(t.pg, query))
}

// lock takes a transaction-scoped advisory lock on key (PostgreSQL); on SQLite the
// transaction already holds the database write lock, so it does nothing.
func (t *txh) lock(ctx context.Context, key string) error {
	if !t.pg {
		return nil
	}
	_, err := t.Tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID(key))
	return err
}

func lockID(key string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("opensase:" + key))
	return int64(h.Sum64()) //nolint:gosec // G115: any 64-bit value is a valid advisory lock id
}

// rebind rewrites ? placeholders to $1, $2, ... for PostgreSQL, leaving quoted strings and
// identifiers alone.
func rebind(pg bool, q string) string {
	if !pg || !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	var quote byte
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// pgCode returns the PostgreSQL error code of err, or "".
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
