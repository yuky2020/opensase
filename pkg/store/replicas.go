package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Coordination between Control Plane replicas on PostgreSQL (ADR-0033). On SQLite there is
// one process: it is always the leader and wake-ups stay local.

const (
	notifyChannel  = "opensase"
	leaderRetry    = 15 * time.Second
	listenRetryMax = 30 * time.Second
)

// IsLeader reports whether this replica runs the singleton jobs (retention, snapshot
// re-signing, audit head logging). Always true on SQLite.
func (s *Store) IsLeader() bool { return !s.db.pg || s.leader.Load() }

// KeepLeadership competes for leadership until ctx ends: it holds a session-level advisory
// lock on a dedicated connection, so a crashed leader's lock is released with its session
// and another replica takes over within leaderRetry. changed is called on each transition.
// On SQLite it returns at once.
func (s *Store) KeepLeadership(ctx context.Context, changed func(leader bool)) {
	if !s.db.pg {
		return
	}
	var conn *sql.Conn
	drop := func() {
		if conn != nil {
			// Discard the session instead of returning it to the pool: closing the session
			// is what releases the advisory lock.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			_ = conn.Close()
			conn = nil
		}
		if s.leader.Swap(false) && changed != nil {
			changed(false)
		}
	}
	defer drop()
	t := time.NewTicker(leaderRetry)
	defer t.Stop()
	for {
		if s.leader.Load() {
			if err := conn.PingContext(ctx); err != nil {
				drop()
			}
		} else {
			var err error
			if conn == nil {
				conn, err = s.db.Conn(ctx)
			}
			var got bool
			if err == nil {
				err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, lockID("leader")).Scan(&got)
			}
			switch {
			case err != nil:
				drop()
			case got:
				s.leader.Store(true)
				if changed != nil {
					changed(true)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Publish sends key to the other replicas (PostgreSQL NOTIFY); it does nothing on SQLite.
func (s *Store) Publish(ctx context.Context, key string) error {
	if !s.db.pg {
		return nil
	}
	_, err := s.db.DB.ExecContext(ctx, `SELECT pg_notify($1, $2)`, notifyChannel, key)
	return err
}

// Subscribe calls fn for every key published by any replica (this one included) until ctx
// ends. After the listening connection is (re)established it calls resync, because keys
// published while it was down are lost. On SQLite it returns at once.
func (s *Store) Subscribe(ctx context.Context, fn func(key string), resync func()) {
	if !s.db.pg {
		return
	}
	wait := time.Second
	for ctx.Err() == nil {
		err := s.listen(ctx, fn, resync)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			wait = min(wait*2, listenRetryMax)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Store) listen(ctx context.Context, fn func(string), resync func()) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// Never hand a LISTENing session back to the pool.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	}()
	return conn.Raw(func(dc any) error {
		sc, ok := dc.(*stdlib.Conn)
		if !ok {
			return errors.New("store: not a pgx connection")
		}
		pc := sc.Conn()
		if _, err := pc.Exec(ctx, "LISTEN "+pgx.Identifier{notifyChannel}.Sanitize()); err != nil {
			return err
		}
		if resync != nil {
			resync()
		}
		for {
			n, err := pc.WaitForNotification(ctx)
			if err != nil {
				return err
			}
			fn(n.Payload)
		}
	})
}
