package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrRevoked is returned when a row exists but is revoked.
var ErrRevoked = errors.New("store: revoked")

// RenewDeviceCert atomically replaces the certificate serial of a non-revoked device with
// newSerial. presented is the serial of the certificate that authenticated the renewal:
//
//   - the current serial: it becomes the previous serial and newSerial the current one;
//   - the previous serial (the device retries after losing a renewal response): newSerial
//     replaces the current serial, which was never delivered; the previous serial is kept.
//
// Anything else is ErrConflict (e.g. two concurrent renewals with the current cert: only one
// wins). It returns ErrNotFound for an unknown device and ErrRevoked for a revoked one.
func (s *Store) RenewDeviceCert(ctx context.Context, deviceID, presented, newSerial string) error {
	return s.renewCert(ctx, "devices", deviceID, presented, newSerial)
}

// renewCert implements RenewDeviceCert and RenewConnectorCert. table is a constant.
func (s *Store) renewCert(ctx context.Context, table, id, presented, newSerial string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var cur, prev string
		var revoked bool
		err := tx.QueryRowContext(ctx, `SELECT cert_serial, prev_cert_serial, revoked FROM `+table+` WHERE id = ?`, id).Scan(&cur, &prev, &revoked)
		if err != nil {
			return mapErr(err)
		}
		switch {
		case revoked:
			return ErrRevoked
		case presented == "" || newSerial == "" || cur == "":
			return ErrConflict
		case presented == cur:
			prev = cur
		case presented == prev:
		default:
			return ErrConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE `+table+` SET cert_serial = ?, prev_cert_serial = ? WHERE id = ? AND cert_serial = ? AND revoked = 0`, //nolint:gosec // G202: table is a constant ("devices" or "connectors") from the callers
			newSerial, prev, id, cur)
		return err
	})
}

// Edge is a row of the edges table.
type Edge struct {
	ID        string
	Revoked   bool
	CreatedAt time.Time
}

// CreateEdge registers an edge ID. ErrConflict if it exists (revoked or not).
func (s *Store) CreateEdge(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO edges(id, created_at) VALUES (?, ?)`, id, time.Now().Unix())
	return mapErr(err)
}

// GetEdge returns a registered edge.
func (s *Store) GetEdge(ctx context.Context, id string) (Edge, error) {
	var e Edge
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT id, revoked, created_at FROM edges WHERE id = ?`, id).Scan(&e.ID, &e.Revoked, &ts)
	e.CreatedAt = time.Unix(ts, 0)
	return e, mapErr(err)
}

// ListEdges returns every registered edge, ordered by ID.
func (s *Store) ListEdges(ctx context.Context) ([]Edge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, revoked, created_at FROM edges ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Edge{}
	for rows.Next() {
		var e Edge
		var ts int64
		if err := rows.Scan(&e.ID, &e.Revoked, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RevokeEdge revokes an edge and forgets its sessions. Revocation is permanent: the ID
// cannot be registered again.
func (s *Store) RevokeEdge(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE edges SET revoked = 1 WHERE id = ?`, id)
		if err := affected(res, err); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM edge_sessions WHERE edge_id = ?`, id)
		return err
	})
}

// ReportEdgeSessions records that edgeID has live sessions for deviceIDs at now. Unknown
// device IDs are ignored. Rows older than now-keep (devices the edge no longer reports) are
// deleted for this edge.
func (s *Store) ReportEdgeSessions(ctx context.Context, edgeID string, deviceIDs []string, now time.Time, keep time.Duration) error {
	return mapErr(s.tx(ctx, func(tx *sql.Tx) error {
		st, err := tx.PrepareContext(ctx, `INSERT INTO edge_sessions(edge_id, device_id, updated_at)
			SELECT ?, id, ? FROM devices WHERE id = ? AND revoked = 0
			ON CONFLICT(edge_id, device_id) DO UPDATE SET updated_at = excluded.updated_at`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, d := range deviceIDs {
			if _, err := st.ExecContext(ctx, edgeID, now.Unix(), d); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM edge_sessions WHERE edge_id = ? AND updated_at < ?`, edgeID, now.Add(-keep).Unix())
		return err
	}))
}

// EdgeHasSession reports whether edgeID reported a live session for deviceID at or after since.
func (s *Store) EdgeHasSession(ctx context.Context, edgeID, deviceID string, since time.Time) (bool, error) {
	var x int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM edge_sessions WHERE edge_id = ? AND device_id = ? AND updated_at >= ?`,
		edgeID, deviceID, since.Unix()).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// DeleteFlowsBefore deletes flow records that started before t and returns how many.
func (s *Store) DeleteFlowsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM flows WHERE start < ?`, t.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
