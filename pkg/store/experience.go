package store

import (
	"context"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// ExperienceRow pairs a stored experience sample with its device ID.
type ExperienceRow struct {
	DeviceID string
	api.ExperienceSample
}

// InsertExperience stores digital experience samples for a device in tenantID.
func (s *Store) InsertExperience(ctx context.Context, tenantID, deviceID string, samples []api.ExperienceSample) error {
	if len(samples) == 0 {
		return nil
	}
	return mapErr(s.tx(ctx, func(tx *txh) error {
		st, err := tx.PrepareContext(ctx, `INSERT INTO experience_samples(tenant_id, device_id, edge_id, at, rtt_ms, loss_pct, dns_ms, network) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, smp := range samples {
			if _, err := st.ExecContext(ctx, tenantID, deviceID, smp.EdgeID, smp.At.Unix(), smp.RTTms, smp.LossPct, smp.DNSms, smp.Network); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ExperienceSince returns experience samples recorded for tenantID since time since.
// If deviceID is non-empty, only samples for that device are returned.
func (s *Store) ExperienceSince(ctx context.Context, tenantID string, since time.Time, deviceID string) ([]ExperienceRow, error) {
	q := `SELECT device_id, edge_id, at, rtt_ms, loss_pct, dns_ms, network FROM experience_samples WHERE tenant_id = ? AND at >= ? AND (? = '' OR device_id = ?) ORDER BY at, id`
	rows, err := s.db.QueryContext(ctx, q, tenantID, since.Unix(), deviceID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExperienceRow{}
	for rows.Next() {
		var r ExperienceRow
		var at int64
		if err := rows.Scan(&r.DeviceID, &r.EdgeID, &at, &r.RTTms, &r.LossPct, &r.DNSms, &r.Network); err != nil {
			return nil, err
		}
		r.At = time.Unix(at, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteExperienceBefore deletes experience samples recorded before t and returns how many.
func (s *Store) DeleteExperienceBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM experience_samples WHERE at < ?`, t.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
