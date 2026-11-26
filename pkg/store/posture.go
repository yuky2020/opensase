package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// SetDevicePosture stores or updates the latest posture report and failing checks of a device.
func (s *Store) SetDevicePosture(ctx context.Context, tenantID, deviceID string, p api.Posture, failing []string, at time.Time) error {
	repJSON, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("store: marshal posture: %w", err)
	}
	if failing == nil {
		failing = []string{}
	}
	failJSON, err := json.Marshal(failing)
	if err != nil {
		return fmt.Errorf("store: marshal posture failing: %w", err)
	}
	q := `INSERT INTO device_posture(device_id, tenant_id, report, failing, reported_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			tenant_id = excluded.tenant_id,
			report = excluded.report,
			failing = excluded.failing,
			reported_at = excluded.reported_at`
	_, err = s.db.ExecContext(ctx, q, deviceID, tenantID, string(repJSON), string(failJSON), at.Unix())
	return mapErr(err)
}

// DevicePosture returns the latest posture report of deviceID. Returns ErrNotFound if none exists.
func (s *Store) DevicePosture(ctx context.Context, deviceID string) (api.DevicePosture, error) {
	var dp api.DevicePosture
	var repJSON, failJSON string
	var reportedAt int64
	q := `SELECT report, failing, reported_at FROM device_posture WHERE device_id = ?`
	err := s.db.QueryRowContext(ctx, q, deviceID).Scan(&repJSON, &failJSON, &reportedAt)
	if err != nil {
		return dp, mapErr(err)
	}
	if err := json.Unmarshal([]byte(repJSON), &dp.Posture); err != nil {
		return dp, fmt.Errorf("store: unmarshal posture report: %w", err)
	}
	if err := json.Unmarshal([]byte(failJSON), &dp.Failing); err != nil {
		return dp, fmt.Errorf("store: unmarshal posture failing: %w", err)
	}
	if dp.Failing == nil {
		dp.Failing = []string{}
	}
	dp.ReportedAt = time.Unix(reportedAt, 0).UTC()
	return dp, nil
}
