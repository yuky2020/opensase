package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

// Connector is a row of the connectors table (ADR-0013).
type Connector struct {
	ID       string
	TenantID string
	Name     string
	Group    string
	// CertSerial is the serial of the current certificate; "" until the connector enrolls.
	CertSerial string
	// PrevCertSerial is the serial replaced by the last renewal; it is valid only for
	// retrying POST /v1/connector/renew.
	PrevCertSerial string
	Revoked        bool
	CreatedAt      time.Time
	LastSeen       time.Time // zero if no Edge ever reported it
}

// Enrolled reports whether the connector has been issued a certificate.
func (c Connector) Enrolled() bool { return c.CertSerial != "" }

const connectorCols = `id, tenant_id, name, grp, cert_serial, prev_cert_serial, revoked, created_at, last_seen`

func scanConnector(sc interface{ Scan(...any) error }) (Connector, error) {
	var c Connector
	var created, seen int64
	err := sc.Scan(&c.ID, &c.TenantID, &c.Name, &c.Group, &c.CertSerial, &c.PrevCertSerial, &c.Revoked, &created, &seen)
	c.CreatedAt = time.Unix(created, 0)
	if seen > 0 {
		c.LastSeen = time.Unix(seen, 0)
	}
	return c, err
}

// CreateConnector inserts a connector of an existing tenant together with the hash of its
// single-use provisioning key, valid until keyExpires. ErrNotFound if the tenant does not
// exist, ErrConflict if the ID is taken.
func (s *Store) CreateConnector(ctx context.Context, c Connector, keyHash []byte, keyExpires time.Time) (Connector, error) {
	if len(keyHash) != 32 {
		return Connector{}, errors.New("store: provisioning key hash must be 32 bytes")
	}
	now := time.Now()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO connectors(id, tenant_id, name, grp, created_at) VALUES (?, ?, ?, ?, ?)`,
			c.ID, c.TenantID, c.Name, c.Group, now.Unix()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO connector_provisioning_keys(key_hash, tenant_id, connector_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
			keyHash, c.TenantID, c.ID, keyExpires.Unix(), now.Unix())
		return err
	})
	if err != nil {
		return Connector{}, mapErr(err)
	}
	c.CertSerial, c.PrevCertSerial, c.Revoked = "", "", false
	c.CreatedAt, c.LastSeen = time.Unix(now.Unix(), 0), time.Time{}
	return c, nil
}

// GetConnector returns a connector by ID.
func (s *Store) GetConnector(ctx context.Context, id string) (Connector, error) {
	c, err := scanConnector(s.db.QueryRowContext(ctx, `SELECT `+connectorCols+` FROM connectors WHERE id = ?`, id))
	return c, mapErr(err)
}

// ConnectorFilter selects connectors in ListConnectors. An empty TenantID matches every
// tenant. EnrolledOnly drops connectors that never enrolled.
type ConnectorFilter struct {
	TenantID       string
	IncludeRevoked bool
	EnrolledOnly   bool
}

// ListConnectors lists connectors matching f, ordered by creation.
func (s *Store) ListConnectors(ctx context.Context, f ConnectorFilter) ([]Connector, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+connectorCols+` FROM connectors
		WHERE (? = '' OR tenant_id = ?) AND (? OR revoked = 0) AND (NOT ? OR cert_serial != '') ORDER BY created_at, rowid`,
		f.TenantID, f.TenantID, f.IncludeRevoked, f.EnrolledOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Connector{}
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeConnector revokes a connector of a tenant and deletes its unused provisioning keys.
// Revocation is permanent.
func (s *Store) RevokeConnector(ctx context.Context, tenantID, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE connectors SET revoked = 1 WHERE tenant_id = ? AND id = ?`, tenantID, id)
		if err := affected(res, err); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM connector_provisioning_keys WHERE connector_id = ?`, id)
		return err
	})
}

// EnrollConnector atomically consumes the single-use connector provisioning key with the given
// hash and stores the certificate serial returned by sign (called inside the transaction with
// the key's connector). The key must be unused and unexpired at now, and the connector must
// be neither revoked nor already enrolled; otherwise ErrKeyInvalid. If sign fails, the key is
// not consumed.
func (s *Store) EnrollConnector(ctx context.Context, hash []byte, now time.Time, sign func(Connector) (serial string, err error)) (Connector, error) {
	var c Connector
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx, `UPDATE connector_provisioning_keys SET used = 1
			WHERE key_hash = ? AND used = 0 AND expires_at > ? RETURNING connector_id`, hash, now.Unix()).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrKeyInvalid
		}
		if err != nil {
			return err
		}
		c, err = scanConnector(tx.QueryRowContext(ctx, `SELECT `+connectorCols+` FROM connectors WHERE id = ?`, id))
		if err != nil {
			return err
		}
		if c.Revoked || c.Enrolled() {
			return ErrKeyInvalid
		}
		serial, err := sign(c)
		if err != nil {
			return err
		}
		if serial == "" {
			return errors.New("store: empty certificate serial")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE connectors SET cert_serial = ? WHERE id = ?`, serial, id); err != nil {
			return err
		}
		c.CertSerial = serial
		return nil
	})
	if errors.Is(err, ErrKeyInvalid) {
		return Connector{}, err
	}
	return c, mapErr(err)
}

// RenewConnectorCert is RenewDeviceCert for connectors, with the same rules for the
// presented serial (current, or previous to retry after a lost response).
func (s *Store) RenewConnectorCert(ctx context.Context, connectorID, presented, newSerial string) error {
	return s.renewCert(ctx, "connectors", connectorID, presented, newSerial)
}

// TouchConnectors sets last_seen to now for the given non-revoked connectors. Unknown IDs are
// ignored.
func (s *Store) TouchConnectors(ctx context.Context, ids []string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	return mapErr(s.tx(ctx, func(tx *sql.Tx) error {
		st, err := tx.PrepareContext(ctx, `UPDATE connectors SET last_seen = ? WHERE id = ? AND revoked = 0`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, id := range ids {
			if _, err := st.ExecContext(ctx, now.Unix(), id); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ConnectorConfigVersion returns the config version of a connector for a config whose content
// hashes to hash: if hash differs from the one recorded, the version is incremented and hash
// recorded, atomically. The version therefore increases on every change of the served config
// and stays put while it does not change.
func (s *Store) ConnectorConfigVersion(ctx context.Context, id string, hash []byte) (uint64, error) {
	var v int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var old []byte
		if err := tx.QueryRowContext(ctx, `SELECT config_version, config_hash FROM connectors WHERE id = ?`, id).Scan(&v, &old); err != nil {
			return err
		}
		if bytes.Equal(old, hash) && v > 0 {
			return nil
		}
		return tx.QueryRowContext(ctx, `UPDATE connectors SET config_version = config_version + 1, config_hash = ? WHERE id = ? RETURNING config_version`,
			hash, id).Scan(&v)
	})
	return uint64(v), mapErr(err)
}
