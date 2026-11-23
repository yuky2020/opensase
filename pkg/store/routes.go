package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
)

var (
	// ErrRouteOverlap is returned when a CIDR overlaps a CIDR of another device in any tenant.
	ErrRouteOverlap = errors.New("store: route overlap")
	// ErrInvalidRoute is returned when a CIDR is outside allowed IPv4 private ranges or has an invalid prefix length.
	ErrInvalidRoute = errors.New("store: invalid route")
)

var (
	rfc1918_10  = netip.MustParsePrefix("10.0.0.0/8")
	rfc1918_172 = netip.MustParsePrefix("172.16.0.0/12")
	rfc1918_192 = netip.MustParsePrefix("192.168.0.0/16")
	cgnat100    = netip.MustParsePrefix("100.64.0.0/10")
)

// validateRoute checks that p is an IPv4 prefix within private ranges (10/8, 172.16/12, 192.168/16)
// with prefix length 16..32, and never 100.64.0.0/10.
func validateRoute(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return fmt.Errorf("%w: must be a valid IPv4 prefix", ErrInvalidRoute)
	}
	bits := p.Bits()
	if bits < 16 || bits > 32 {
		return fmt.Errorf("%w: prefix length %d must be between 16 and 32", ErrInvalidRoute, bits)
	}
	addr := p.Addr()
	if cgnat100.Contains(addr) {
		return fmt.Errorf("%w: 100.64.0.0/10 is reserved for tunnel addresses", ErrInvalidRoute)
	}
	if !rfc1918_10.Contains(addr) && !rfc1918_172.Contains(addr) && !rfc1918_192.Contains(addr) {
		return fmt.Errorf("%w: %s is not in IPv4 private ranges (10/8, 172.16/12, 192.168/16)", ErrInvalidRoute, p)
	}
	return nil
}

func normalizeAndCheckInternalOverlap(cidrs []netip.Prefix) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return []netip.Prefix{}, nil
	}
	seen := make(map[netip.Prefix]bool, len(cidrs))
	var unique []netip.Prefix
	for _, c := range cidrs {
		c = c.Masked()
		if err := validateRoute(c); err != nil {
			return nil, err
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		unique = append(unique, c)
	}
	for i := 0; i < len(unique); i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[i].Overlaps(unique[j]) {
				return nil, fmt.Errorf("%w: %s overlaps with %s", ErrRouteOverlap, unique[i], unique[j])
			}
		}
	}
	return unique, nil
}

// SetDeviceRoutes replaces the authorised CIDRs for deviceID of tenantID in one transaction.
// It refuses any CIDR that overlaps a CIDR of ANOTHER device in ANY tenant with ErrRouteOverlap.
// Only IPv4 private ranges (10/8, 172.16/12, 192.168/16) with prefix length 16..32 are accepted.
func (s *Store) SetDeviceRoutes(ctx context.Context, tenantID, deviceID string, cidrs []netip.Prefix) error {
	norm, err := normalizeAndCheckInternalOverlap(cidrs)
	if err != nil {
		return err
	}

	return s.tx(ctx, func(tx *sql.Tx) error {
		var rowTenant string
		err := tx.QueryRowContext(ctx, `SELECT tenant_id FROM devices WHERE id = ?`, deviceID).Scan(&rowTenant)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return mapErr(err)
		}
		if rowTenant != tenantID {
			return ErrNotFound
		}

		if len(norm) > 0 {
			rows, err := tx.QueryContext(ctx, `SELECT device_id, cidr FROM device_routes WHERE device_id != ?`, deviceID)
			if err != nil {
				return mapErr(err)
			}
			defer rows.Close()

			for rows.Next() {
				var otherDev, otherCIDR string
				if err := rows.Scan(&otherDev, &otherCIDR); err != nil {
					return mapErr(err)
				}
				otherP, err := netip.ParsePrefix(otherCIDR)
				if err != nil {
					continue
				}
				for _, p := range norm {
					if p.Overlaps(otherP) {
						return fmt.Errorf("%w: %s overlaps %s of device %s", ErrRouteOverlap, p, otherCIDR, otherDev)
					}
				}
			}
			if err := rows.Err(); err != nil {
				return mapErr(err)
			}
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM device_routes WHERE device_id = ?`, deviceID); err != nil {
			return mapErr(err)
		}

		for _, p := range norm {
			if _, err := tx.ExecContext(ctx, `INSERT INTO device_routes(device_id, tenant_id, cidr) VALUES (?, ?, ?)`,
				deviceID, tenantID, p.String()); err != nil {
				return mapErr(err)
			}
		}
		return nil
	})
}

// DeviceRoutes returns the authorised CIDRs for deviceID.
// If the device does not exist, ErrNotFound is returned.
func (s *Store) DeviceRoutes(ctx context.Context, deviceID string) ([]netip.Prefix, error) {
	var x int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id = ?`, deviceID).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT cidr FROM device_routes WHERE device_id = ? ORDER BY cidr`, deviceID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := []netip.Prefix{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, mapErr(err)
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AllDeviceRoutes returns all authorised CIDRs grouped by device ID.
func (s *Store) AllDeviceRoutes(ctx context.Context) (map[string][]netip.Prefix, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, cidr FROM device_routes ORDER BY device_id, cidr`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := make(map[string][]netip.Prefix)
	for rows.Next() {
		var dev, c string
		if err := rows.Scan(&dev, &c); err != nil {
			return nil, mapErr(err)
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		out[dev] = append(out[dev], p)
	}
	return out, rows.Err()
}
