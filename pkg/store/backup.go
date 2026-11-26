package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Backup writes a consistent copy of a SQLite database to path while the Control Plane runs
// (VACUUM INTO, issue #67). path must not exist; the file is created with mode 0600 because
// it holds every tenant's data. PostgreSQL installs back up with the database's own tools.
func (s *Store) Backup(ctx context.Context, path string) error {
	if s.db.pg {
		return errors.New("store: online backup is for SQLite; back up PostgreSQL with pg_dump")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("store: backup %s already exists", path)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return os.Chmod(path, 0o600)
}

// Restore checks that the SQLite backup at from opens, migrates and has a valid audit chain,
// then copies it to to (which must not exist: move the old database aside first). The
// Control Plane must be stopped.
func Restore(ctx context.Context, from, to string) error {
	if _, err := os.Stat(to); err == nil {
		return fmt.Errorf("store: %s exists; move it aside before restoring", to)
	}
	tmp := filepath.Join(filepath.Dir(to), "."+filepath.Base(to)+".restore")
	_ = os.Remove(tmp)
	if err := copyFile(from, tmp); err != nil {
		return err
	}
	s, err := Open(ctx, tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: backup does not open: %w", err)
	}
	v, err := s.VerifyAudit(ctx)
	_ = s.Close()
	if err == nil && v.BadID != 0 {
		err = fmt.Errorf("audit chain broken at entry %d: %s", v.BadID, v.Reason)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: backup check: %w", err)
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		_ = os.Remove(tmp + sfx)
	}
	return os.Rename(tmp, to)
}

func copyFile(from, to string) error {
	in, err := os.Open(from) //nolint:gosec // G304: operator-chosen backup file
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen restore target
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
