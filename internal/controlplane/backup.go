package controlplane

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// backupLoop writes scheduled backups (issue #67). It runs on the leader only.
func (s *Server) backupLoop(ctx context.Context) {
	if s.cfg.BackupDir == "" {
		return
	}
	if s.cfg.Store.Postgres() {
		s.log.Warn("scheduled backups are for SQLite; back up PostgreSQL with pg_dump", "backupDir", s.cfg.BackupDir)
		return
	}
	every := s.cfg.BackupEvery
	if every <= 0 {
		every = 24 * time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if s.cfg.Store.IsLeader() {
			if err := s.backupOnce(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("backup failed", "dir", s.cfg.BackupDir, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// backupOnce writes controlplane-<time>.db and, with PKIDir set, pki-<time>.tar.gz, then
// prunes older backups.
func (s *Server) backupOnce(ctx context.Context) error {
	if err := os.MkdirAll(s.cfg.BackupDir, 0o700); err != nil {
		return err
	}
	stamp := s.now().UTC().Format("20060102T150405Z")
	db := filepath.Join(s.cfg.BackupDir, "controlplane-"+stamp+".db")
	if err := s.cfg.Store.Backup(ctx, db); err != nil {
		return err
	}
	if s.cfg.PKIDir != "" {
		if err := archiveDir(s.cfg.PKIDir, filepath.Join(s.cfg.BackupDir, "pki-"+stamp+".tar.gz")); err != nil {
			return fmt.Errorf("pki archive: %w", err)
		}
	}
	keep := s.cfg.BackupKeep
	if keep <= 0 {
		keep = 7
	}
	for _, prefix := range []string{"controlplane-", "pki-"} {
		if err := prune(s.cfg.BackupDir, prefix, keep); err != nil {
			return err
		}
	}
	s.log.Info("backup written", "file", db)
	return nil
}

// prune keeps the newest keep files whose name starts with prefix (names sort by time).
func prune(dir, prefix string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), prefix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			return err
		}
		names = names[1:]
	}
	return nil
}

// archiveDir writes the regular files under dir to a gzip tar at out (mode 0600: it holds
// private keys).
func archiveDir(dir, out string) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen backup directory
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || strings.HasSuffix(p, ".tmp") {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		src, err := os.Open(p) //nolint:gosec // G304: walking the operator's PKI directory
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, src)
		_ = src.Close()
		return err
	})
	for _, c := range []io.Closer{tw, gz, f} {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		_ = os.Remove(out)
	}
	return err
}
