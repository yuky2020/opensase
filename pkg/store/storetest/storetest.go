// Package storetest gives tests a private PostgreSQL schema when OPENSASE_TEST_POSTGRES is
// set (ADR-0033).
package storetest

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
)

// PostgresDSN returns a URL for a fresh schema on the server named by OPENSASE_TEST_POSTGRES,
// dropped when the test ends, and false when the variable is not set.
func PostgresDSN(t testing.TB) (string, bool) {
	t.Helper()
	base := os.Getenv("OPENSASE_TEST_POSTGRES")
	if base == "" {
		return "", false
	}
	db, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	name := fmt.Sprintf("t%d", time.Now().UnixNano())
	if _, err := db.Exec(`CREATE SCHEMA ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, err := sql.Open("pgx", base); err == nil {
			_, _ = c.Exec(`DROP SCHEMA ` + name + ` CASCADE`)
			_ = c.Close()
		}
	})
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "search_path=" + name, true
}
