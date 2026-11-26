package store

import "testing"

func TestRebind(t *testing.T) {
	tests := []struct{ in, want string }{
		{`SELECT 1`, `SELECT 1`},
		{`SELECT a FROM t WHERE x = ? AND y = ?`, `SELECT a FROM t WHERE x = $1 AND y = $2`},
		{`SELECT '?' , "a?b" FROM t WHERE x = ?`, `SELECT '?' , "a?b" FROM t WHERE x = $1`},
		{`INSERT INTO t(a, b) VALUES (?, 'it''s ?') RETURNING id`, `INSERT INTO t(a, b) VALUES ($1, 'it''s ?') RETURNING id`},
	}
	for _, tc := range tests {
		if got := rebind(true, tc.in); got != tc.want {
			t.Errorf("rebind(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := rebind(false, tc.in); got != tc.in {
			t.Errorf("SQLite must not rewrite %q", tc.in)
		}
	}
}
