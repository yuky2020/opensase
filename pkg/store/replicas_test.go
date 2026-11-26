package store

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// pgPair opens two stores on the same PostgreSQL schema, as two Control Plane replicas.
func pgPair(t *testing.T) (*Store, *Store) {
	t.Helper()
	base := os.Getenv("OPENSASE_TEST_POSTGRES")
	if base == "" {
		t.Skip("OPENSASE_TEST_POSTGRES not set")
	}
	dsn := testSchema(t, base)
	ctx := context.Background()
	var out [2]*Store
	for i := range out {
		s, err := Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		out[i] = s
	}
	return out[0], out[1]
}

func TestSQLiteIsAlwaysLeader(t *testing.T) {
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.IsLeader() || s.Postgres() {
		t.Fatal("SQLite store must be the leader")
	}
	if err := s.Publish(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

// TestLeadershipFailover covers ADR-0033: one replica leads; when it stops, the other takes
// over.
func TestLeadershipFailover(t *testing.T) {
	a, b := pgPair(t)
	ctxA, stopA := context.WithCancel(context.Background())
	defer stopA()
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	go a.KeepLeadership(ctxA, nil)
	waitFor(t, a.IsLeader, "a leads")
	go b.KeepLeadership(ctxB, nil)
	time.Sleep(200 * time.Millisecond)
	if b.IsLeader() {
		t.Fatal("two leaders")
	}
	stopA()
	waitFor(t, func() bool { return !a.IsLeader() }, "a steps down")
	// b retries every leaderRetry.
	deadline := time.Now().Add(leaderRetry + 5*time.Second)
	for !b.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("b did not take over")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestPublishSubscribe covers ADR-0033: a key published by one replica reaches the other.
func TestPublishSubscribe(t *testing.T) {
	a, b := pgPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 4)
	var resyncs atomic.Int32
	go b.Subscribe(ctx, func(k string) { got <- k }, func() { resyncs.Add(1) })
	waitFor(t, func() bool { return resyncs.Load() == 1 }, "listening")
	if err := a.Publish(ctx, "device-1"); err != nil {
		t.Fatal(err)
	}
	select {
	case k := <-got:
		if k != "device-1" {
			t.Fatalf("got %q", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

// TestCopySQLiteToPostgres covers the migration path of ADR-0033.
func TestCopySQLiteToPostgres(t *testing.T) {
	base := os.Getenv("OPENSASE_TEST_POSTGRES")
	if base == "" {
		t.Skip("OPENSASE_TEST_POSTGRES not set")
	}
	ctx := context.Background()
	src, err := Open(ctx, t.TempDir()+"/cp.db")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	seed(t, src)
	for i := range 3 {
		if err := src.AddAudit(ctx, AuditEntry{At: time.Now(), Actor: "super", Method: "POST", Path: "/x", Status: 200 + i}); err != nil {
			t.Fatal(err)
		}
	}
	dst, err := Open(ctx, testSchema(t, base))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	counts, err := src.CopyTo(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, c := range counts {
		total += c.Rows
	}
	if total == 0 {
		t.Fatal("nothing copied")
	}
	// Identity continues after the copied ids.
	if err := dst.AddAudit(ctx, AuditEntry{At: time.Now(), Actor: "super", Method: "POST", Path: "/y", Status: 201}); err != nil {
		t.Fatal(err)
	}
	if v, err := dst.VerifyAudit(ctx); err != nil || v.BadID != 0 || v.Entries != 4 {
		t.Fatalf("verify %+v %v", v, err)
	}
	if _, err := src.CopyTo(ctx, dst); err == nil {
		t.Fatal("copy into a non-empty database must fail")
	}
}
