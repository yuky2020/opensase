package controlplane

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store/storetest"
)

// TestTwoReplicas covers ADR-0033 on PostgreSQL: a device enrolled through replica A
// authenticates to replica B, and a policy change written on A wakes the device's long-poll
// held by B.
func TestTwoReplicas(t *testing.T) {
	dsn, ok := storetest.PostgresDSN(t)
	if !ok {
		t.Skip("OPENSASE_TEST_POSTGRES not set")
	}
	dir := t.TempDir()
	if err := pki.InitDir(dir, pki.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	a := newEnvAt(t, dir, dsn, nil)
	b := newEnvAt(t, dir, dsn, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listening := make(chan struct{}, 1)
	go b.s.cfg.Store.Subscribe(ctx, b.s.notify.notify, func() { b.s.notify.notifyAll(); listening <- struct{}{} })
	<-listening

	key := a.setupTenant(1)
	_, cert := a.enroll(key)
	// B learns the tenant CA created on A.
	if err := b.s.cfg.Authority.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	b.s.pool.Store(b.s.cfg.Authority.ClientCAPool())
	dev := b.client(&cert)
	resp, _ := b.do(dev, "GET", "/v1/snapshot", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("snapshot from replica B: %d", resp.StatusCode)
	}
	tag := resp.Header.Get("ETag")

	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", b.srv.URL+"/v1/snapshot?wait=30", nil)
		req.Header.Set("If-None-Match", tag)
		r, err := dev.Do(req)
		if err != nil {
			done <- 0
			return
		}
		r.Body.Close()
		done <- r.StatusCode
	}()
	time.Sleep(300 * time.Millisecond)
	p := examplePolicy()
	p.Rules = append(p.Rules, policy.Rule{ID: "late", Priority: 99, Action: policy.ActionBlock, Match: policy.Match{CIDRs: []string{"203.0.113.0/24"}}})
	a.adminDo("PUT", "/v1/admin/tenants/acme/policy", p, 204)
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("long-poll on B: %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("policy change on A did not wake the long-poll on B")
	}
}
