package edge

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/yuky2020/opensase/pkg/policy"
)

type fakeIPT struct {
	mu    sync.Mutex
	calls []string
	fail  string // fail calls containing this
	rules map[string]bool
}

func (f *fakeIPT) run(_ context.Context, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := strings.Join(args, " ")
	f.calls = append(f.calls, c)
	if f.fail != "" && strings.Contains(c, f.fail) {
		return errors.New("permission denied")
	}
	if f.rules == nil {
		f.rules = map[string]bool{}
	}
	for _, op := range []string{" -A ", " -D ", " -C "} {
		if i := strings.Index(c, op); i >= 0 {
			key := c[i+len(op):]
			switch op {
			case " -A ":
				f.rules[key] = true
			case " -D ":
				if !f.rules[key] {
					return errors.New("no such rule")
				}
				delete(f.rules, key)
			case " -C ":
				if !f.rules[key] {
					return errors.New("no such rule")
				}
			}
		}
	}
	return nil
}

func (f *fakeIPT) chainRules() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for r := range f.rules {
		if strings.HasPrefix(r, inspectChain+" ") {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}

// TestInspectRedirect covers issue #22: only devices whose policy needs inspection are
// redirected, the chain follows policy changes, and the Edge falls back to redirecting
// everyone when it cannot manage the rules.
func TestInspectRedirect(t *testing.T) {
	fx := newFixtureCfg(t, func(c *Config) { c.InspectListen = "0.0.0.0:15002" })
	ipt := &fakeIPT{rules: map[string]bool{
		// The blanket rule of an older entrypoint.
		"PREROUTING -i wg0 ! -d 100.96.0.0/12 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 15002": true,
	}}
	fx.e.redir.ipt = ipt.run
	fx.web = policy.WebPolicy{Inspect: true}
	fx.setPeer("d1", 1)
	fx.web = policy.WebPolicy{}
	fx.setPeer("d2", 1)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"d1", "d2"} {
		d := fx.e.reg.get(id)
		fx.e.reg.mu.Lock()
		_ = fx.e.reg.allocateLocked(d)
		fx.e.reg.mu.Unlock()
	}
	if !fx.e.setupInspectRedirect(context.Background(), "wg0") {
		t.Fatal("setup failed")
	}
	if ipt.rules["PREROUTING -i wg0 ! -d 100.96.0.0/12 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 15002"] {
		t.Fatal("blanket rule left in place")
	}
	if !ipt.rules["PREROUTING -i wg0 ! -d 100.96.0.0/12 -p tcp -m multiport --dports 80,443 -j "+inspectChain] {
		t.Fatal("no jump to the chain")
	}
	fx.e.reconcileInspect(context.Background())
	d1 := fx.e.reg.get("d1").ip4.String()
	want := []string{inspectChain + " -s " + d1 + "/32 -p tcp -j REDIRECT --to-ports 15002"}
	if got := ipt.chainRules(); !slices.Equal(got, want) {
		t.Fatalf("chain %v want %v", got, want)
	}
	// d1 turns inspection off, d2 gets web rules (plain HTTP is proxied for it).
	fx.web = policy.WebPolicy{}
	fx.setPeer("d1", 2)
	fx.web = policy.WebPolicy{Rules: []policy.WebRule{{ID: "r", Domains: []string{"x.example"}, Action: policy.ActionBlock}}}
	fx.setPeer("d2", 2)
	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	d2 := fx.e.reg.get("d2").ip4.String()
	if got := ipt.chainRules(); !slices.Equal(got, []string{inspectChain + " -s " + d2 + "/32 -p tcp -j REDIRECT --to-ports 15002"}) {
		t.Fatalf("after policy change %v", got)
	}

	// No NET_ADMIN: setup reports false, the caller keeps redirecting everyone.
	fx2 := newFixtureCfg(t, func(c *Config) { c.InspectListen = "0.0.0.0:15002" })
	bad := &fakeIPT{fail: "-F " + inspectChain}
	fx2.e.redir.ipt = bad.run
	if fx2.e.setupInspectRedirect(context.Background(), "wg0") {
		t.Fatal("setup succeeded without permission")
	}
	fx2.e.reconcileInspect(context.Background()) // inactive: no calls
	for _, c := range bad.calls {
		if strings.Contains(c, "-s ") {
			t.Fatalf("per-device rule attempted while inactive: %s", c)
		}
	}
}
