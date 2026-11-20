package edge

import (
	"github.com/yuky2020/opensase/pkg/policy"
)

// ztnaView is the ZTNA part of a device snapshot (ADR-0013): its tenant and the compiled
// policy whose PrivateApps are the apps the user is entitled to. It is immutable and swapped
// atomically together with device.compiled.
type ztnaView struct {
	tenant string
	c      *policy.Compiled
}

func newZTNAView(tenant string, c *policy.Compiled) *ztnaView {
	return &ztnaView{tenant: tenant, c: c}
}

// app returns the entitled app whose Domains match name (name match only). The result shares
// memory with the compiled snapshot and must not be modified.
func (v *ztnaView) app(name string) (policy.PrivateApp, bool) {
	if v == nil || v.c == nil {
		return policy.PrivateApp{}, false
	}
	return v.c.PrivateApp(name)
}

// access returns the entitled app matching name whose Ports contain port (empty Ports means
// no access). The result must not be modified.
func (v *ztnaView) access(name string, port uint16) (policy.PrivateApp, bool) {
	if v == nil || v.c == nil {
		return policy.PrivateApp{}, false
	}
	return v.c.PrivateAppAccess(name, port)
}
