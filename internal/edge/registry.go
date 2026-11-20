// Package edge implements the OpenSASE Edge: the PQ session-setup channel
// (ADR-0002), the WireGuard data plane with per-device cloud-side policy enforcement, the
// policy-aware DNS resolver, and flow reporting to the Control Plane.
package edge

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Tunnel address plan. 100.64.0.1 and fd7a:5a5e::1 are the Edge itself.
var (
	TunnelPrefix4 = netip.MustParsePrefix("100.64.0.0/10")
	TunnelPrefix6 = netip.MustParsePrefix("fd7a:5a5e::/64")
	EdgeIPv4      = netip.MustParseAddr("100.64.0.1")
	EdgeIPv6      = netip.MustParseAddr("fd7a:5a5e::1")
)

// maxOffset is the largest host offset usable in 100.64.0.0/10 (excluding broadcast).
const maxOffset = 1<<22 - 2

// device is the Edge's view of one enrolled device. Fields other than compiled are guarded
// by registry.mu.
type device struct {
	id       string
	tenantID string
	compiled atomic.Pointer[policy.Compiled]
	ztna     atomic.Pointer[ztnaView] // tenant + entitled private apps, swapped with compiled
	version  uint64

	offset uint32 // 0 = no tunnel address yet
	ip4    netip.Addr
	ip6    netip.Addr

	wgPub     [32]byte
	hasPeer   bool
	sessionID string
	epoch     uint64
	// certNotAfter is the expiry of the device certificate that set up or last rotated the
	// session; the peer is removed once it passes (expireSessions).
	certNotAfter time.Time
}

// registry holds devices known from the Control Plane peer feed and their tunnel state.
// Lookups by tunnel IP on the packet path are lock-free (copy-on-write index).
type registry struct {
	mu      sync.Mutex
	devices map[string]*device
	used    map[uint32]bool
	next    uint32
	byIP    atomic.Pointer[map[netip.Addr]*device]
}

func newRegistry() *registry {
	r := &registry{devices: map[string]*device{}, used: map[uint32]bool{}, next: 2}
	empty := map[netip.Addr]*device{}
	r.byIP.Store(&empty)
	return r
}

// byTunnelIP returns the device owning a tunnel address, or nil.
func (r *registry) byTunnelIP(ip netip.Addr) *device {
	return (*r.byIP.Load())[ip.Unmap()]
}

// get returns a device by ID (nil if unknown).
func (r *registry) get(id string) *device {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.devices[id]
}

// reindexLocked rebuilds the IP index. Caller holds mu.
func (r *registry) reindexLocked() {
	m := make(map[netip.Addr]*device, 2*len(r.devices))
	for _, d := range r.devices {
		if d.offset != 0 {
			m[d.ip4], m[d.ip6] = d, d
		}
	}
	r.byIP.Store(&m)
}

// allocateLocked assigns a tunnel address to d if it has none. Caller holds mu.
func (r *registry) allocateLocked(d *device) error {
	if d.offset != 0 {
		return nil
	}
	for range maxOffset {
		off := r.next
		r.next++
		if r.next > maxOffset {
			r.next = 2
		}
		if r.used[off] {
			continue
		}
		if a4, _ := addrAt(off); SyntheticPrefix.Contains(a4) {
			continue // reserved for PrivateApp names (ADR-0013)
		}
		r.used[off] = true
		d.offset = off
		d.ip4, d.ip6 = addrAt(off)
		r.reindexLocked()
		return nil
	}
	return errors.New("edge: tunnel address pool exhausted")
}

// addrAt returns the IPv4 and IPv6 tunnel addresses with host offset off.
func addrAt(off uint32) (netip.Addr, netip.Addr) {
	b4 := TunnelPrefix4.Addr().As4()
	base := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	v := base + off
	ip4 := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	b6 := TunnelPrefix6.Addr().As16()
	b6[12], b6[13], b6[14], b6[15] = byte(off>>24), byte(off>>16), byte(off>>8), byte(off)
	return ip4, netip.AddrFrom16(b6)
}

// syncResult describes what changed in a peer feed sync.
type syncResult struct {
	removed []*device // devices gone from the feed (revoked or deleted); their state is reset
	updated int
	invalid int
}

// sync applies the Control Plane peer feed: verifies and compiles new snapshots, adds new
// devices and removes devices missing from the feed. Removed devices keep their struct (the
// caller tears down their WireGuard peer) but lose their address.
func (r *registry) sync(peers api.EdgePeers, keys map[string]ed25519.PublicKey) syncResult {
	type compiled struct {
		snap *policy.Snapshot
		c    *policy.Compiled
	}
	// Verify and compile outside the lock.
	fresh := make(map[string]compiled, len(peers.Devices))
	var res syncResult
	for i := range peers.Devices {
		p := &peers.Devices[i]
		if old := r.get(p.DeviceID); old != nil && old.compiled.Load() != nil {
			// Skip work if the version did not change; the payload is re-verified only on change.
			if v := envelopeVersionHint(old); v != 0 && sameVersion(&p.Snapshot, v) {
				fresh[p.DeviceID] = compiled{}
				continue
			}
		}
		snap, err := policy.Verify(&p.Snapshot, keys)
		if err == nil && (snap.DeviceID != p.DeviceID || snap.TenantID != p.TenantID) {
			err = fmt.Errorf("snapshot subject %s/%s does not match peer %s/%s", snap.TenantID, snap.DeviceID, p.TenantID, p.DeviceID)
		}
		var c *policy.Compiled
		if err == nil {
			c, err = policy.Compile(snap)
		}
		if err != nil {
			res.invalid++
			continue
		}
		fresh[p.DeviceID] = compiled{snap, c}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for id, fc := range fresh {
		d, ok := r.devices[id]
		if !ok {
			d = &device{id: id}
			r.devices[id] = d
		}
		if fc.c == nil {
			continue // unchanged
		}
		if d.version >= fc.snap.Version && d.compiled.Load() != nil {
			continue // never go backwards
		}
		d.tenantID = fc.snap.TenantID
		d.version = fc.snap.Version
		d.ztna.Store(newZTNAView(fc.snap.TenantID, fc.c))
		d.compiled.Store(fc.c)
		res.updated++
	}
	for id, d := range r.devices {
		if _, ok := fresh[id]; ok {
			continue
		}
		// Invalid snapshots count as present: keep enforcing the last good one.
		if r.inFeed(peers, id) {
			continue
		}
		delete(r.devices, id)
		if d.offset != 0 {
			delete(r.used, d.offset)
		}
		res.removed = append(res.removed, cloneDevice(d))
		d.offset, d.hasPeer = 0, false
	}
	if len(res.removed) > 0 {
		r.reindexLocked()
	}
	return res
}

func (r *registry) inFeed(peers api.EdgePeers, id string) bool {
	for i := range peers.Devices {
		if peers.Devices[i].DeviceID == id {
			return true
		}
	}
	return false
}

// cloneDevice copies the fields needed to tear down a removed device.
func cloneDevice(d *device) *device {
	c := &device{id: d.id, tenantID: d.tenantID, offset: d.offset, ip4: d.ip4, ip6: d.ip6, wgPub: d.wgPub, hasPeer: d.hasPeer}
	return c
}

func envelopeVersionHint(d *device) uint64 {
	if c := d.compiled.Load(); c != nil {
		return c.Version()
	}
	return 0
}

// sameVersion cheaply checks the version inside an envelope payload without verifying it.
// It is only used to skip re-verification of an unchanged snapshot that was verified before.
func sameVersion(e *policy.Envelope, v uint64) bool {
	var hdr struct {
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal(e.Payload, &hdr); err != nil {
		return false
	}
	return hdr.Version == v
}
