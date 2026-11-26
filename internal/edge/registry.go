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
	"github.com/yuky2020/opensase/pkg/tunneladdr"
)

// Tunnel address plan (pkg/tunneladdr). 100.64.0.1 and fd7a:5a5e::1 are the Edge itself.
var (
	TunnelPrefix4 = tunneladdr.Prefix4
	TunnelPrefix6 = tunneladdr.Prefix6
	EdgeIPv4      = tunneladdr.EdgeIPv4
	EdgeIPv6      = tunneladdr.EdgeIPv6
)

// maxOffset is the largest host offset usable in 100.64.0.0/10 (excluding broadcast).
const maxOffset = tunneladdr.MaxOffset

// device is the Edge's view of one enrolled device. Fields other than compiled are guarded
// by registry.mu.
type device struct {
	id       string
	tenantID string
	compiled atomic.Pointer[policy.Compiled]
	ztna     atomic.Pointer[ztnaView] // tenant + entitled private apps, swapped with compiled
	version  uint64

	offset uint32 // 0 = no tunnel address yet
	// cpOffset is the offset the Control Plane assigned (issue #70), the same on every Edge;
	// 0 if the Control Plane is older and the Edge picks one.
	cpOffset uint32
	dnsName  string // "<device>.<user>" in the tenant's internal zone (issue #62)
	ip4      netip.Addr
	ip6      netip.Addr

	routes []netip.Prefix

	wgPub     [32]byte
	hasPeer   bool
	sessionID string
	epoch     uint64
	// certNotAfter is the expiry of the device certificate that set up or last rotated the
	// session; the peer is removed once it passes (expireSessions).
	certNotAfter time.Time
	// sessionSerial is the serial of that certificate; staleSince is when the feed first
	// listed a different (renewed) serial. The peer is removed once that lasts longer than
	// the grace period (ST-10).
	sessionSerial string
	staleSince    time.Time
}

// ownsAddress reports whether ip is the device's tunnel address or falls within one of its routes.
func (d *device) ownsAddress(ip netip.Addr) bool {
	if (d.ip4.IsValid() && ip == d.ip4) || (d.ip6.IsValid() && ip == d.ip6) {
		return true
	}
	for _, r := range d.routes {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

type routeEntry struct {
	prefix netip.Prefix
	device *device
}

// registry holds devices known from the Control Plane peer feed and their tunnel state.
// Lookups by tunnel IP or routed prefix on the packet path are lock-free (copy-on-write index).
type registry struct {
	mu       sync.Mutex
	devices  map[string]*device
	used     map[uint32]bool
	reserved map[uint32]bool // offsets the Control Plane assigned (issue #70)
	next     uint32
	byIP     atomic.Pointer[map[netip.Addr]*device]
	byName   atomic.Pointer[map[string]*device] // tenant + "/" + dnsName (issue #62)
	routes   atomic.Pointer[[]routeEntry]
	serials  atomic.Pointer[map[string]string] // device ID -> current cert serial (ST-01)
}

func newRegistry() *registry {
	r := &registry{devices: map[string]*device{}, used: map[uint32]bool{}, next: 2}
	empty := map[netip.Addr]*device{}
	r.byIP.Store(&empty)
	noNames := map[string]*device{}
	r.byName.Store(&noNames)
	emptyRoutes := []routeEntry{}
	r.routes.Store(&emptyRoutes)
	noSerials := map[string]string{}
	r.serials.Store(&noSerials)
	return r
}

// byTunnelIP returns the device owning a tunnel address or routed subnet, or nil.
func (r *registry) byTunnelIP(ip netip.Addr) *device {
	u := ip.Unmap()
	if d := (*r.byIP.Load())[u]; d != nil {
		return d
	}
	if reList := r.routes.Load(); reList != nil {
		for _, re := range *reList {
			if re.prefix.Contains(u) {
				return re.device
			}
		}
	}
	return nil
}

// byDNSName returns the device of tenant with this internal DNS name, or nil (issue #62).
func (r *registry) byDNSName(tenant, name string) *device {
	return (*r.byName.Load())[tenant+"/"+name]
}

// serial returns the current certificate serial of a device from the last feed ("" if none).
func (r *registry) serial(id string) string { return (*r.serials.Load())[id] }

// get returns a device by ID (nil if unknown).
func (r *registry) get(id string) *device {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.devices[id]
}

// reindexLocked rebuilds the IP index and route table. Caller holds mu.
func (r *registry) reindexLocked() {
	m := make(map[netip.Addr]*device, 2*len(r.devices))
	names := make(map[string]*device, len(r.devices))
	var routes []routeEntry
	for _, d := range r.devices {
		if d.dnsName != "" {
			names[d.tenantID+"/"+d.dnsName] = d
		}
		if d.offset != 0 {
			m[d.ip4], m[d.ip6] = d, d
		}
		for _, rt := range d.routes {
			routes = append(routes, routeEntry{prefix: rt, device: d})
		}
	}
	r.byIP.Store(&m)
	r.byName.Store(&names)
	r.routes.Store(&routes)
}

// placeLocked moves d to its Control Plane offset before a new session (epoch 0), so the
// device gets the same tunnel addresses on every Edge (issue #70). Rotations never move a
// live session. If another device holds that offset (assigned locally before the Control
// Plane offered one), d keeps or gets a local offset. Caller holds mu.
func (r *registry) placeLocked(d *device) {
	want := d.cpOffset
	if want == 0 || d.offset == want || r.used[want] {
		return
	}
	if d.offset != 0 {
		delete(r.used, d.offset)
	}
	r.used[want] = true
	d.offset = want
	d.ip4, d.ip6 = addrAt(want)
	r.reindexLocked()
}

// allocateLocked assigns a tunnel address to d if it has none: its Control Plane offset if
// free, else the next free local one. Caller holds mu.
func (r *registry) allocateLocked(d *device) error {
	if d.offset != 0 {
		return nil
	}
	if d.cpOffset != 0 && !r.used[d.cpOffset] {
		r.placeLocked(d)
		return nil
	}
	for range maxOffset {
		off := r.next
		r.next++
		if r.next > maxOffset {
			r.next = 2
		}
		if r.used[off] || r.reservedLocked(off) {
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

// reservedLocked reports whether the Control Plane assigned off to some device, so a local
// allocation does not take it. Caller holds mu.
func (r *registry) reservedLocked(off uint32) bool {
	if r.reserved == nil {
		return false
	}
	return r.reserved[off]
}

// addrAt returns the IPv4 and IPv6 tunnel addresses with host offset off.
func addrAt(off uint32) (netip.Addr, netip.Addr) { return tunneladdr.AddrAt(off) }

// syncResult describes what changed in a peer feed sync.
type syncResult struct {
	removed       []*device // devices gone from the feed (revoked or deleted); their state is reset
	updated       int
	invalid       int
	routesUpdated []*device // devices whose routes changed
}

// sync applies the Control Plane peer feed: verifies and compiles new snapshots, adds new
// devices and removes devices missing from the feed. Removed devices keep their struct (the
// caller tears down their WireGuard peer) but lose their address.
func (r *registry) sync(peers api.EdgePeers, keys map[string]ed25519.PublicKey) syncResult {
	type compiled struct {
		snap *policy.Snapshot
		c    *policy.Compiled
	}
	serials := make(map[string]string, len(peers.Devices))
	for _, p := range peers.Devices {
		serials[p.DeviceID] = p.CertSerial
	}
	r.serials.Store(&serials)
	reserved := make(map[uint32]bool, len(peers.Devices))
	for _, p := range peers.Devices {
		if p.TunnelOffset != 0 {
			reserved[p.TunnelOffset] = true
		}
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
	r.reserved = reserved
	routesChanged := false
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
	for i := range peers.Devices {
		p := &peers.Devices[i]
		d := r.devices[p.DeviceID]
		if d == nil {
			continue
		}
		if d.dnsName != p.DNSName {
			d.dnsName = p.DNSName
			routesChanged = true // rebuilds the name index too
		}
		if p.TunnelOffset != 0 && tunneladdr.Usable(p.TunnelOffset) {
			d.cpOffset = p.TunnelOffset
		} else {
			d.cpOffset = 0
		}
		newRoutes := parseRoutes(p.Routes)
		if !routesEqual(d.routes, newRoutes) {
			d.routes = newRoutes
			res.routesUpdated = append(res.routesUpdated, d)
			routesChanged = true
		}
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
	if len(res.removed) > 0 || routesChanged {
		r.reindexLocked()
	}
	return res
}

func parseRoutes(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil && p.IsValid() {
			out = append(out, p.Masked())
		}
	}
	return out
}

func routesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
	c := &device{
		id:       d.id,
		tenantID: d.tenantID,
		offset:   d.offset,
		ip4:      d.ip4,
		ip6:      d.ip6,
		wgPub:    d.wgPub,
		hasPeer:  d.hasPeer,
		routes:   append([]netip.Prefix(nil), d.routes...),
	}
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
