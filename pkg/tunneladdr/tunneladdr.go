// Package tunneladdr is the tunnel address plan shared by the Control Plane, which gives each
// device a stable host offset, and the Edges, which turn the offset into the device's tunnel
// addresses (issue #70). A device keeps its addresses on every Edge, so a failover does not
// change them.
package tunneladdr

import (
	"net/netip"

	"github.com/yuky2020/opensase/pkg/policy"
)

// Tunnel prefixes. Offset 1 (100.64.0.1, fd7a:5a5e::1) is the Edge itself.
var (
	Prefix4   = netip.MustParsePrefix("100.64.0.0/10")
	Prefix6   = netip.MustParsePrefix("fd7a:5a5e::/64")
	EdgeIPv4  = netip.MustParseAddr("100.64.0.1")
	EdgeIPv6  = netip.MustParseAddr("fd7a:5a5e::1")
	synthetic = netip.MustParsePrefix(policy.SyntheticPrefix)
)

// MinOffset and MaxOffset bound the device host offsets (MaxOffset excludes the broadcast
// address of Prefix4).
const (
	MinOffset = 2
	MaxOffset = 1<<22 - 2
)

// AddrAt returns the IPv4 and IPv6 tunnel addresses with host offset off.
func AddrAt(off uint32) (netip.Addr, netip.Addr) {
	b4 := Prefix4.Addr().As4()
	base := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	v := base + off
	ip4 := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	b6 := Prefix6.Addr().As16()
	b6[12], b6[13], b6[14], b6[15] = byte(off>>24), byte(off>>16), byte(off>>8), byte(off)
	return ip4, netip.AddrFrom16(b6)
}

// Usable reports whether off may be given to a device: inside the pool and outside the
// Edge-local range reserved for private app names.
func Usable(off uint32) bool {
	if off < MinOffset || off > MaxOffset {
		return false
	}
	a4, _ := AddrAt(off)
	return !synthetic.Contains(a4)
}

// NextUsable returns the first usable offset >= off, or 0 if there is none.
func NextUsable(off uint32) uint32 {
	off = max(off, MinOffset)
	for off <= MaxOffset {
		if Usable(off) {
			return off
		}
		a4, _ := AddrAt(off)
		if synthetic.Contains(a4) {
			// Skip the whole reserved range at once.
			end := synthetic.Addr().As4()
			base := Prefix4.Addr().As4()
			span := uint32(1) << (32 - synthetic.Bits())
			start := (uint32(end[0])<<24 | uint32(end[1])<<16 | uint32(end[2])<<8 | uint32(end[3])) -
				(uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3]))
			off = start + span
			continue
		}
		off++
	}
	return 0
}
