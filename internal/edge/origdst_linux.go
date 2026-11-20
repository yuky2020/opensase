//go:build linux

package edge

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// soOriginalDst is SO_ORIGINAL_DST from <linux/netfilter_ipv4.h>.
const soOriginalDst = 80

// originalDst returns the pre-REDIRECT IPv4 destination of an accepted connection
// (netfilter conntrack, getsockopt(SOL_IP, SO_ORIGINAL_DST)). The kernel fills a
// struct sockaddr_in, which fits in the 16 bytes of IPv6Mreq.Multiaddr.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var mreq *syscall.IPv6Mreq
	var serr error
	if err := rc.Control(func(fd uintptr) {
		mreq, serr = syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, serr
	}
	raw := mreq.Multiaddr
	if family := binary.NativeEndian.Uint16(raw[0:2]); family != syscall.AF_INET {
		return netip.AddrPort{}, errors.New("edge: original destination is not IPv4")
	}
	port := uint16(raw[2])<<8 | uint16(raw[3])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[4:8])), port), nil
}
