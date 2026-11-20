//go:build !linux

package edge

import (
	"errors"
	"net"
	"net/netip"
)

// originalDst needs netfilter (Linux).
func originalDst(*net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("edge: SO_ORIGINAL_DST is only available on Linux")
}
