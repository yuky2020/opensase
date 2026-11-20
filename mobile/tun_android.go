//go:build android

package mobile

import "golang.zx2c4.com/wireguard/tun"

// openTUN wraps the VpnService TUN fd. The fd must be detached on the Kotlin side
// (ParcelFileDescriptor.detachFd): the Go core owns and closes it.
func openTUN(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
