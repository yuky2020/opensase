//go:build linux && !android

package mobile

import "golang.zx2c4.com/wireguard/tun"

// openTUN wraps an already-configured TUN fd (desktop Linux; the headless client uses
// StartDevice with tun.CreateTUN instead).
func openTUN(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
