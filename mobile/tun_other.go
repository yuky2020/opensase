//go:build !linux

package mobile

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

func openTUN(_ int) (tun.Device, error) {
	return nil, errors.New("mobile: Start(fd) is only supported on Android and Linux; use StartDevice")
}
