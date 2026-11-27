//go:build !linux

package edge

func checkIPForward() error {
	return nil
}

func checkIPv6Forward() error {
	return nil
}
