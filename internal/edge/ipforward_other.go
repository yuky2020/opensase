//go:build !linux

package edge

func checkIPForward() error {
	return nil
}
