//go:build linux

package edge

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func checkIPForward() error {
	return checkIPForwardFile("/proc/sys/net/ipv4/ip_forward")
}

func checkIPForwardFile(path string) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: fixed /proc path, parameter only for tests
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		return errors.New("IPv4 forwarding is disabled in the Edge network namespace (net.ipv4.ip_forward=0): enable it (docker --sysctl net.ipv4.ip_forward=1, or the Kubernetes sysctl/init container) or tunnel traffic is dropped")
	}
	return nil
}
