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

func checkIPv6Forward() error {
	return checkIPv6ForwardFile("/proc/sys/net/ipv6/conf/all/forwarding")
}

func checkIPv6ForwardFile(path string) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: fixed /proc path, parameter only for tests
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		return errors.New("IPv6 forwarding is disabled in the Edge network namespace (net.ipv6.conf.all.forwarding=0): enable net.ipv6.conf.all.forwarding=1 to forward IPv6 tunnel traffic")
	}
	return nil
}
