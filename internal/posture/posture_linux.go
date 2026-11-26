//go:build linux

package posture

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/yuky2020/opensase/pkg/api"
)

func collect() api.Posture {
	p := api.Posture{
		OS:            "linux",
		ClientVersion: clientVersion(),
	}

	// 1. OSVersion from /etc/os-release VERSION_ID, fallback to /proc/sys/kernel/osrelease
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		p.OSVersion = parseOSRelease(string(b))
	}
	if p.OSVersion == "" {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			p.OSVersion = strings.TrimSpace(string(b))
		}
	}

	// 2. DiskEncrypted
	p.DiskEncrypted = collectDiskEncrypted()

	// 3. ScreenLock, Firewall, Managed are left nil for Linux

	// 4. BootTime from /proc/stat btime
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		p.BootTime = parseBtime(string(b))
	}

	return p
}

func collectDiskEncrypted() *bool {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	mountSource := parseMountinfoRoot(string(b))
	if mountSource == "" || !strings.HasPrefix(mountSource, "/dev/") {
		return nil
	}

	devPath, err := filepath.EvalSymlinks(mountSource)
	if err != nil {
		devPath = mountSource
	}

	fi, err := os.Stat(devPath) //nolint:gosec // G703: path from /proc/self/mountinfo (kernel data), only stat-ed
	if err != nil {
		return nil
	}
	// Check if devPath is a block device (ModeDevice set, ModeCharDevice unset)
	if fi.Mode()&os.ModeDevice == 0 || fi.Mode()&os.ModeCharDevice != 0 {
		return nil
	}

	devName := filepath.Base(devPath)
	visited := make(map[string]bool)
	queue := []string{devName}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true

		uuidBytes, err := os.ReadFile(filepath.Join("/sys/block", cur, "dm", "uuid")) //nolint:gosec // G304: sysfs names listed by the kernel
		if err == nil && strings.HasPrefix(string(uuidBytes), "CRYPT-") {
			return boolPtr(true)
		}

		entries, err := os.ReadDir(filepath.Join("/sys/block", cur, "slaves"))
		if err == nil {
			for _, entry := range entries {
				slave := entry.Name()
				if !visited[slave] {
					queue = append(queue, slave)
				}
			}
		}
	}

	return boolPtr(false)
}
