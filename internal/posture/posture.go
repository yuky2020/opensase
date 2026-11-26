// Package posture collects the desktop device posture (ADR-0035).
package posture

import (
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

func boolPtr(b bool) *bool {
	return &b
}

func clientVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// parseOSRelease parses /etc/os-release key-value pairs and returns VERSION_ID without quotes,
// or empty string if not present.
func parseOSRelease(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == "VERSION_ID" {
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"'`)
			return v
		}
	}
	return ""
}

// parseMountinfoRoot parses /proc/self/mountinfo and returns the mount source of the
// block device holding "/" (the last mount for "/"), or empty string if not found.
func parseMountinfoRoot(content string) string {
	var rootDev string
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		// Mount point is field index 4.
		if fields[4] != "/" {
			continue
		}
		// Find the "-" separator.
		dashIdx := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				dashIdx = i
				break
			}
		}
		if dashIdx == -1 || dashIdx+2 >= len(fields) {
			continue
		}
		// fields[dashIdx+1] is fstype, fields[dashIdx+2] is mountSource.
		rootDev = fields[dashIdx+2]
	}
	return rootDev
}

// parseBtime parses /proc/stat lines to find the btime (boot time in seconds since epoch)
// and returns it in UTC, or a zero time if not found or invalid.
func parseBtime(content string) time.Time {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "btime" {
			sec, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil && sec > 0 {
				return time.Unix(sec, 0).UTC()
			}
		}
	}
	return time.Time{}
}

// Collect gathers advisory device posture for the current platform.
func Collect() api.Posture {
	return collect()
}
