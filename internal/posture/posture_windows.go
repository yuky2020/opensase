//go:build windows

package posture

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/yuky2020/opensase/pkg/api"
)

func collect() api.Posture {
	p := api.Posture{
		OS:            "windows",
		ClientVersion: clientVersion(),
	}

	// 1. OSVersion: "<major>.<minor>.<build>" from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
	p.OSVersion = collectWindowsOSVersion()

	// 2. Firewall: true only when EnableFirewall is 1 in all of DomainProfile, StandardProfile, and PublicProfile (nil if unreadable)
	p.Firewall = collectWindowsFirewall()

	// 3. Managed: true when HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters has non-empty Domain, false otherwise
	p.Managed = collectWindowsManaged()

	// 4. DiskEncrypted and ScreenLock nil (already nil)

	// 5. BootTime = now minus windows.GetTickCount64 milliseconds if available, otherwise zero
	if ms := tickCount64(); ms > 0 {
		p.BootTime = time.Now().Add(-time.Duration(ms) * time.Millisecond).UTC()
	}

	return p
}

func collectWindowsOSVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()

	major, _, errMajor := k.GetIntegerValue("CurrentMajorVersionNumber")
	minor, _, errMinor := k.GetIntegerValue("CurrentMinorVersionNumber")
	build, _, errBuild := k.GetStringValue("CurrentBuildNumber")
	if errBuild != nil {
		build, _, errBuild = k.GetStringValue("CurrentBuild")
	}
	if errMajor == nil && errMinor == nil && errBuild == nil && build != "" {
		return fmt.Sprintf("%d.%d.%s", major, minor, build)
	}
	return ""
}

func collectWindowsFirewall() *bool {
	profiles := []string{
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`,
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`,
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`,
	}

	for _, subkey := range profiles {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, subkey, registry.QUERY_VALUE)
		if err != nil {
			return nil
		}
		val, _, err := k.GetIntegerValue("EnableFirewall")
		_ = k.Close()
		if err != nil {
			return nil
		}
		if val != 1 {
			return boolPtr(false)
		}
	}

	return boolPtr(true)
}

func collectWindowsManaged() *bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return boolPtr(false)
	}
	defer func() { _ = k.Close() }()

	domain, _, err := k.GetStringValue("Domain")
	if err == nil && strings.TrimSpace(domain) != "" {
		return boolPtr(true)
	}
	return boolPtr(false)
}

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// tickCount64 returns the milliseconds since boot, or 0 if the call is unavailable.
func tickCount64() uint64 {
	if procGetTickCount64.Find() != nil {
		return 0
	}
	r, _, _ := procGetTickCount64.Call()
	return uint64(r)
}
