package posture

import (
	"testing"
	"time"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "ubuntu with double quotes",
			content: `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
`,
			want: "22.04",
		},
		{
			name: "debian with double quotes",
			content: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`,
			want: "12",
		},
		{
			name: "fedora unquoted",
			content: `NAME="Fedora Linux"
VERSION="40 (Workstation Edition)"
ID=fedora
VERSION_ID=40
VERSION_CODENAME=""
PLATFORM_ID="platform:f40"
PRETTY_NAME="Fedora Linux 40 (Workstation Edition)"
`,
			want: "40",
		},
		{
			name: "single quotes and whitespace around key/value",
			content: `NAME=Custom
  VERSION_ID = '6.1.0' 
ID=custom
`,
			want: "6.1.0",
		},
		{
			name: "arch linux without version id",
			content: `NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://archlinux.org/"
`,
			want: "",
		},
		{
			name: "commented version id ignored",
			content: `# VERSION_ID="99.9"
NAME="Test"
`,
			want: "",
		},
		{
			name:    "empty version id",
			content: `VERSION_ID=""`,
			want:    "",
		},
		{
			name:    "empty content",
			content: "",
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOSRelease(tc.content)
			if got != tc.want {
				t.Errorf("parseOSRelease() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseMountinfoRoot(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "standard ext4 plain block device",
			content: `28 1 8:1 / / rw,relatime master:1 - ext4 /dev/sda1 rw,errors=remount-ro
29 28 8:2 / /home rw,relatime - ext4 /dev/sda2 rw
`,
			want: "/dev/sda1",
		},
		{
			name: "dm device root",
			content: `36 35 254:0 / / rw,noatime shared:1 - ext4 /dev/dm-0 rw
37 36 0:25 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
`,
			want: "/dev/dm-0",
		},
		{
			name: "mapper root with optional fields",
			content: `10 1 254:1 / / rw,relatime master:1 shared:2 - btrfs /dev/mapper/root rw,subvol=/
`,
			want: "/dev/mapper/root",
		},
		{
			name: "nvme partition",
			content: `40 30 259:2 / / rw,relatime - ext4 /dev/nvme0n1p2 rw
`,
			want: "/dev/nvme0n1p2",
		},
		{
			name: "container overlay root",
			content: `100 50 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l
`,
			want: "overlay",
		},
		{
			name: "tmpfs root",
			content: `15 1 0:15 / / rw,relatime - tmpfs none rw
`,
			want: "none",
		},
		{
			name: "multiple root mounts uses last one",
			content: `20 1 8:1 / /old rw - ext4 /dev/sda1 rw
28 1 254:0 / / rw - ext4 /dev/dm-0 rw
35 28 8:2 / /home rw - ext4 /dev/sda2 rw
`,
			want: "/dev/dm-0",
		},
		{
			name: "no root mount",
			content: `35 28 8:2 / /home rw - ext4 /dev/sda2 rw
36 28 0:20 / /tmp rw - tmpfs tmpfs rw
`,
			want: "",
		},
		{
			name:    "empty content",
			content: "",
			want:    "",
		},
		{
			name: "malformed lines ignored",
			content: `too few fields
1 2 3 4 / 6 missing separator
`,
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMountinfoRoot(tc.content)
			if got != tc.want {
				t.Errorf("parseMountinfoRoot() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseBtime(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    time.Time
	}{
		{
			name: "valid btime in proc stat",
			content: `cpu  12345 6789 101112
intr 123456
ctxt 7891011
btime 1764172800
processes 12345
`,
			want: time.Unix(1764172800, 0).UTC(),
		},
		{
			name: "btime with extra spaces",
			content: `cpu 1 2 3
btime    1700000000  
`,
			want: time.Unix(1700000000, 0).UTC(),
		},
		{
			name: "missing btime",
			content: `cpu  12345 6789 101112
processes 12345
`,
			want: time.Time{},
		},
		{
			name: "invalid btime non-numeric",
			content: `btime not-a-number
`,
			want: time.Time{},
		},
		{
			name: "negative btime ignored",
			content: `btime -100
`,
			want: time.Time{},
		},
		{
			name:    "empty content",
			content: "",
			want:    time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBtime(tc.content)
			if !got.Equal(tc.want) {
				t.Errorf("parseBtime() = %v, want %v", got, tc.want)
			}
		})
	}
}
