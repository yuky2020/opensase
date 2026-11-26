#!/bin/sh
set -eu

# Usage: scripts/package-rpm.sh <version> <opensased binary> <flutter bundle dir> <out dir> <opensase cli binary>
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <version> <opensased binary> <flutter bundle dir> <out dir> <opensase cli binary>" >&2
    exit 1
fi

VERSION="$1"
OPENSASED_BIN="$2"
FLUTTER_BUNDLE_DIR="$3"
OUT_DIR="$4"
OPENSASE_CLI_BIN="$5"

if [ ! -f "$OPENSASED_BIN" ]; then
    echo "Error: opensased binary not found at $OPENSASED_BIN" >&2
    exit 1
fi

if [ ! -f "$OPENSASE_CLI_BIN" ]; then
    echo "Error: opensase cli binary not found at $OPENSASE_CLI_BIN" >&2
    exit 1
fi

if [ ! -d "$FLUTTER_BUNDLE_DIR" ]; then
    echo "Error: flutter bundle dir not found at $FLUTTER_BUNDLE_DIR" >&2
    exit 1
fi

LINUX_DIR="deploy/desktop/linux"
if [ ! -d "$LINUX_DIR" ]; then
    LINUX_DIR="$(dirname "$0")/../deploy/desktop/linux"
fi
if [ ! -d "$LINUX_DIR" ]; then
    echo "Error: deploy/desktop/linux directory not found" >&2
    exit 1
fi

RPM_VERSION=$(printf '%s\n' "$VERSION" | tr '-' '~')

STAGE_DIR=$(mktemp -d)
TOP_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR" "$TOP_DIR"' EXIT

mkdir -p "$TOP_DIR/BUILD" "$TOP_DIR/RPMS" "$TOP_DIR/SOURCES" "$TOP_DIR/SPECS" "$TOP_DIR/SRPMS" "$TOP_DIR/BUILDROOT"
mkdir -p "$OUT_DIR"

mkdir -p "$STAGE_DIR/usr/bin"
mkdir -p "$STAGE_DIR/usr/lib/systemd/system"
mkdir -p "$STAGE_DIR/usr/lib/sysusers.d"
mkdir -p "$STAGE_DIR/opt/opensase"
mkdir -p "$STAGE_DIR/usr/share/applications"

# Install daemon binary
cp "$OPENSASED_BIN" "$STAGE_DIR/usr/bin/opensased"
chmod 0755 "$STAGE_DIR/usr/bin/opensased"

# Install CLI binary
cp "$OPENSASE_CLI_BIN" "$STAGE_DIR/usr/bin/opensase"
chmod 0755 "$STAGE_DIR/usr/bin/opensase"

# Install systemd service unit
cp "$LINUX_DIR/opensased.service" "$STAGE_DIR/usr/lib/systemd/system/opensased.service"
chmod 0644 "$STAGE_DIR/usr/lib/systemd/system/opensased.service"

# Install sysusers configuration
cp "$LINUX_DIR/opensase.sysusers" "$STAGE_DIR/usr/lib/sysusers.d/opensase.conf"
chmod 0644 "$STAGE_DIR/usr/lib/sysusers.d/opensase.conf"

# Install Flutter application bundle
cp -R "$FLUTTER_BUNDLE_DIR"/* "$STAGE_DIR/opt/opensase/"
chmod 0755 "$STAGE_DIR/opt/opensase/opensase"

# Install app launcher
cp "$LINUX_DIR/opensase-app" "$STAGE_DIR/usr/bin/opensase-app"
chmod 0755 "$STAGE_DIR/usr/bin/opensase-app"

# Install desktop entry
cp "$LINUX_DIR/eu.opensase.opensase.desktop" "$STAGE_DIR/usr/share/applications/eu.opensase.opensase.desktop"
chmod 0644 "$STAGE_DIR/usr/share/applications/eu.opensase.opensase.desktop"

cat << EOF > "$TOP_DIR/SPECS/opensase.spec"
Name:           opensase
Version:        $RPM_VERSION
Release:        1
Summary:        OpenSASE client and daemon
License:        Apache-2.0
URL:            https://github.com/yuky2020/opensase
BuildArch:      x86_64
Requires:       gtk3, systemd, nftables

%global debug_package %{nil}
%global __os_install_post %{nil}

%description
OpenSASE provides an on-device firewall with post-quantum secure tunnel,
policy enforcement, and a desktop user interface.

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{stagedir}/. %{buildroot}/

%pre
getent group opensase >/dev/null || groupadd -r opensase

%post
%if %{defined systemd_post}
%systemd_post opensased.service
%else
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now opensased.service || :
fi
%endif
echo "OpenSASE daemon installed and started."
echo "To control OpenSASE as a non-root user, add your user to the opensase group:"
echo "  usermod -aG opensase <user>"
echo "and log in again."

%preun
%if %{defined systemd_preun}
%systemd_preun opensased.service
%else
if [ "\$1" -eq 0 ]; then
    if [ -d /run/systemd/system ]; then
        systemctl disable --now opensased.service || :
    fi
fi
%endif

%postun
%if %{defined systemd_postun}
%systemd_postun opensased.service
%else
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
%endif

%files
%defattr(-,root,root,-)
/usr/bin/opensased
/usr/bin/opensase
/usr/bin/opensase-app
/opt/opensase
/usr/lib/systemd/system/opensased.service
/usr/lib/sysusers.d/opensase.conf
/usr/share/applications/eu.opensase.opensase.desktop
EOF

rpmbuild -bb \
    --define "_topdir $TOP_DIR" \
    --buildroot "$TOP_DIR/BUILDROOT" \
    --define "stagedir $STAGE_DIR" \
    "$TOP_DIR/SPECS/opensase.spec"

cp "$TOP_DIR"/RPMS/x86_64/opensase-"$RPM_VERSION"-1.x86_64.rpm "$OUT_DIR/opensase-$RPM_VERSION-1.x86_64.rpm"
