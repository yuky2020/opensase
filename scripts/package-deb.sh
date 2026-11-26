#!/bin/sh
set -eu

# Usage: scripts/package-deb.sh <version> <opensased binary> <flutter bundle dir> <out dir> <opensase cli binary>
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
if [ ! -f "$LINUX_DIR/opensased.service" ]; then
    echo "Error: opensased.service unit file not found" >&2
    exit 1
fi

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT

# Create filesystem layout
mkdir -p "$STAGE_DIR/usr/bin"
mkdir -p "$STAGE_DIR/usr/lib/systemd/system"
mkdir -p "$STAGE_DIR/usr/lib/sysusers.d"
mkdir -p "$STAGE_DIR/opt/opensase"
mkdir -p "$STAGE_DIR/usr/share/applications"
mkdir -p "$STAGE_DIR/DEBIAN"
mkdir -p "$OUT_DIR"

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

# Create package control file
cat << EOF > "$STAGE_DIR/DEBIAN/control"
Package: opensase
Version: $VERSION
Architecture: amd64
Maintainer: OpenSASE project <noreply@opensase.invalid>
Depends: libgtk-3-0, systemd, nftables
Section: net
Priority: optional
Description: OpenSASE client and daemon
 OpenSASE provides an on-device firewall with post-quantum secure tunnel,
 policy enforcement, and a desktop user interface.
EOF
chmod 0644 "$STAGE_DIR/DEBIAN/control"

# Create maintainer scripts
cat << 'EOF' > "$STAGE_DIR/DEBIAN/postinst"
#!/bin/sh
set -e

case "$1" in
    configure)
        if ! getent group opensase >/dev/null; then
            addgroup --system opensase
        fi

        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
            systemctl enable --now opensased.service || true
        fi

        echo "OpenSASE daemon installed and started."
        echo "To control OpenSASE as a non-root user, add your user to the opensase group:"
        echo "  usermod -aG opensase <user>"
        echo "and log in again."
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        ;;
esac

exit 0
EOF
chmod 0755 "$STAGE_DIR/DEBIAN/postinst"

cat << 'EOF' > "$STAGE_DIR/DEBIAN/prerm"
#!/bin/sh
set -e

case "$1" in
    remove|deconfigure)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now opensased.service || true
        fi
        ;;
    upgrade|failed-upgrade)
        ;;
    *)
        ;;
esac

exit 0
EOF
chmod 0755 "$STAGE_DIR/DEBIAN/prerm"

cat << 'EOF' > "$STAGE_DIR/DEBIAN/postrm"
#!/bin/sh
set -e

case "$1" in
    purge)
        delgroup --system opensase || true
        rm -rf /var/lib/opensase
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
        fi
        ;;
    remove)
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
        fi
        ;;
    upgrade|failed-upgrade|abort-install|abort-upgrade)
        ;;
    *)
        ;;
esac

exit 0
EOF
chmod 0755 "$STAGE_DIR/DEBIAN/postrm"

# Build package using dpkg-deb
dpkg-deb --build --root-owner-group "$STAGE_DIR" "$OUT_DIR/opensase_${VERSION}_amd64.deb"
