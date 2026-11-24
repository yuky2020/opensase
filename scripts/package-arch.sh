#!/bin/sh
set -eu

# Usage: scripts/package-arch.sh <version> <opensased> <bundle> <out dir> <cli>
#
# NOTE: makepkg must not run as root. This script must be run as a non-root user.
# When running in containers or CI environments, execute as a non-root builder user.

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <version> <opensased> <bundle> <out dir> <cli>" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "Error: makepkg must not run as root. Please run as a non-root user." >&2
    exit 1
fi

VERSION="$1"
OPENSASED_BIN="$2"
FLUTTER_BUNDLE_DIR="$3"
OUT_DIR="$4"
OPENSASE_CLI_BIN="$5"

to_abs() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$PWD" "$1" ;;
    esac
}

OPENSASED_BIN="$(to_abs "$OPENSASED_BIN")"
FLUTTER_BUNDLE_DIR="$(to_abs "$FLUTTER_BUNDLE_DIR")"
OUT_DIR="$(to_abs "$OUT_DIR")"
OPENSASE_CLI_BIN="$(to_abs "$OPENSASE_CLI_BIN")"

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

ARCH_DIR="deploy/desktop/arch"
if [ ! -d "$ARCH_DIR" ]; then
    ARCH_DIR="$(dirname "$0")/../deploy/desktop/arch"
fi
if [ ! -d "$ARCH_DIR" ]; then
    echo "Error: deploy/desktop/arch directory not found" >&2
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

ARCH_DIR="$(to_abs "$ARCH_DIR")"
LINUX_DIR="$(to_abs "$LINUX_DIR")"

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

cp "$ARCH_DIR/PKGBUILD" "$BUILD_DIR/"
cp "$ARCH_DIR/opensase.install" "$BUILD_DIR/"
mkdir -p "$OUT_DIR"

export OPENSASE_VERSION="$VERSION"
export OPENSASE_DAEMON="$OPENSASED_BIN"
export OPENSASE_CLI="$OPENSASE_CLI_BIN"
export OPENSASE_BUNDLE="$FLUTTER_BUNDLE_DIR"
export OPENSASE_LINUX_DIR="$LINUX_DIR"

(
    cd "$BUILD_DIR"
    makepkg --nodeps --noconfirm --force
    cp ./*.pkg.tar.zst "$OUT_DIR/"
)
