#!/bin/sh
set -eu

# OpenSASE VM test environment - image fetcher
# Downloads official Debian stable and Fedora base images, verifies cryptographic
# checksums, and installs them in VM_DIR/base.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

init_vm_dirs

DEBIAN_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
DEBIAN_CHECKSUM_URL="https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
DEBIAN_TARGET="${BASE_DIR}/debian-base.qcow2"

FEDORA_IMAGE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2"
FEDORA_CHECKSUM_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-45-1.4-x86_64-CHECKSUM"
FEDORA_TARGET="${BASE_DIR}/fedora-base.qcow2"

# Retrieve remote Content-Length header or return a fallback estimation
get_remote_size() {
    url="$1"
    fallback="$2"
    if command -v curl >/dev/null 2>&1; then
        len="$(curl -sIL "$url" | tr -d '\r' | grep -i '^content-length:' | tail -n 1 | awk '{print $2}' || true)"
        if [ -n "$len" ] && [ "$len" -gt 0 ] 2>/dev/null; then
            mb=$((len / 1024 / 1024))
            echo "${mb} MiB (${len} bytes)"
            return 0
        fi
    fi
    echo "${fallback}"
}

echo "======================================================================"
echo "OpenSASE Maintainer VM Base Images"
echo "======================================================================"
echo "Target base directory: ${BASE_DIR}"
echo ""
echo "1. Debian Stable (Generic Cloud Image - qcow2):"
echo "   URL:  ${DEBIAN_IMAGE_URL}"
echo "   Size: $(get_remote_size "${DEBIAN_IMAGE_URL}" "~350 MiB")"
echo "   Hash: ${DEBIAN_CHECKSUM_URL} (SHA512)"
echo "   Dest: ${DEBIAN_TARGET}"
echo ""
echo "2. Fedora Cloud Base (qcow2):"
echo "   URL:  ${FEDORA_IMAGE_URL}"
echo "   Size: $(get_remote_size "${FEDORA_IMAGE_URL}" "~450 MiB")"
echo "   Hash: ${FEDORA_CHECKSUM_URL} (CHECKSUM)"
echo "   Dest: ${FEDORA_TARGET}"
echo ""
echo "3. Windows Base Image:"
echo "   Notice: Windows is not downloaded automatically. Maintainers must"
echo "   supply an evaluation ISO path when setting up the Windows VM:"
echo "     scripts/vm/windows.sh <path-to-evaluation-iso>"
echo "======================================================================"
echo ""

# Require explicit confirmation via --yes
has_yes=0
for arg in "$@"; do
    if [ "$arg" = "--yes" ]; then
        has_yes=1
        break
    fi
done

if [ "$has_yes" -eq 0 ]; then
    echo "Approval required: Image downloads are not executed without maintainer approval."
    echo "To download and verify base images, execute with --yes:"
    echo "  $0 --yes"
    exit 0
fi

# Step 1: Debian download and verification
echo "----------------------------------------------------------------------"
echo "Downloading Debian stable generic cloud image and checksums..."
echo "----------------------------------------------------------------------"
debian_tmp_img="${BASE_DIR}/debian-13-generic-amd64.qcow2.tmp"
debian_sums="${BASE_DIR}/debian-SHA512SUMS"

curl -fL -o "${debian_sums}" "${DEBIAN_CHECKSUM_URL}"
curl -fL --progress-bar -o "${debian_tmp_img}" "${DEBIAN_IMAGE_URL}"

echo "Verifying Debian image SHA-512 checksum..."
debian_expected="$(grep 'debian-13-generic-amd64\.qcow2' "${debian_sums}" | awk '{print $1}')"
if [ -z "$debian_expected" ]; then
    echo "Error: Could not locate debian-13-generic-amd64.qcow2 in ${debian_sums}" >&2
    rm -f "${debian_tmp_img}"
    exit 1
fi

debian_actual="$(sha512sum "${debian_tmp_img}" | awk '{print $1}')"
if [ "$debian_expected" != "$debian_actual" ]; then
    echo "Error: SHA-512 checksum mismatch for Debian image!" >&2
    echo "  Expected: ${debian_expected}" >&2
    echo "  Actual:   ${debian_actual}" >&2
    rm -f "${debian_tmp_img}"
    exit 1
fi
echo "Debian checksum verified: ${debian_actual}"
mv -f "${debian_tmp_img}" "${DEBIAN_TARGET}"
echo "Debian base image ready at: ${DEBIAN_TARGET}"

# Step 2: Fedora download and verification
echo ""
echo "----------------------------------------------------------------------"
echo "Downloading Fedora Cloud Base image and checksums..."
echo "----------------------------------------------------------------------"
fedora_tmp_img="${BASE_DIR}/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2.tmp"
fedora_checksum_file="${BASE_DIR}/fedora-CHECKSUM"

curl -fL -o "${fedora_checksum_file}" "${FEDORA_CHECKSUM_URL}"
curl -fL --progress-bar -o "${fedora_tmp_img}" "${FEDORA_IMAGE_URL}"

echo "Verifying Fedora image checksum..."
# Check whether CHECKSUM uses SHA512 or SHA256
if grep -i 'SHA512' "${fedora_checksum_file}" >/dev/null 2>&1; then
    fedora_expected="$(grep -v '^#' "${fedora_checksum_file}" | grep 'Fedora-Cloud-Base-Generic-45-1.4\.x86_64\.qcow2' | sed 's/.*= *//' | awk '{print $1}')"
    fedora_actual="$(sha512sum "${fedora_tmp_img}" | awk '{print $1}')"
else
    fedora_expected="$(grep -v '^#' "${fedora_checksum_file}" | grep 'Fedora-Cloud-Base-Generic-45-1.4\.x86_64\.qcow2' | sed 's/.*= *//' | awk '{print $1}')"
    fedora_actual="$(sha256sum "${fedora_tmp_img}" | awk '{print $1}')"
fi

if [ -z "$fedora_expected" ]; then
    echo "Error: Could not extract checksum from ${fedora_checksum_file}" >&2
    rm -f "${fedora_tmp_img}"
    exit 1
fi

if [ "$fedora_expected" != "$fedora_actual" ]; then
    echo "Error: Checksum mismatch for Fedora image!" >&2
    echo "  Expected: ${fedora_expected}" >&2
    echo "  Actual:   ${fedora_actual}" >&2
    rm -f "${fedora_tmp_img}"
    exit 1
fi
echo "Fedora checksum verified: ${fedora_actual}"
mv -f "${fedora_tmp_img}" "${FEDORA_TARGET}"
echo "Fedora base image ready at: ${FEDORA_TARGET}"

echo ""
echo "All base images downloaded and verified successfully."
