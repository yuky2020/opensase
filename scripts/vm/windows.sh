#!/bin/sh
set -eu

# OpenSASE VM test environment - Windows VM manager
# Creates a 64 GB base disk and boots the evaluation installer on first run.
# Subsequent runs boot a copy-on-write overlay with a display window.
#
# VirtIO drivers are not needed because IDE disk emulation (-drive if=ide)
# and Intel e1000 NIC emulation (-device e1000) are natively supported
# by Windows without extra drivers.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

init_vm_dirs
check_kvm_access

instance_name="windows"
instance_dir="${INSTANCES_DIR}/${instance_name}"
mkdir -p "$instance_dir"

base_image="${BASE_DIR}/windows-base.qcow2"
overlay="${instance_dir}/overlay.qcow2"
pid_file="${instance_dir}/qemu.pid"
port_file="${instance_dir}/port.txt"

# If already running, notify maintainer
if is_vm_running "$instance_name"; then
    pid="$(cat "$pid_file")"
    echo "Windows VM is already running (PID: ${pid})."
    if [ -f "$port_file" ]; then
        rdp_port="$(cat "$port_file")"
        echo "RDP forwarded to host port: ${rdp_port}"
    fi
    exit 0
fi

# -----------------------------------------------------------------------------
# First Run: Base Image Installation
# -----------------------------------------------------------------------------
if [ ! -f "$base_image" ]; then
    if [ $# -lt 1 ]; then
        echo "Error: Windows base disk does not exist yet (${base_image})." >&2
        echo "Usage: $0 <path-to-evaluation-iso>" >&2
        echo "" >&2
        echo "On first run, provide the path to the official Windows evaluation ISO." >&2
        echo "A 64 GB qcow2 base disk will be created and booted with a display window." >&2
        echo "Once the OS installation completes, shut down the guest OS." >&2
        echo "Subsequent runs will use a fast copy-on-write overlay over the base image." >&2
        exit 1
    fi

    iso_path="$1"
    if [ ! -f "$iso_path" ]; then
        echo "Error: ISO file not found at: ${iso_path}" >&2
        exit 1
    fi

    echo "Creating 64 GB qcow2 base disk at: ${base_image}..."
    qemu-img create -f qcow2 "$base_image" 64G

    echo "----------------------------------------------------------------------"
    echo "Starting Windows installer with a display window..."
    echo "----------------------------------------------------------------------"
    echo "Hardware details:"
    echo "  - RAM: 4 GB, vCPUs: 2"
    echo "  - Disk: IDE emulation (-drive if=ide). VirtIO drivers are not needed."
    echo "  - Network: Intel e1000 (-device e1000). Natively supported."
    echo "  - Networking: User-mode slirp (host reachable at 10.0.2.2)."
    echo ""
    echo "Action required:"
    echo "  Complete the Windows setup wizard in the display window."
    echo "  When setup is complete and Windows reaches the desktop, shut down"
    echo "  the guest OS cleanly from the Start menu."
    echo "----------------------------------------------------------------------"

    qemu-system-x86_64 \
        -enable-kvm \
        -m 4G \
        -smp 2 \
        -cpu host \
        -drive file="${base_image}",if=ide,format=qcow2 \
        -cdrom "${iso_path}" \
        -boot d \
        -netdev user,id=net0 \
        -device e1000,netdev=net0

    echo ""
    echo "Windows base installation session finished."
    echo "The base disk is ready at: ${base_image}"
    echo "Subsequent runs of $0 will automatically boot an overlay over this base."
    exit 0
fi

# -----------------------------------------------------------------------------
# Subsequent Runs: Overlay Boot
# -----------------------------------------------------------------------------
echo "Windows base image detected at: ${base_image}"

if [ ! -f "$overlay" ]; then
    create_overlay "$base_image" "$overlay"
else
    echo "Reusing existing overlay: ${overlay}"
fi

# Find free port for RDP forwarding (guest 3389 -> host port)
rdp_port="$(find_free_port 3389)"
echo "$rdp_port" > "$port_file"

echo "----------------------------------------------------------------------"
echo "Starting Windows VM with display window..."
echo "----------------------------------------------------------------------"
echo "Overlay:  ${overlay}"
echo "RDP port: Host 127.0.0.1:${rdp_port} -> Guest 3389"
echo "Host IP:  Reachable from guest as 10.0.2.2"
echo "Drivers:  VirtIO drivers not needed (IDE disk emulation + e1000 NIC)"
echo ""
echo "To reset this instance back to the clean base image, run:"
echo "  scripts/vm/reset.sh windows"
echo "----------------------------------------------------------------------"

qemu-system-x86_64 \
    -enable-kvm \
    -m 4G \
    -smp 2 \
    -cpu host \
    -drive file="${overlay}",if=ide,format=qcow2 \
    -netdev user,id=net0,hostfwd=tcp::"${rdp_port}"-:3389 \
    -device e1000,netdev=net0 \
    -pidfile "${pid_file}"
