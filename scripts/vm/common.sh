#!/bin/sh
set -eu

# OpenSASE VM test environment - common definitions and helpers
# Base directory for VM disks and runtime instances
VM_DIR="${VM_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/opensase-vms}"
BASE_DIR="${VM_DIR}/base"
INSTANCES_DIR="${VM_DIR}/instances"

# Ensure required directory tree exists
init_vm_dirs() {
    mkdir -p "${BASE_DIR}" "${INSTANCES_DIR}"
}

# Create a qcow2 overlay backed by a base image
# Usage: create_overlay <base_image> <overlay_image>
create_overlay() {
    base_img="$1"
    overlay_img="$2"

    if [ ! -f "$base_img" ]; then
        echo "Error: Base image not found: $base_img" >&2
        return 1
    fi

    overlay_dir="$(dirname "$overlay_img")"
    mkdir -p "$overlay_dir"

    echo "Creating qcow2 overlay: $overlay_img (base: $base_img)"
    qemu-img create -f qcow2 -F qcow2 -b "$base_img" "$overlay_img"
}

# Find an available TCP port on 127.0.0.1
# Usage: find_free_port [start_port]
find_free_port() {
    start_port="${1:-2222}"

    # Try python3 ephemeral socket binding if python3 is available
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
print(port)
' && return 0
    fi

    # Fallback port scanning starting from start_port
    candidate="$start_port"
    while [ "$candidate" -le 65535 ]; do
        in_use=0
        if command -v ss >/dev/null 2>&1; then
            if ss -tln | grep -q ":${candidate} "; then
                in_use=1
            fi
        elif command -v nc >/dev/null 2>&1; then
            if nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1; then
                in_use=1
            fi
        fi

        if [ "$in_use" -eq 0 ]; then
            echo "$candidate"
            return 0
        fi
        candidate=$((candidate + 1))
    done

    echo "Error: No available TCP port found" >&2
    return 1
}

# Print instructions for SSH and SCP access
# Usage: print_ssh_info <user> <port>
print_ssh_info() {
    ssh_user="$1"
    ssh_port="$2"

    echo ""
    echo "======================================================================"
    echo "SSH and SCP Connection Information:"
    echo "======================================================================"
    echo "  SSH command:"
    echo "    ssh -p ${ssh_port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${ssh_user}@127.0.0.1"
    echo ""
    echo "  SCP command (copy files into guest):"
    echo "    scp -P ${ssh_port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <file> ${ssh_user}@127.0.0.1:/tmp/"
    echo "======================================================================"
    echo ""
}

# Check KVM availability and group permissions
check_kvm_access() {
    if [ ! -e /dev/kvm ]; then
        echo "Warning: /dev/kvm does not exist. Hardware acceleration may be unavailable." >&2
    elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        echo "Warning: /dev/kvm is not read/write accessible by $USER." >&2
        echo "Ensure your user belongs to the kvm group: sudo usermod -aG kvm $USER" >&2
    fi
}

# Check if a VM instance is currently running
# Usage: is_vm_running <instance_name>
is_vm_running() {
    instance_name="$1"
    pid_file="${INSTANCES_DIR}/${instance_name}/qemu.pid"

    if [ -f "$pid_file" ]; then
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Stop a running VM instance
# Usage: stop_vm_instance <instance_name>
stop_vm_instance() {
    instance_name="$1"
    pid_file="${INSTANCES_DIR}/${instance_name}/qemu.pid"

    if [ ! -f "$pid_file" ]; then
        echo "Instance '${instance_name}' is not running (no PID file found)."
        return 0
    fi

    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -z "$pid" ]; then
        rm -f "$pid_file"
        echo "Instance '${instance_name}' is not running (empty PID file removed)."
        return 0
    fi

    if kill -0 "$pid" 2>/dev/null; then
        echo "Stopping instance '${instance_name}' (PID: ${pid})..."
        kill -TERM "$pid" 2>/dev/null || true

        # Wait up to 10 seconds for graceful termination
        wait_count=0
        while kill -0 "$pid" 2>/dev/null && [ "$wait_count" -lt 10 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done

        # Force terminate if still running
        if kill -0 "$pid" 2>/dev/null; then
            echo "Instance did not terminate cleanly; sending SIGKILL..."
            kill -KILL "$pid" 2>/dev/null || true
            sleep 1
        fi
    else
        echo "Process ${pid} is no longer running."
    fi

    rm -f "$pid_file"
    echo "Instance '${instance_name}' stopped."
}
