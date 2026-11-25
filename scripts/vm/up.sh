#!/bin/sh
set -eu

# OpenSASE VM test environment - VM starter
# Launches a headless QEMU/KVM virtual machine with a copy-on-write overlay,
# cloud-init user-data seed ISO, passwordless sudo for user 'tester',
# and user-mode networking with an SSH port forward.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

init_vm_dirs
check_kvm_access

if [ $# -lt 1 ]; then
    echo "Usage: $0 <debian|fedora>" >&2
    exit 1
fi

target="$1"
case "$target" in
    debian|fedora)
        ;;
    *)
        echo "Error: Unknown target '$target'. Supported targets are 'debian' or 'fedora'." >&2
        exit 1
        ;;
esac

base_image="${BASE_DIR}/${target}-base.qcow2"
if [ ! -f "$base_image" ]; then
    echo "Error: Base image for '${target}' not found at: ${base_image}" >&2
    echo "Please download and verify base images first by running:" >&2
    echo "  scripts/vm/fetch-images.sh --yes" >&2
    exit 1
fi

instance_dir="${INSTANCES_DIR}/${target}"
mkdir -p "$instance_dir"

overlay="${instance_dir}/overlay.qcow2"
seed_iso="${instance_dir}/seed.iso"
user_data="${instance_dir}/user-data"
meta_data="${instance_dir}/meta-data"
pid_file="${instance_dir}/qemu.pid"
port_file="${instance_dir}/port.txt"

# If already running, print connection info and exit cleanly
if is_vm_running "$target"; then
    pid="$(cat "$pid_file")"
    echo "VM '${target}' is already running (PID: ${pid})."
    if [ -f "$port_file" ]; then
        ssh_port="$(cat "$port_file")"
        print_ssh_info "tester" "$ssh_port"
    fi
    exit 0
fi

# 1. Overlay creation (or reuse)
if [ ! -f "$overlay" ]; then
    create_overlay "$base_image" "$overlay"
else
    echo "Reusing existing overlay: ${overlay}"
fi

# 2. Cloud-init seed ISO generation (or reuse)
if [ ! -f "$seed_iso" ]; then
    echo "Configuring cloud-init credentials..."

    # Gather maintainer SSH public keys
    ssh_keys=""
    for key_file in "$HOME"/.ssh/*.pub; do
        if [ -f "$key_file" ]; then
            key_content="$(cat "$key_file")"
            ssh_keys="${ssh_keys}      - ${key_content}
"
        fi
    done

    # Generate an ephemeral keypair if no existing public keys were discovered
    if [ -z "$ssh_keys" ]; then
        test_key="${instance_dir}/id_ed25519"
        if [ ! -f "$test_key" ]; then
            echo "No SSH keys found in ~/.ssh/*.pub; generating dedicated test keypair..."
            ssh-keygen -t ed25519 -N "" -f "$test_key" -C "tester@opensase-vm"
        fi
        key_content="$(cat "${test_key}.pub")"
        ssh_keys="      - ${key_content}
"
        echo "Created test key at ${test_key}"
    fi

    # Write cloud-init user-data and meta-data
    cat > "$user_data" <<EOF
#cloud-config
users:
  - name: tester
    gecos: OpenSASE Test User
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
${ssh_keys}ssh_pwauth: false
package_update: false
EOF

    cat > "$meta_data" <<EOF
instance-id: ${target}-vm-instance
local-hostname: ${target}-vm
EOF

    echo "Building cloud-init seed ISO: ${seed_iso}..."
    if command -v genisoimage >/dev/null 2>&1; then
        genisoimage -output "$seed_iso" -volid cidata -joliet -rock "$user_data" "$meta_data" >/dev/null 2>&1
    elif command -v xorriso >/dev/null 2>&1; then
        xorriso -as genisoimage -output "$seed_iso" -volid cidata -joliet -rock "$user_data" "$meta_data" >/dev/null 2>&1
    else
        echo "Error: genisoimage or xorriso is required to generate the cloud-init seed ISO." >&2
        exit 1
    fi
else
    echo "Reusing existing seed ISO: ${seed_iso}"
fi

# 3. Port allocation
ssh_port=""
if [ -f "$port_file" ]; then
    saved_port="$(cat "$port_file" 2>/dev/null || true)"
    if [ -n "$saved_port" ]; then
        # Check if saved port is still available
        if command -v ss >/dev/null 2>&1 && ! ss -tln | grep -q ":${saved_port} "; then
            ssh_port="$saved_port"
        fi
    fi
fi

if [ -z "$ssh_port" ]; then
    case "$target" in
        debian) base_p=2222 ;;
        fedora) base_p=2223 ;;
        *) base_p=2224 ;;
    esac
    ssh_port="$(find_free_port "$base_p")"
    echo "$ssh_port" > "$port_file"
fi

# 4. Start QEMU headless with KVM acceleration
# Note:
# - Virtual machine has its own Linux kernel, so /dev/net/tun is available inside the guest.
# - User-mode networking (slirp) forwards guest port 22 to host port ${ssh_port}.
# - The host is accessible from the guest at 10.0.2.2.
# - Packages are copied in via scp; 9p and virtiofs are not required.
echo "Starting QEMU VM for ${target} in headless mode (4 GB RAM, 2 vCPUs)..."

qemu-system-x86_64 \
    -enable-kvm \
    -m 4G \
    -smp 2 \
    -cpu host \
    -drive file="${overlay}",if=virtio,format=qcow2 \
    -drive file="${seed_iso}",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp::"${ssh_port}"-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -daemonize \
    -pidfile "${pid_file}"

echo "VM '${target}' started successfully (PID: $(cat "${pid_file}"))."
print_ssh_info "tester" "${ssh_port}"
