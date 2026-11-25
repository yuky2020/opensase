#!/bin/sh
set -eu

# OpenSASE VM test environment - VM reset
# Stops a running VM instance and removes its copy-on-write overlay and
# generated seed files so that the next invocation starts from a clean base.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <debian|fedora|windows|name>" >&2
    exit 1
fi

name="$1"
instance_dir="${INSTANCES_DIR}/${name}"

echo "Resetting VM instance '${name}'..."

# Ensure the VM is stopped before removing its disk overlay
stop_vm_instance "$name"

# Remove the copy-on-write overlay and instance state files
if [ -d "$instance_dir" ]; then
    echo "Cleaning up overlay and instance files in ${instance_dir}..."
    rm -f "${instance_dir}/overlay.qcow2"
    rm -f "${instance_dir}/seed.iso"
    rm -f "${instance_dir}/user-data"
    rm -f "${instance_dir}/meta-data"
    rm -f "${instance_dir}/port.txt"
    rm -f "${instance_dir}/qemu.pid"
    echo "Instance '${name}' successfully reset. The base image in ${BASE_DIR} is preserved."
    echo "The next run will boot from a fresh copy-on-write overlay."
else
    echo "Instance directory '${instance_dir}' not found; nothing to reset."
fi
