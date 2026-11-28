#!/bin/sh
set -eu

# OpenSASE VM test environment - SCP helper
# Copies one or more local files to /tmp/ inside a running Linux test VM
# using the dedicated VM SSH key.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <debian|fedora> <file>..." >&2
    exit 1
fi

target="$1"
shift

case "$target" in
    debian|fedora)
        ;;
    *)
        echo "Error: Unknown target '$target'. Supported targets are 'debian' or 'fedora'." >&2
        exit 1
        ;;
esac

port_file="${INSTANCES_DIR}/${target}/port.txt"
if [ ! -f "$port_file" ]; then
    echo "Error: SSH port file not found for '${target}': ${port_file}" >&2
    echo "Start the VM first by running:" >&2
    echo "  scripts/vm/up.sh ${target}" >&2
    exit 1
fi

ssh_port="$(cat "$port_file")"
if [ -z "$ssh_port" ]; then
    echo "Error: SSH port file is empty for '${target}': ${port_file}" >&2
    echo "Start the VM first by running:" >&2
    echo "  scripts/vm/up.sh ${target}" >&2
    exit 1
fi

if [ ! -f "$VM_KEY" ]; then
    echo "Error: VM SSH key not found at: ${VM_KEY}" >&2
    echo "Reset and recreate the VM by running:" >&2
    echo "  scripts/vm/reset.sh ${target} && scripts/vm/up.sh ${target}" >&2
    exit 1
fi

exec scp \
    -i "$VM_KEY" \
    -P "$ssh_port" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -o LogLevel=ERROR \
    "$@" tester@127.0.0.1:/tmp/
