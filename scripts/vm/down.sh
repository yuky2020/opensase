#!/bin/sh
set -eu

# OpenSASE VM test environment - VM stopper
# Stops a running VM instance gracefully using its recorded pidfile.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <debian|fedora|windows|name>" >&2
    exit 1
fi

name="$1"
stop_vm_instance "$name"
