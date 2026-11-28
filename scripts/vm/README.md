# OpenSASE Maintainer VM Test Environment

This directory contains POSIX sh scripts for running local virtual machine test environments on a single Linux workstation using QEMU and KVM.

The environment allows maintainers to execute the manual release checklist across multiple operating systems (Debian, Fedora, and Windows) without requiring root privileges or external hypervisor software.

---

## Requirements

Before using these scripts, ensure the following tools are installed on your Linux host:

1. **QEMU & KVM**:
   - `qemu-system-x86_64` (x86_64 system emulator)
   - `qemu-img` (disk image utility)
2. **ISO Creation Utility**:
   - `genisoimage` or `xorriso` (for generating cloud-init configuration seed ISOs)
3. **KVM Group Membership**:
   - Your user account must have read/write access to `/dev/kvm`. On Debian, Fedora, and Arch Linux, this is typically granted by adding your user to the `kvm` group:
     ```bash
     sudo usermod -aG kvm $USER
     ```
     Log out and back in (or run `newgrp kvm`) for the group change to take effect.
4. **Standard Utilities**:
   - `curl` and `sha512sum` / `sha256sum` (for image downloads and verification)
   - `ssh` and `scp` (for remote terminal access and copying packages)

---

## Directory Structure

All VM images and instance state files are kept outside the source repository under `VM_DIR`, which defaults to:

```
${XDG_DATA_HOME:-$HOME/.local/share}/opensase-vms/
├── id_ed25519                   # Dedicated VM SSH private key (created on first use)
├── id_ed25519.pub               # Dedicated VM SSH public key
├── base/
│   ├── debian-base.qcow2        # Verified Debian generic cloud image
│   ├── fedora-base.qcow2        # Verified Fedora Cloud Base image
│   └── windows-base.qcow2       # Installed 64 GB Windows base disk
└── instances/
    ├── debian/
    │   ├── overlay.qcow2        # Copy-on-write overlay
    │   ├── seed.iso             # Cloud-init seed ISO
    │   ├── port.txt             # Allocated host SSH port
    │   └── qemu.pid             # Running QEMU process PID
    ├── fedora/
    │   └── ...
    └── windows/
        ├── overlay.qcow2        # Copy-on-write overlay
        ├── port.txt             # Allocated host RDP port
        └── qemu.pid             # Running QEMU process PID
```

You can customize the base directory by exporting `VM_DIR=/path/to/directory`.

---

## Scripts Overview

### `common.sh`
Common POSIX sh library sourced by the other scripts.
- Defines `VM_DIR`, `BASE_DIR`, `INSTANCES_DIR`, and `VM_KEY` (`$VM_DIR/id_ed25519`).
- Provides `ensure_vm_key` to create the dedicated VM SSH keypair at `$VM_DIR/id_ed25519` on first use.
- Provides `create_overlay` to instantiate a qcow2 overlay backed by a base image:
  ```bash
  qemu-img create -f qcow2 -F qcow2 -b "$base" "$overlay"
  ```
- Provides `find_free_port` to find an available TCP port on `127.0.0.1`.
- Provides `print_ssh_info` to output `ssh` and `scp` connection syntax.
- Provides `check_kvm_access`, `is_vm_running`, and `stop_vm_instance`.

### `fetch-images.sh`
Downloads official upstream base cloud images and verifies their integrity.
- **Debian**: Downloads the official Debian stable generic cloud image (`qcow2`) from `cloud.debian.org/images/cloud/` and validates it against the published `SHA512SUMS`.
- **Fedora**: Downloads the official Fedora Cloud Base image (`qcow2`) from `download.fedoraproject.org` and validates it against the published `CHECKSUM` file.
- **Maintainer Approval**: Prints the URLs, destination paths, and download sizes first. Requires `--yes` to proceed with downloading:
  ```bash
  scripts/vm/fetch-images.sh --yes
  ```
- **Windows Notice**: Reminds maintainers that Windows images are not downloaded automatically and that an evaluation ISO path must be provided to `windows.sh`.

### `up.sh <debian|fedora>`
Spawns a headless Linux virtual machine.
- Reuses or creates a copy-on-write qcow2 overlay over the base image.
- Builds a cloud-init seed ISO (`seed.iso`) containing:
  - User `tester` with passwordless `sudo`.
  - Authorized SSH key from the dedicated keypair at `$VM_DIR/id_ed25519` (created on first use and kept in `$VM_DIR` so resetting or stopping instances preserves it).
- Boots QEMU with:
  - Headless execution (`-display none -daemonize -pidfile ...`).
  - 4 GB RAM, 2 vCPUs, `-enable-kvm`.
  - User-mode networking (`slirp`) forwarding host port (e.g. 2222) to guest SSH port 22.
  - Full guest kernel running with `/dev/net/tun` available inside the VM.
- Prints both the short helper commands (`scripts/vm/ssh.sh`, `scripts/vm/copy.sh`) and the full `ssh`/`scp` commands to connect and copy files.
- Packages are transferred into the VM using `scp` (eliminating dependencies on 9p or virtiofs).
- **Note**: A VM instance created before the dedicated key was introduced keeps its existing `seed.iso` and overlay. Run `scripts/vm/reset.sh <name>` first so the next `up.sh <name>` generates a fresh seed authorizing `$VM_DIR/id_ed25519.pub`.

### `ssh.sh <debian|fedora> [command...]`
Opens an SSH session (or runs an optional command) on a running Linux test VM.
- Reads the allocated host port from `instances/<name>/port.txt`.
- Connects as `tester@127.0.0.1` using the dedicated key at `$VM_DIR/id_ed25519`.

### `copy.sh <debian|fedora> <file>...`
Copies one or more local files to `/tmp/` inside a running Linux test VM.
- Reads the allocated host port from `instances/<name>/port.txt`.
- Transfers files via `scp` using the dedicated key at `$VM_DIR/id_ed25519`.

### `down.sh <name>`
Stops a running virtual machine instance (`debian`, `fedora`, `windows`) using its PID file.
- Sends `SIGTERM` and waits for clean shutdown.
- Falls back to `SIGKILL` if the VM does not stop within 10 seconds.
- Removes the stale PID file.

### `reset.sh <name>`
Stops the named VM and discards its copy-on-write overlay and instance state (`overlay.qcow2`, `seed.iso`, `port.txt`, `qemu.pid`).
- The base image in `VM_DIR/base` remains untouched.
- The next invocation of `up.sh` or `windows.sh` starts from a pristine, clean OS state.
- Works identically for `debian`, `fedora`, and `windows`.

### `windows.sh <path-to-evaluation-iso>`
Manages the Windows test VM.
- **First Run**:
  - Requires the path to a Windows evaluation ISO:
    ```bash
    scripts/vm/windows.sh /path/to/windows_evaluation.iso
    ```
  - Creates a 64 GB qcow2 base disk (`VM_DIR/base/windows-base.qcow2`).
  - Boots the installer with a display window.
  - **No VirtIO drivers required**: Uses IDE/SATA disk emulation (`-drive if=ide`) and the Intel e1000 network adapter (`-device e1000`), both of which are supported natively by the installer without additional driver media.
  - The maintainer completes the installation and shuts down the guest.
- **Subsequent Runs**:
  - Automatically creates and boots a copy-on-write overlay (`overlay.qcow2`).
  - Boots with a display window and user-mode networking.
  - Forwards guest RDP (port 3389) to a dynamically chosen host port.
  - Running `scripts/vm/reset.sh windows` discards the overlay while preserving the installed base disk.

---

## Workflow Guide

### 1. Initial Setup

Fetch and verify Linux base images:
```bash
scripts/vm/fetch-images.sh --yes
```

### 2. Testing Debian Packages (.deb)

1. Start the Debian VM:
   ```bash
   scripts/vm/up.sh debian
   ```
2. Copy the `.deb` release package into the VM:
   ```bash
   scripts/vm/copy.sh debian opensase_<version>_amd64.deb
   ```
3. SSH into the VM:
   ```bash
   scripts/vm/ssh.sh debian
   ```
4. Perform testing as outlined in [manual-checklist.md](../../docs/testing/manual-checklist.md).
5. When finished, exit SSH and reset the VM:
   ```bash
   scripts/vm/reset.sh debian
   ```

### 3. Testing Fedora Packages (.rpm)

1. Start the Fedora VM:
   ```bash
   scripts/vm/up.sh fedora
   ```
2. Copy the `.rpm` release package into the VM:
   ```bash
   scripts/vm/copy.sh fedora opensase-<version>-1.x86_64.rpm
   ```
3. SSH into the VM:
   ```bash
   scripts/vm/ssh.sh fedora
   ```
4. Perform testing and reset when finished:
   ```bash
   scripts/vm/reset.sh fedora
   ```

### 4. Testing Windows Packages (.msi)

1. Set up the Windows base disk (performed once):
   ```bash
   scripts/vm/windows.sh /path/to/evaluation.iso
   ```
2. Start the Windows test overlay:
   ```bash
   scripts/vm/windows.sh
   ```
3. Install and verify the `.msi` package in the graphical display window.
4. When finished, shut down the VM and reset the overlay:
   ```bash
   scripts/vm/reset.sh windows
   ```
