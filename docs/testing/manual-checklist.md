# OpenSASE Manual Release Verification Checklist

This checklist defines the manual platform testing procedure required prior to publishing any OpenSASE release. As specified in the release quality bar ([docs/release-quality-bar.md](../release-quality-bar.md)), every release must pass automated continuous integration as well as this manual checklist on a single maintainer host machine.

---

## Environment Matrix

The manual release test environment covers five target platforms:

| Target Platform | Package Format | Execution Environment | Network Route to Host |
|-----------------|----------------|-----------------------|-----------------------|
| Debian          | `.deb`         | QEMU / KVM VM         | `10.0.2.2` (user net) |
| Fedora          | `.rpm`         | QEMU / KVM VM         | `10.0.2.2` (user net) |
| Arch Linux      | `.pkg.tar.zst` | Native host           | `127.0.0.1` / local   |
| Windows         | `.msi`         | QEMU / KVM VM         | `10.0.2.2` (user net) |
| Android         | `.apk`         | Android emulator AVD  | `10.0.2.2` (emulator) |

---

## Prerequisites: Starting the Central Stack on the Host

All client test environments connect to an all-in-one quick start image running on the Linux host. The quick start container hosts both the Control Plane (HTTPS on port 9443) and an Edge (terminating post-quantum WireGuard tunnels on UDP port 51820).

Because QEMU user-mode networking and the Android emulator route host loopback traffic through the virtual gateway `10.0.2.2`, set `OPENSASE_PUBLIC_HOST=10.0.2.2`.

### 1. Launch Quick Start Container

Run the quick start container on your host machine (see [deploy/release/README.md](../containers.md)):

```bash
${CONTAINER_TOOL:-container-engine} run -d --name opensase --restart unless-stopped \
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
  --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -p 9443:9443 -p 8443:8443 -p 8444:8444 -p 51820:51820/udp \
  -e OPENSASE_PUBLIC_HOST=10.0.2.2 \
  -v opensase-data:/data \
  opensase-quickstart:<version>
```

### 2. Extract Secrets and Connection Parameters

Extract the connection details and enrollment provisioning key:

```bash
# Display connection variables
${CONTAINER_TOOL:-container-engine} exec opensase cat /data/quickstart.env

# Save the provisioning key to a private file for transfer to VMs
(umask 077; ${CONTAINER_TOOL:-container-engine} exec opensase sed -n 's/^PROVISIONING_KEY=//p' /data/quickstart.env > provisioning.key)
```

Note the values:
- `CONTROL_URL`: Pinned Control Plane URL (e.g. `https://10.0.2.2:9443#sha256=<ca-hash>`). For Arch Linux native testing on the host itself, substitute `10.0.2.2` with `127.0.0.1`.
- `ENROLL_URI`: Full enrollment URI (`opensase://enroll?...`) used for the Android client.
- `PROVISIONING_KEY`: One-time key used by `opensase enroll`.

---

## Platform Checklist Procedures

Execute the following verification steps on each platform.

---

### Platform 1: Debian VM (`.deb`)

#### Step 1: Boot VM
Start the Debian test VM:
```bash
scripts/vm/up.sh debian
```
Note the allocated SSH port (default: 2222).

#### Step 2: Copy Package and Install
Copy the release package and provisioning key into the VM:
```bash
scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  opensase_<version>_amd64.deb provisioning.key tester@127.0.0.1:/tmp/
```

SSH into the VM:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null tester@127.0.0.1
```

Install the Debian package:
```bash
sudo apt update
sudo apt install -y /tmp/opensase_<version>_amd64.deb
```
Verify that the `opensased` daemon started automatically:
```bash
systemctl is-active opensased
```

#### Step 3: Enrol
Enrol the device against the Control Plane (at `10.0.2.2:9443`):
```bash
sudo opensase enroll \
  -control "$(grep '^CONTROL_URL=' /tmp/quickstart.env 2>/dev/null || echo 'https://10.0.2.2:9443#sha256=<ca-hash>')" \
  -key-file /tmp/provisioning.key
```

Connect the tunnel:
```bash
opensase connect
```

#### Step 4: Verify Status and Post-Quantum Handshake
Check client daemon status:
```bash
opensase status
```
Verify the output:
- `"state": "connected"`
- `"connected": true`
- `"pq": true`
- `"kex": "X25519MLKEM768"` (confirms post-quantum hybrid key exchange)

#### Step 5: Traffic Flow Verification
Verify traffic passes through the tunnel to an external destination:
```bash
curl -I https://example.com
```
Confirm HTTP 200 response and incrementing `txBytes` / `rxBytes` in `opensase status`.

#### Step 6: Policy Category Block Verification
Check that a domain belonging to a blocked category name (e.g. `malware.example` or configured category):
```bash
curl -I https://malware.example || true
```
Verify the connection is blocked. Check recent flow records to verify enforcement:
```bash
opensase flows -n 5
```
Confirm the flow entry shows `"action": "block"` with the corresponding policy category name.

#### Step 7: Disconnect
Disconnect the tunnel:
```bash
opensase disconnect
opensase status
```
Confirm `"connected": false`.

#### Step 8: Uninstall
Purge the Debian package:
```bash
sudo apt purge -y opensase
```

#### Step 9: Verify Service and Files are Removed
Verify the systemd service is removed and not running:
```bash
systemctl status opensased || true
```
(Expected: `Unit opensased.service could not be found` or inactive).

Verify binaries and state directories are removed:
```bash
! test -f /usr/bin/opensased
! test -f /usr/bin/opensase
! test -d /var/lib/opensase
```

Exit the VM and clean up:
```bash
exit
scripts/vm/reset.sh debian
```

---

### Platform 2: Fedora VM (`.rpm`)

#### Step 1: Boot VM
Start the Fedora test VM:
```bash
scripts/vm/up.sh fedora
```
Note the allocated SSH port (default: 2223).

#### Step 2: Copy Package and Install
Copy the release package and provisioning key into the VM:
```bash
scp -P 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  opensase-<version>-1.x86_64.rpm provisioning.key tester@127.0.0.1:/tmp/
```

SSH into the VM:
```bash
ssh -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null tester@127.0.0.1
```

Install the RPM package:
```bash
sudo dnf install -y /tmp/opensase-<version>-1.x86_64.rpm
```
Verify the daemon is active:
```bash
systemctl is-active opensased
```

#### Step 3: Enrol
Enrol the device:
```bash
sudo opensase enroll \
  -control "https://10.0.2.2:9443#sha256=<ca-hash>" \
  -key-file /tmp/provisioning.key
```

Connect the tunnel:
```bash
opensase connect
```

#### Step 4: Verify Status and Post-Quantum Handshake
Check status:
```bash
opensase status
```
Verify:
- `"state": "connected"`
- `"connected": true`
- `"pq": true`
- `"kex": "X25519MLKEM768"`

#### Step 5: Traffic Flow Verification
Verify external network connectivity:
```bash
curl -I https://example.com
```

#### Step 6: Policy Category Block Verification
Attempt connection to a domain under a blocked category name:
```bash
curl -I https://malware.example || true
```
Check recent flows:
```bash
opensase flows -n 5
```
Verify an entry records `"action": "block"`.

#### Step 7: Disconnect
Disconnect the tunnel:
```bash
opensase disconnect
opensase status
```
Confirm `"connected": false`.

#### Step 8: Uninstall
Remove the RPM package:
```bash
sudo dnf remove -y opensase
```

#### Step 9: Verify Service and Files are Removed
Verify the systemd service is inactive and removed:
```bash
systemctl status opensased || true
```
Verify binaries are removed:
```bash
! test -f /usr/bin/opensased
! test -f /usr/bin/opensase
```

Exit the VM and clean up:
```bash
exit
scripts/vm/reset.sh fedora
```

---

### Platform 3: Arch Linux Native (package)

Executed natively on the maintainer Linux host.

#### Step 1: Install Package
Install the package archive using `pacman`:
```bash
sudo pacman -U --noconfirm opensase-<version>-1-x86_64.pkg.tar.zst
```
Verify the daemon is active:
```bash
sudo systemctl is-active opensased
```

#### Step 2: Enrol
Enrol the host (for native host testing, use `127.0.0.1`):
```bash
sudo opensase enroll \
  -control "https://127.0.0.1:9443#sha256=<ca-hash>" \
  -key-file provisioning.key
```

Connect the tunnel:
```bash
opensase connect
```

#### Step 3: Verify Status and Post-Quantum Handshake
Check status:
```bash
opensase status
```
Verify:
- `"state": "connected"`
- `"connected": true`
- `"pq": true`
- `"kex": "X25519MLKEM768"`

#### Step 4: Traffic Flow Verification
Verify external network connectivity through the tunnel:
```bash
curl -I https://example.com
```

#### Step 5: Policy Category Block Verification
Check that a domain belonging to a blocked category name is blocked:
```bash
curl -I https://malware.example || true
opensase flows -n 5
```
Verify the blocked decision is logged with the category name.

#### Step 6: Disconnect
Disconnect the tunnel:
```bash
opensase disconnect
opensase status
```
Confirm `"connected": false`.

#### Step 7: Uninstall
Uninstall the package:
```bash
sudo pacman -R --noconfirm opensase
```

#### Step 8: Verify Service and Files are Removed
Verify that the systemd service is stopped:
```bash
systemctl status opensased || true
```
Verify binaries are deleted:
```bash
! test -f /usr/bin/opensased
! test -f /usr/bin/opensase
```

---

### Platform 4: Windows VM (MSI)

#### Step 1: Boot Windows VM
Start the Windows VM with graphical display:
```bash
scripts/vm/windows.sh
```

#### Step 2: Install Package
Inside the Windows guest:
1. Open Command Prompt as Administrator.
2. Run the installer:
   ```cmd
   msiexec /i opensase-<version>-x64.msi
   ```
3. Complete the installation wizard.
4. Verify the Windows service is running:
   ```cmd
   sc query OpenSASE
   ```
   (State should indicate `RUNNING`).

#### Step 3: Enrol
From an elevated Command Prompt or using the desktop application:
```cmd
"C:\Program Files\OpenSASE\opensase-cli.exe" enroll -control https://10.0.2.2:9443#sha256=<ca-hash> -key-file C:\path\to\provisioning.key
```
Connect the tunnel:
```cmd
"C:\Program Files\OpenSASE\opensase-cli.exe" connect
```

#### Step 4: Verify Status and Post-Quantum Handshake
Check client status:
```cmd
"C:\Program Files\OpenSASE\opensase-cli.exe" status
```
Verify:
- State indicates connected.
- Negotiated key exchange indicates `X25519MLKEM768`.

#### Step 5: Traffic Flow Verification
Open a browser inside the Windows VM and navigate to:
```
https://example.com
```
Confirm the page loads successfully through the post-quantum tunnel.

#### Step 6: Policy Category Block Verification
In the browser, attempt to navigate to a site under a blocked category name (e.g. `http://malware.example`).
Verify that the request is blocked.
Check flows from the command line:
```cmd
"C:\Program Files\OpenSASE\opensase-cli.exe" flows -n 5
```
Verify the flow decision records `block` for the category.

#### Step 7: Kill Switch Verification
Verify that the dynamic Windows Filtering Platform (WFP) kill switch enforces traffic isolation:

1. **Connected browsing**:
   Confirm that when connected, normal web browsing functions through the post-quantum tunnel.
2. **External DNS restriction**:
   While connected, verify that a DNS query to a public resolver on port 53 outside the tunnel is blocked:
   ```cmd
   nslookup example.com 9.9.9.9
   ```
   Confirm the request times out or is refused, whereas name resolution via the configured tunnel resolver succeeds.
3. **Graceful disconnect**:
   Stop the tunnel:
   ```cmd
   "C:\Program Files\OpenSASE\opensase-cli.exe" disconnect
   ```
   Confirm that standard web browsing works again outside the tunnel.
4. **Crash recovery (fail-open window)**:
   Reconnect the tunnel:
   ```cmd
   "C:\Program Files\OpenSASE\opensase-cli.exe" connect
   ```
   Kill `opensased.exe` in Task Manager (or run `taskkill /F /IM opensased.exe`). Verify that traffic fails open while the service restarts (expected, ADR decision #49: the operating system destroys dynamic WFP sessions when the process terminates).
5. **Emergency recovery**:
   Verify that stopping the service via the Service Control Manager clears the kill switch:
   ```cmd
   sc stop OpenSASE
   ```
   `sc stop OpenSASE` is the emergency path to remove all filters and restore connectivity.

#### Step 8: Disconnect
Disconnect the client:
```cmd
"C:\Program Files\OpenSASE\opensase-cli.exe" disconnect
"C:\Program Files\OpenSASE\opensase-cli.exe" status
```
Confirm state indicates disconnected.

#### Step 9: Uninstall
Uninstall the MSI package:
```cmd
msiexec /x opensase-<version>-x64.msi
```

#### Step 10: Verify Service and Files are Removed
Verify that the Windows service is removed:
```cmd
sc query OpenSASE
```
(Expected: `[SC] EnumQueryServicesStatus:OpenService FAILED 1060: The specified service does not exist as an installed service.`).

Verify the application directory is cleanly removed:
```cmd
dir "C:\Program Files\OpenSASE"
```
(Expected: `The system cannot find the path specified`).

Shut down the VM and reset overlay:
```bash
scripts/vm/reset.sh windows
```

---

### Platform 5: Android Emulator (APK)

#### Step 1: Start Emulator
Launch the Android AVD `opensase` (API 35, x86_64) using KVM acceleration (as documented in `CLAUDE.md`):
```bash
emulator -avd opensase -no-window -no-audio -no-snapshot &
adb wait-for-device
```

#### Step 2: Install Package
Install the signed release APK:
```bash
adb install -r opensase-<version>.apk
```

#### Step 3: Enrol
1. Launch the OpenSASE Android app:
   ```bash
   adb shell monkey -p eu.opensase.opensase -c android.intent.category.LAUNCHER 1
   ```
2. In the app onboarding screen, paste the `ENROLL_URI` (`opensase://enroll?...`) or configure:
   - Control URL: `https://10.0.2.2:9443#sha256=<ca-hash>`
   - Provisioning Key: content from `provisioning.key`
3. Tap **Enrol Device**.
4. When prompted by Android for VPN permission, accept the VPN dialog.
5. Tap **Connect**.

#### Step 4: Verify Status and Post-Quantum Handshake
In the application status screen:
- Connection state shows **Connected**.
- Key exchange displays **X25519MLKEM768**.

#### Step 5: Traffic Flow Verification
Open a web browser inside the Android emulator:
```bash
adb shell am start -a android.intent.action.VIEW -d "https://example.com"
```
Verify the site loads cleanly over the tunnel.

#### Step 6: Policy Category Block Verification
Attempt navigation to a domain belonging to a blocked category name:
```bash
adb shell am start -a android.intent.action.VIEW -d "https://malware.example"
```
Verify the blocked alert is displayed and the connection is dropped. Open the app flow view and confirm the blocked event.

#### Step 7: Disconnect
In the app UI, toggle the connect switch to **Disconnected**. Verify status shows disconnected.

#### Step 8: Uninstall
Uninstall the application:
```bash
adb uninstall eu.opensase.opensase
```

#### Step 9: Verify Service and Files are Removed
Verify the application package is completely removed:
```bash
adb shell pm list packages | grep opensase || true
```
(Expected: empty output).
Verify no lingering VPN service profiles remain.

---

## Release Sign-Off Results Table Template

Copy and fill this template for each release candidate:

| Platform | Package Version | Result (Pass / Fail) | Tested By | Date (YYYY-MM-DD) | Notes |
|---|---|---|---|---|---|
| Debian VM (`.deb`) | `1.0.0` | Pass | Maintainer | 2026-11-25 | Clean install, X25519MLKEM768 verified, purge verified |
| Fedora VM (`.rpm`) | `1.0.0` | Pass | Maintainer | 2026-11-25 | Clean install, X25519MLKEM768 verified, remove verified |
| Arch Linux native (`.pkg.tar.zst`) | `1.0.0` | Pass | Maintainer | 2026-11-25 | Native install, X25519MLKEM768 verified, pacman -R verified |
| Windows VM (`.msi`) | `1.0.0` | Pass | Maintainer | 2026-11-25 | IDE+e1000 emulation, X25519MLKEM768 verified, clean uninstall |
| Android emulator (`.apk`) | `1.0.0` | Pass | Maintainer | 2026-11-25 | AVD opensase, X25519MLKEM768 verified, uninstall verified |

---

## Gate Checklist Summary

Before tagging the final release commit:
- [ ] Automated CI and security tests passed.
- [ ] Debian VM test passed.
- [ ] Fedora VM test passed.
- [ ] Arch Linux native test passed.
- [ ] Windows VM test passed.
- [ ] Android emulator test passed.
- [ ] Results table recorded in release tracking issue.
