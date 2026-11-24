# OpenSASE Desktop Daemon (`opensased`)

`opensased` is the background daemon that manages the OpenSASE client engine (`mobile.Engine`), configures local TUN interfaces and system routing, and exposes a secure local HTTP API over a Unix domain socket on Unix platforms (and Windows named pipe in slice B2). A desktop UI (such as the Flutter desktop client) communicates with this daemon to control enrollment, connection status, and observe security events and traffic flows.

The UI process runs under normal user privileges and never holds private keys, session tokens, or WireGuard credentials. All cryptographic operations and privileged network routing remain contained inside `opensased`.

---

## Linux Installation and Setup

### 1. Install the Binary and Service Unit

Copy the daemon binary and systemd service unit to their system locations:

```bash
install -m 0755 bin/opensased /usr/bin/opensased
install -m 0644 deploy/desktop/linux/opensased.service /etc/systemd/system/opensased.service
```

### 2. Configure Access Group

Create the `opensase` system group and add desktop users who should have permission to control the client:

```bash
groupadd opensase
usermod -aG opensase $USER
```

*Note: Group membership updates take effect on next login or via `newgrp opensase`.*

### 3. Enable and Start the Service

Reload systemd configurations and enable the daemon:

```bash
systemctl daemon-reload
systemctl enable --now opensased
```

Verify service status:

```bash
systemctl status opensased
```

---

## Windows Installation and Setup

### 1. Place Binaries and Drivers

Copy `opensased.exe` and the signed `wintun.dll` (from the official Wintun distribution) to the application directory:

```powershell
mkdir "C:\Program Files\OpenSASE"
copy opensased.exe "C:\Program Files\OpenSASE\"
copy wintun.dll "C:\Program Files\OpenSASE\"
```

### 2. Install the Windows Service

Open an elevated Command Prompt or PowerShell (Run as Administrator) and register the service:

```cmd
cd "C:\Program Files\OpenSASE"
opensased.exe install
```

This registers the service `OpenSASE` (display name: "OpenSASE client") configured for automatic startup, with recovery actions that restart the service after 5 seconds up to 3 times on failure, and registers the Windows event log source `OpenSASE`.

To uninstall at any time:
```cmd
opensased.exe uninstall
```

### 3. Start the Service

Start the service via the Service Control Manager or command line:

```cmd
sc start OpenSASE
```

Or verify status:
```cmd
sc query OpenSASE
```

For console debugging from an elevated command prompt without running through the SCM:
```cmd
opensased.exe run
```

---

## Local API Specification

The daemon serves a local JSON HTTP API over:
- Linux/Unix: Unix domain socket at `/run/opensase/opensased.sock`
- Windows: Named pipe at `\\.\pipe\opensase`

### Access Control

#### Linux/Unix
1. **Filesystem and Group Permissions:**
   The socket directory `/run/opensase` is created with mode `0750` and the socket file with mode `0660`, owned by `root:opensase`. If the `opensase` group does not exist at startup, permissions fall back to root-only `0600` with a warning log.
2. **Peer Credential Verification (`SO_PEERCRED`):**
   Every incoming connection over the Unix socket is inspected for its peer UID using `SO_PEERCRED`. Only root (UID 0) or users belonging to the configured group (default `opensase`) are permitted; all other callers receive HTTP 403 Forbidden. Enroll and unenroll operations are restricted to root or the daemon's user.

#### Windows
1. **Named Pipe Security Descriptor (SDDL):**
   The pipe is created at `\\.\pipe\opensase` with SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`:
   - `SYSTEM` (`SY`) and `Administrators` (`BA`) receive Generic All (`GA`) access.
   - `Interactive Users` (`IU`) receive Generic Read and Generic Write (`GRGW`) access, allowing the desktop UI of the signed-in interactive user to connect.
   - Remote or network callers receive no access.
2. **Role-Based Privilege Separation (Who May Call What):**
   - **Interactive Users:** May query client status (`GET /v1/status`), view recent traffic flows (`GET /v1/flows`), stream events (`GET /v1/events`), and initiate tunnel connections or disconnections (`POST /v1/connect`, `POST /v1/disconnect`).
   - **Administrators Only:** Device enrollment (`POST /v1/enroll`) and unenrollment (`POST /v1/unenroll`) require Administrator privileges (membership in `S-1-5-32-544` and an elevated token). Calls from unprivileged interactive users receive HTTP 403 Forbidden.
   - **State Directory ACL:** The state directory (`%ProgramData%\OpenSASE`) is created with a protected DACL restricted to `SYSTEM` and `Administrators`.

#### Common Protections
1. **Host Header Defense:**
   To defend against DNS rebinding if a local proxy or browser ever accesses the endpoint, requests whose `Host` header is neither `localhost` (with optional port) nor empty are rejected with HTTP 403 Forbidden.
2. **Request Constraints:**
   Request bodies are limited to 64 KiB. JSON decoders reject unknown fields (HTTP 400).
3. **Credential Safety:**
   Provisioning keys and session secrets are never returned in responses, included in error messages, or written to log files.

---

### Endpoints

#### `GET /v1/status`
Returns the engine status JSON augmented with the current daemon connection state.

**Response (HTTP 200 OK):**
```json
{
  "state": "connected",
  "connected": true,
  "enrolled": true,
  "deviceId": "dev-01a2b3c4",
  "edge": "edge-fra-1",
  "network": "ethernet",
  "snapshotVersion": 4,
  "stale": false,
  "pq": true,
  "kex": "X25519MLKEM768",
  "epoch": 2,
  "lastHandshake": 1764000000,
  "txBytes": 1048576,
  "rxBytes": 2097152
}
```

#### `POST /v1/connect`
Connects the tunnel: establishes a post-quantum session, allocates the TUN device, configures interface IP addresses, installs split-default routing and bypass host routes, and applies local DNS policies.

- **Idempotent:** Calling `POST /v1/connect` when already connected returns HTTP 200 OK without reinitializing the interface.

**Response (HTTP 200 OK):**
```json
{
  "connected": true
}
```

#### `POST /v1/disconnect`
Disconnects the active tunnel: undoes installed routing table entries and DNS modifications, closes the TUN adapter, and stops the client engine.

- **Idempotent:** Calling `POST /v1/disconnect` when already disconnected returns HTTP 200 OK.

**Response (HTTP 200 OK):**
```json
{
  "connected": false
}
```

#### `POST /v1/enroll`
Enrolls the device with the Control Plane using a provisioning key.

- **Constraint:** Refused with HTTP 409 Conflict if called while the tunnel is connected.
- **Security:** Provisioning keys are never echoed in logs or responses.

**Request Body:**
```json
{
  "controlUrl": "https://controlplane.example.internal:8443",
  "provisioningKey": "secret-key-material",
  "deviceName": "desktop-workstation"
}
```

**Response (HTTP 200 OK):**
```json
{
  "enrolled": true
}
```

#### `POST /v1/unenroll`
Disconnects any active tunnel, deletes enrollment keys and certificates from the state directory, and resets local state.

**Response (HTTP 200 OK):**
```json
{
  "enrolled": false
}
```

#### `GET /v1/flows?limit=N`
Returns the recent flow records captured by the client firewall and DNS filtering components, newest first.

- **Query Parameters:** `limit` (integer, default 50).

**Response (HTTP 200 OK):**
```json
[
  {
    "start": "2026-11-24T12:00:00Z",
    "flow": {
      "app": "browser",
      "network": "ethernet",
      "protocol": "tcp",
      "dstIp": "198.51.100.10",
      "dstPort": 443,
      "domain": "app.example.internal"
    },
    "decision": {
      "action": "allow",
      "ruleId": "rule-corp-access",
      "layer": "tenant"
    },
    "bytesOut": 1420,
    "bytesIn": 4096,
    "where": "device",
    "deviceId": "dev-01a2b3c4"
  }
]
```

#### `GET /v1/events`
Server-Sent Events (SSE) stream (`text/event-stream`).

- **Ring Buffer Replay:** Upon connecting, the daemon first replays the last 200 engine events in FIFO order, followed by real-time event streaming.
- **Concurrency Limit:** At most 8 concurrent event streams are supported. Subsequent requests receive HTTP 429 Too Many Requests until an active stream disconnects.

**Stream Format:**
```
event: state
data: {"state":"connected","error":""}

event: flow
data: {"start":"2026-11-24T12:00:00Z","flow":{...},"decision":{...}}
```

---

## Errors

All error responses return a JSON object with an `error` message string:

```json
{
  "error": "cannot enroll while connected"
}
```
