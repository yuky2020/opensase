# Device posture settings and monitoring

The OpenSASE admin portal provides controls to configure posture verification baselines and monitor the compliance of enrolled endpoints ([ADR-0035](../adr/0035-device-posture.md)).

For comprehensive operational details on how posture signals are collected by client platforms and evaluated by the Control Plane, see the [Device posture operational guide](../operations/posture.md).

```mermaid
flowchart LR
    Dev[Client device] -->|POST /v1/posture| CP[Control Plane]
    Admin[Admin portal] -->|PUT /v1/admin/tenants/{t}/policy| CP
    Admin -->|GET /v1/admin/tenants/{t}/devices/{d}/posture| CP
    CP -->|Posture chip & report| Admin
    CP -->|Standard or restricted snapshot| Dev
```

## Configuring tenant posture policy

The posture configuration is managed under the **Device posture** section of the [Policy editor](policy.md) (`/policy`). Changes are saved atomically as part of the tenant policy with optimistic concurrency (`If-Match` ETag header).

### Settings

| Setting | Field | Description |
|---|---|---|
| **Minimum OS versions** | `minOsVersion` | Minimum required operating system version per platform (`android`, `windows`, `linux`, `macos`, `ios`). Evaluated at enrolment and on every report. |
| **Minimum client version** | `minClientVersion` | Minimum OpenSASE client software version required across all platforms. |
| **Required checks** | `require` | Mandatory security checks that endpoints must satisfy. Options: `diskEncryption`, `screenLock`, `firewall` (Windows only), and `managed` (work profile or domain/MDM joined). |
| **Restrict non-compliant devices** | `restrict` | When toggled on, devices failing any posture check receive a restricted snapshot allowing only remediation domains instead of standard access rules. |
| **Remediation domains** | `remediationDomains` | List of hostnames (e.g. corporate help pages or OS update services) that non-compliant devices can reach while restricted. Managed via chips in the editor. |

### Rule and private app scoping

Both tenant firewall rules and ZTNA private applications can restrict access by device posture using the **Posture** dropdown:

- **Any posture (`""`)**: Default. Matches devices regardless of posture compliance.
- **Compliant only (`"compliant"`)**: Rule or private application is available only to devices passing all posture requirements.
- **Non-compliant only (`"noncompliant"`)**: Applies only to devices failing one or more posture requirements (e.g., to route non-compliant devices to custom remediation portals).

## Monitoring device posture

On the **Devices** screen (`/devices`), administrators can monitor the real-time compliance state of all enrolled endpoints.

### Posture status chips

Each row in the devices table displays a posture chip:

- **Compliant (Green)**: The endpoint has submitted a posture report and satisfies all configured posture checks.
- **N checks failing (Red)**: The endpoint is failing one or more posture requirements (e.g., outdated OS or disabled screen lock).
- **No report (Outline)**: No posture report has been received yet for the device (such as newly enrolled devices within their initial grace period).

### Detailed posture report

Tapping any posture chip opens a dialog showing the full posture report:

- **Operating system and OS version**: The reported platform and version string.
- **Client version**: The installed OpenSASE app version.
- **Disk encryption**: Whether disk encryption is active on the device.
- **Screen lock**: Whether a device PIN, password, or biometric lock screen is configured.
- **Host firewall**: Whether the host firewall is enabled (Windows).
- **Managed status**: Whether the device runs under a work profile or MDM.
- **Timestamps**: Device boot time, report collection time, and submission time.
- **Failing checks**: Specific checks currently failing on the device, or `None` if compliant.
