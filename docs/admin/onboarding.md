# Onboarding wizard

The **Get started** page (`/onboarding`) provides a guided 8-step wizard to initialize a tenant,
configure identity integration, establish baseline security policies, deploy a private access
connector, and enroll the first device.

Access the wizard by clicking **Get started** in the admin portal navigation.

```mermaid
flowchart LR
    W[1. Welcome] --> O[2. Organisation]
    O --> S[3. Sign-in]
    S --> P[4. First policy]
    P --> D[5. DNS]
    D --> C[6. Private apps]
    C --> Dev[7. Devices]
    Dev --> Done[8. Done]
```

## Step 1: Welcome

The welcome step introduces the onboarding workflow.

- **Super-admin view:** Displays an overview of deployment health from `GET /v1/admin/status`,
  including reporting Edges, certificates expiring within 14 days, and the state of the audit hash chain.
- **Tenant admin view:** Displays a welcome summary for the selected tenant.

Click **Continue** to proceed.

## Step 2: Organisation

Select or create the tenant organisation.

- **Super-admin:** Enter an **Organisation name** (e.g. `Acme Corporation`) and an optional **Organisation ID**
  (e.g. `acme`). Click **Create organisation** (`POST /v1/admin/tenants`). Alternatively, select an existing tenant
  from the dropdown.
- **Tenant admin:** Confirms the active tenant name and ID.

## Step 3: Sign-in (SSO)

Configure OpenID Connect (OIDC) single sign-on for administrator and user authentication
([ADR-0031](../adr/0031-portal-oidc-sign-in.md)).

1. Enter the identity provider details:
    - **Issuer URL:** The OIDC discovery endpoint (e.g. `https://auth.example.com`).
    - **Client ID:** The client ID registered in your identity provider.
    - **Client Secret:** The client secret (saved securely, never displayed again).
2. Configure **Group roles** mapping IdP groups to OpenSASE tenant roles:
    - Map group names (e.g. `security-admins`) to `admin`, `policy-editor`, or `viewer`.
    - If no mapping is entered, group `admin` defaults to role `admin`.
3. Click **Save and continue** (`PUT /v1/admin/tenants/{t}/oidc`).
4. To verify the integration, click **Test sign-in** to launch the authorization flow in a new browser tab.

To use device provisioning keys without an identity provider, click **Skip this step**.

## Step 4: First policy

Select and apply a baseline firewall policy for the tenant:

- **Recommended:**
    - Default action: `allow`.
    - Web categories blocked: `malware` and `phishing` ([ADR-0022](../adr/0022-web-categories-ut1.md)).
    - SafeSearch: forced on search engines and video sites (`safeSearch: true`, [ADR-0025](../adr/0025-safesearch.md)).
- **Permissive:**
    - Default action: `allow`.
    - Web categories blocked: none.
    - SafeSearch: disabled (`safeSearch: false`).

Click **Save and continue** to write the initial policy via `PUT /v1/admin/tenants/{t}/policy`.

## Step 5: DNS

Configure the Edge DNS resolver and domain protection ([DNS security](../operations/dns-security.md)):

1. **Internal zone:** Specify an internal domain name (e.g. `corp.internal`). The Edge resolver
   automatically answers `<device>.<user>.<zone>` with each device's tunnel address.
2. **Redirect plain queries:** Enable **Redirect plain DNS queries** (`dns.redirectQueries: true`).
   The Edge will intercept plain UDP port 53 DNS directed to external resolvers and apply the tenant policy.
3. **Malware blocklist:** Enable the built-in malware distribution blocklist (`builtinLists: ["malware"]`).

Click **Save and continue** to update the tenant policy.

## Step 6: Private apps (ZTNA)

Deploy an outbound-only Connector to broker zero-trust access to internal applications ([ADR-0013](../adr/0013-ztna-connector.md)):

1. Enter a **Connector name** (default `connector-1`) with group `default`.
2. Click **Create connector** (`POST /v1/admin/tenants/{t}/connectors`).
3. Copy the generated **provisioning key**. This key is valid for 24 hours, is single-use, and is shown only once.
4. Start the connector using Docker or the binary:

    ```bash
    connector -control https://<controlplane>:9443#sha256=<root-pin> \
      -key-file /run/secrets/connector_key \
      -state /var/lib/opensase-connector
    ```

5. The wizard polls every 5 seconds. When the connector dials an Edge broker, the step marks complete.

If private applications are not needed immediately, click **Skip this step**.

## Step 7: Devices

Enroll your first client device:

1. Enter a **User ID** (e.g. `admin`) and click **Generate key** (`POST /v1/admin/tenants/{t}/provisioning-keys`).
2. The wizard displays:
    - The one-time provisioning key (valid for 24 hours, 1 use).
    - An **enrollment QR code** encoding the deep link:
      `opensase://enroll?control=<control-url#sha256=pin>&key=<key>`
    - The CLI enrollment command for Linux or Windows:

      ```bash
      opensase enroll -control https://<controlplane>:9443#sha256=<pin>
      ```

3. Open the Android or desktop client, scan the QR code or run the command, and complete enrollment.
4. The wizard polls every 5 seconds and updates when the enrolled device appears in the tenant inventory.

## Step 8: Done

The final screen displays a verification summary confirming each configured subsystem:

- Organisation created and active.
- Identity provider sign-in configured (or skipped).
- Baseline policy and SafeSearch applied.
- Internal DNS zone and malware blocklist enabled.
- Connector connected (or skipped).
- First device enrolled and verified.

Click the shortcut buttons to navigate directly to the **Overview**, **Policy editor**, **Devices**,
or **Private apps** screens.
