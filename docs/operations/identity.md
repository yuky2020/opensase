# Users, sign-in and provisioning

## Enrol with the identity provider

With OIDC configured for the tenant (see the portal sign-in), users enrol by signing in
instead of typing a provisioning key (issue #68):

```bash
sudo opensase enroll -control https://controlplane.example.com:9443 -sso <tenant>
```

1. The CLI prints a URL. Open it in a browser on the same computer and sign in.
2. The identity provider returns to the Control Plane.
3. The Control Plane creates the user on first sign-in, from the email claim, and stores the
   groups claim.
4. It sends the CLI a single-use provisioning key, valid 5 minutes, through a loopback URL
   (`http://127.0.0.1:<port>/callback`).
5. The CLI enrols with that key.

The Android app uses the return URL `opensase://enroll`.

Provisioning keys stay for servers, Workload Gateways, Connectors, kiosks and tenants
without an identity provider.

## Rules for users and groups

A tenant rule can be limited to some users (ID or email) or identity provider groups:

```json
{"id": "sales-crm", "priority": 50, "action": "allow", "groups": ["sales"],
 "match": {"domains": ["crm.example.com"]}}
```

The Control Plane keeps such a rule only in the snapshots of matching users. A group change
(at sign-in or through SCIM) rebuilds the members' snapshots.

## SCIM 2.0

The identity provider can keep users and groups in sync with SCIM 2.0:

1. Create the tenant's SCIM token (admin role). It is shown once, together with the base
   URL:

    ```bash
    curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
      https://controlplane.example.com:9443/v1/admin/tenants/<tenant>/scim-token
    ```

2. Enter the base URL `https://controlplane.example.com:9443/scim/v2/<tenant>` and the
   token in the identity provider's SCIM settings.

What the endpoint supports:

- `Users` and `Groups`: create, read, replace, patch and delete.
- The filters `userName eq`, `externalId eq` and `displayName eq`.
- Paging with `startIndex` and `count`.

What provisioning changes do:

- **Deactivate a user** (`active: false`) or **delete it**: every device of the user is
  revoked at once, and the user can no longer enrol.
- **Change a group's members**: the members' snapshots are rebuilt.

!!! warning "Post-quantum TLS"
    The Control Plane accepts only TLS 1.3 with X25519MLKEM768. The identity provider's
    SCIM client must support it: current Go, Java and OpenSSL 3.5 based servers do, many
    hosted identity services do not yet.
