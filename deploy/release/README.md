# Running Released OpenSASE Container Images

This directory describes how to run released OpenSASE container images published to GitHub Container Registry (`ghcr.io`).

## Images Overview

Container images are published under `ghcr.io/yuky2020/opensase-<component>:<version>`:

- `ghcr.io/yuky2020/opensase-controlplane:<version>`: Multi-tenant Control Plane, PKI management, policy snapshots, and admin portal.
- `ghcr.io/yuky2020/opensase-edge:<version>`: Edge gateway terminating WireGuard tunnels, enforcing policy, DNS filtering, and brokering ZTNA.
- `ghcr.io/yuky2020/opensase-connector:<version>`: Outbound-only connector dialing private applications.
- `ghcr.io/yuky2020/opensase-ocr:<version>`: Optional OCR service for DLP on images.

---

## First setup (PKI and first tenant)

The Control Plane image also ships `opensasectl`. Create the PKI once on the host that will run
the Control Plane (`-session-url` and `-wg-endpoint` are where clients reach the Edge,
`-broker-addr` is where Connectors reach it). Run the tools and the Control Plane with your own
uid (`--user`), as the dev stack does, so they can write `pki/` and `data/`.

```bash
mkdir -p pki data
docker run --rm --user "$(id -u):$(id -g)" --entrypoint /opensasectl -v "$PWD/pki:/pki" \
  ghcr.io/yuky2020/opensase-controlplane:<version> \
  pki init -dir /pki -session-url https://<edge-host>:8443 -wg-endpoint <edge-host>:51820 \
  -broker-addr <edge-host>:8444 -cp-san <control-host> -edge-san <edge-host>
```

Give the Control Plane only `root.crt`, `root.key`, `controlplane.crt`, `controlplane.key`,
`snapshot.key`, `edges.json` and `tenants/` (never `pki/edge`, which holds the Edge keys), and
give the Edge only `pki/edge`. With the Control Plane running, create the first tenant, user and
device provisioning key (the output contains secrets: store it safely):

```bash
docker run --rm --entrypoint /opensasectl -v "$PWD/pki/root.crt:/pki/root.crt:ro" \
  -e OPENSASE_URL=https://<control-host>:9443 -e OPENSASE_CA=/pki/root.crt \
  -e OPENSASE_ADMIN_TOKEN="<admin-token>" \
  ghcr.io/yuky2020/opensase-controlplane:<version> \
  bootstrap -tenant <tenant> -user-id <user> -email <email> -control-url https://<control-host>:9443
```

The dev stack script `deploy/dev/bootstrap.sh` shows the complete sequence (policy, private
apps, Connector keys).

---

## Control Plane

The Control Plane manages tenants, users, PKI, and policy snapshots, and serves the Flutter web admin portal at `/admin/`.

### Requirements
- Port `9443/tcp` for HTTPS API and admin portal.
- Persistent volumes for PKI data (`/pki`) and SQLite database state (`/data`).
- Environment variable `OPENSASE_ADMIN_TOKEN` containing the super-admin secret token.
- The admin portal is bundled into the release image at `/portal` and automatically served via `OPENSASE_PORTAL_DIR=/portal` at `https://<control-host>:9443/admin/`.

### Docker Run Example

```bash
docker run -d \
  --name controlplane \
  --restart unless-stopped \
  --user "$(id -u):$(id -g)" \
  -p 9443:9443/tcp \
  -e OPENSASE_ADMIN_TOKEN="<admin-token>" \
  -v /path/to/pki:/pki \
  -v /path/to/data:/data \
  ghcr.io/yuky2020/opensase-controlplane:<version> \
  -listen :9443 \
  -db /data/controlplane.db \
  -pki /pki \
  -control-url https://<control-host>:9443 \
  -portal-dir /portal
```

---

## Edge

The Edge terminates post-quantum WireGuard tunnels from clients and enforces security policies.

### Requirements
- Linux capabilities: `NET_ADMIN` (for TUN device manipulation), `NET_BIND_SERVICE` (for DNS resolver on port 53), `SETUID`, `SETGID`.
- Device `/dev/net/tun` passed to the container.
- Kernel IPv4 forwarding enabled: `--sysctl net.ipv4.ip_forward=1`.
- Ports:
  - `8443/tcp`: Session setup listener.
  - `8444/tcp`: Connector broker listener.
  - `51820/udp`: WireGuard tunnel port.
- Persistent volumes for Edge PKI (`/pki:ro`) and state cache/flow logs (`/var/lib/opensase-edge`).
- Environment variables:
  - `EDGE_UID`: Unprivileged user ID to run as (default `1000`).
  - `EDGE_GID`: Unprivileged group ID to run as (default `1000`).
  - `EDGE_ALLOW_PRIVATE`: Allow tunnel clients to reach private IP ranges (`0` or `1`, default `0`).
  - `EDGE_INSPECT_PORT`: Port for TLS inspection redirect listener (default `15002`).
  - `EDGE_CLAMD`: Malware scanner address `host:port` (optional).
  - `EDGE_OCR`: OCR service endpoint URL (optional, e.g. `http://ocr:8090`).

### Docker Run Example

```bash
docker run -d \
  --name edge \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETUID \
  --cap-add SETGID \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -p 8443:8443/tcp \
  -p 8444:8444/tcp \
  -p 51820:51820/udp \
  -e EDGE_UID=1000 \
  -e EDGE_GID=1000 \
  -e EDGE_ALLOW_PRIVATE=0 \
  -e EDGE_INSPECT_PORT=15002 \
  -e EDGE_OCR="http://ocr:8090" \
  -v /path/to/pki/edge:/pki:ro \
  -v /path/to/edge-state:/var/lib/opensase-edge \
  ghcr.io/yuky2020/opensase-edge:<version> \
  -control-url https://<control-host>:9443 \
  -pki /pki \
  -listen :8443 \
  -wg-port 51820 \
  -wg-endpoint <edge-host>:51820 \
  -upstream-dns 1.1.1.1:53 \
  -ztna-listen 0.0.0.0:15001 \
  -broker-listen :8444 \
  -state-dir /var/lib/opensase-edge \
  -flow-log /var/lib/opensase-edge/flows.jsonl
```

---

## Connector

The Connector connects a private network to the Edge broker. It makes only outbound connections to the Control Plane and Edge; no inbound ports are exposed.

### Requirements
- No published ports (outbound only).
- Persistent state directory volume (`/var/lib/opensase-connector`).
- Provisioning key passed either through a mounted secret file (`-key-file`) as in Docker Compose, or through the `OPENSASE_CONNECTOR_KEY` environment variable.

### Docker Run Example (Using Mounted Secret File)

```bash
docker run -d \
  --name connector \
  --restart unless-stopped \
  -v /path/to/connector.key:/run/secrets/connector_key:ro \
  -v /path/to/connector-state:/var/lib/opensase-connector \
  ghcr.io/yuky2020/opensase-connector:<version> \
  -control https://<control-host>:9443#sha256=<root-sha256> \
  -key-file /run/secrets/connector_key \
  -state /var/lib/opensase-connector
```

### Docker Run Example (Using Environment Variable)

```bash
docker run -d \
  --name connector \
  --restart unless-stopped \
  -e OPENSASE_CONNECTOR_KEY="<connector-provisioning-key>" \
  -v /path/to/connector-state:/var/lib/opensase-connector \
  ghcr.io/yuky2020/opensase-connector:<version> \
  -control https://<control-host>:9443#sha256=<root-sha256> \
  -state /var/lib/opensase-connector
```

---

## OCR Service (Optional)

The OCR service provides text extraction from images for Edge data loss prevention (DLP). It runs isolated without network capabilities.

### Requirements
- Port `8090/tcp` (HTTP API).
- Internal network reachability by the Edge.

### Docker Run Example

```bash
docker run -d \
  --name ocr \
  --restart unless-stopped \
  -p 8090:8090 \
  ghcr.io/yuky2020/opensase-ocr:<version> \
  -listen :8090 \
  -langs eng+ita \
  -workers 2
```
