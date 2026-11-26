# Helm charts

Two charts (decision #51). Both need Kubernetes 1.33 or later.

| Chart | Runs | Namespace Pod Security |
|---|---|---|
| `opensase-controlplane` | Control Plane and admin portal | `restricted` |
| `opensase-edge` | one Edge (one identity, one public address) | `privileged` (NET_ADMIN, TUN device) |

## 1. Make the PKI offline

The PKI names the public DNS names of the Control Plane and the Edge, so make it before you
install:

```bash
opensasectl pki init -dir pki \
  -cp-san controlplane.example.com -edge-san edge1.example.com \
  -session-url https://edge1.example.com:8443 -wg-endpoint edge1.example.com:51820 \
  -broker-addr edge1.example.com:8444
```

`pki/edges.json` lists the Edges devices may use. Add one entry per Edge, with an optional
`"priority"`.

## 2. Secrets

Keep the Control Plane and Edge material apart: never give the Control Plane `pki/edge`.

```bash
kubectl create namespace opensase
kubectl label namespace opensase pod-security.kubernetes.io/enforce=restricted
kubectl -n opensase create secret generic opensase-pki \
  --from-file=pki/root.crt --from-file=pki/root.key \
  --from-file=pki/controlplane.crt --from-file=pki/controlplane.key \
  --from-file=pki/snapshot.key --from-file=pki/ca-kek.key --from-file=pki/edges.json
kubectl -n opensase create secret generic opensase-admin-token \
  --from-literal=token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"

kubectl create namespace opensase-edge
kubectl label namespace opensase-edge pod-security.kubernetes.io/enforce=privileged
kubectl -n opensase-edge create secret generic opensase-edge-1-pki --from-file=pki/edge/
```

## 3. Install

```bash
helm install cp deploy/helm/opensase-controlplane -n opensase \
  --set controlURL=https://controlplane.example.com:9443
helm install edge1 deploy/helm/opensase-edge -n opensase-edge \
  --set controlURL=https://controlplane.example.com:9443 \
  --set wgEndpoint=edge1.example.com:51820 \
  --set pki.existingSecret=opensase-edge-1-pki
```

Each release also publishes both charts, signed with cosign, as OCI artifacts. Install them
without a checkout, with the same values:

```bash
helm install cp oci://ghcr.io/yuky2020/charts/opensase-controlplane --version <version> -n opensase \
  --set controlURL=https://controlplane.example.com:9443
cosign verify ghcr.io/yuky2020/charts/opensase-controlplane:<version> \
  --certificate-identity-regexp '^https://github.com/yuky2020/opensase/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Point the DNS names at the LoadBalancer addresses. The Services use
`externalTrafficPolicy: Local`, so clients' source addresses reach the pods unchanged.

## Database

- **SQLite** (`database.type=sqlite`, the default): one replica on a ReadWriteOnce volume,
  updated with `Recreate`. Scheduled backups go to `/data/backups`. The volume is kept when
  the release is deleted.
- **PostgreSQL** (`database.type=postgres`): several replicas (`replicas`), updated with
  rolling updates. Put the `postgres://` URL in a Secret and set
  `database.postgres.existingSecret`. Move an existing SQLite install with
  `opensasectl store migrate` (see the Control Plane docs).

## Edge networking

- **TUN device.** The Edge creates `/dev/net/tun` itself; this needs `CAP_MKNOD`, which the
  chart grants.
- **IP forwarding.** `net.ipv4.ip_forward` must be 1 in the pod. By default a privileged
  init container sets it (`ipForward=initContainer`). Use `ipForward=sysctl` if the kubelet
  allows that sysctl, or `none` if your CNI sets it already.
- **Never `hostNetwork`.**
- **Bare metal without a LoadBalancer.** Use `service.type=NodePort` and point `wgEndpoint`
  and the session URL at a node.

## Monitoring

Both charts expose `/metrics`, `/healthz` and `/readyz` on the ClusterIP Service
`<release>-...-ops` (issue #73). See the monitoring page of the docs for the alert rules.
