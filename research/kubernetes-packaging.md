# Kubernetes packaging for OpenSASE (issue #40)

**Question.** How should the Control Plane and the Edge be packaged for Kubernetes as a Helm chart, given:

- the Edge's privileges: NET_ADMIN, plus SETUID, SETGID and NET_BIND_SERVICE for its entrypoint, `/dev/net/tun`, IP forwarding and iptables;
- the Edge's exposure: UDP 51820 and TCP 8443/8444 at one stable public address;
- the Control Plane's needs: PKI, an admin token, SQLite on a volume, and post-quantum-only TLS on 9443?

And what do comparable open-source WireGuard projects do, and where do they go wrong?

Researched 2026-11-24. Sources are numbered [n] and listed at the end. Statements labelled *(inference)* follow from the sources but are not stated in them. Statements labelled *(verify)* need a test on a real cluster.

---

## 1. How the components run today (repository facts)

Sources: `deploy/release/README.md`, `deploy/release/Dockerfile.*`, `deploy/release/quickstart/quickstart.sh`, `deploy/dev/docker-compose.yml`, `deploy/dev/edge-entrypoint.sh`, plus a few code references.

### Control Plane

- **Image.** `distroless/static:nonroot`, running as UID 65532. It ships `/controlplane` and `/opensasectl`, with the portal at `/portal`.
- **Port.** One listener: 9443/tcp.
- **Hardening.** Compose runs it with `cap_drop: ALL`, `no-new-privileges` and `read_only` plus a tmpfs `/tmp`. That already matches the Pod Security "restricted" profile.
- **Inputs.**
  - Read-only PKI files: `root.crt/key`, `controlplane.crt/key`, `snapshot.key`, `edges.json`.
  - A **writable** `pki/tenants/` directory, because tenant CAs are created on demand.
  - A writable `/data` holding `controlplane.db` and the categories archive.
  - The `OPENSASE_ADMIN_TOKEN` environment variable.
- **Database.** SQLite opened with `journal_mode(WAL)` (`pkg/store/store.go:49`).
- **TLS.** All TLS goes through `pqsession.Harden`, which sets TLS 1.3 only with `CurvePreferences = [X25519MLKEM768]` (`pkg/pqsession/pqsession.go:24`). Client certificates are `VerifyClientCertIfGiven` (`internal/controlplane/server.go:175`), so devices, Edges and Connectors authenticate with mTLS on the same port.
- **Health.** There is no `/healthz`. Compose checks health with `opensasectl pq-check`. `GET /v1/pki/ca` is unauthenticated.
- **Source IP matters.** The enrolment limiter counts **failed attempts per TCP peer IP**, and "no proxy headers [are] trusted" (`internal/controlplane/hardening.go:214-226`).

### Edge

- **Image.** `alpine` with `iptables`, `iproute2` and `setpriv`.
- **WireGuard implementation.** The Edge uses **userspace wireguard-go on a TUN device** (`tun.CreateTUN`, `internal/edge/edge.go:278`). It needs no kernel module, but it needs `/dev/net/tun`.
- **MTU.** The default is 1280 (`cmd/edge/main.go:36`).
- **Entrypoint, part 1: firewall as root.** It runs as root with NET_ADMIN, NET_BIND_SERVICE, SETUID and SETGID. It installs these rules:
  - NAT MASQUERADE for 100.64.0.0/10 and RFC 1918 subnets out of `eth0`;
  - TCPMSS clamping;
  - REDIRECTs for ZTNA and TLS inspection;
  - **`iptables -P FORWARD DROP`**, then OSASE_* chains with conntrack matches.
- **Entrypoint, part 2: privilege drop.** It then runs `setpriv` to EDGE_UID, keeping NET_ADMIN and NET_BIND_SERVICE as **ambient** capabilities.
- **Sysctls and ports.** It needs `net.ipv4.ip_forward=1`. It serves 8443/tcp (PQ session setup), 8444/tcp (Connector broker, mTLS) and 51820/udp.
- **State.** `/var/lib/opensase-edge` holds the state cache and flow log. It also needs `pki/edge` (`root.crt`, `edge.crt/key`, `edge-wg.key`).
- **The public address is fixed in the PKI.** `opensasectl pki init -session-url -wg-endpoint -broker-addr -edge-san` writes it into `edges.json` and into the Edge certificate SANs. Clients learn `sessionUrl`, `wgEndpoint` and `brokerAddr` from `EdgeInfo` (`pkg/api/types.go:137`). **So the Edge's public address must be known before the PKI is created.**
- **TCP and UDP must reach the same pod.** The 8443 TLS session derives the WireGuard PSK through the exporter, bound to both WireGuard keys and the session id (`pqsession.Context`). The same Edge process must therefore receive a client's TCP 8443 and its UDP 51820 *(inference from the code)*.
- **Keepalive.** Clients send WireGuard keepalives every 25 s (`mobile/session.go:171`).

---

## 2. The Kubernetes constraints, from primary sources

### 2.1 Pod Security Admission: the Edge cannot be "baseline"

- **Baseline capabilities.** Baseline allows adding only `AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT` [1]. **NET_ADMIN is not on the list**, so any Edge pod violates baseline.
- **Other baseline rules.** Baseline also forbids `hostNetwork`, `hostPath` volumes and (by recommendation) `hostPort`. It allows only a list of "safe" sysctls [1], and `net.ipv4.ip_forward` is not among them [1][2].
- **Restricted profile.** Restricted requires all of these [1]:
  - `drop: [ALL]`, adding back only `NET_BIND_SERVICE`;
  - `runAsNonRoot: true`;
  - `allowPrivilegeEscalation: false`;
  - seccomp `RuntimeDefault` or `Localhost`;
  - volumes limited to configMap, csi, downwardAPI, emptyDir, ephemeral, PVC, projected and secret.
- **How it is enforced.** PSA is applied per namespace with `pod-security.kubernetes.io/<enforce|audit|warn>: <privileged|baseline|restricted>`, plus an optional `-version` pin. Exemptions (usernames, runtime classes, namespaces) are static configuration of the admission controller [3].
- **Consequence for the chart.** The Edge must run in a namespace labelled `enforce: privileged` (or an exempt one). The Control Plane can and should run under `restricted` *(inference)*. A single-namespace chart would force the Control Plane, which holds the root CA key, into a privileged namespace. Split them.

### 2.2 `/dev/net/tun`

- **No device field in the pod spec.** Unlike Docker's `--device`, the pod spec cannot list devices. The options are:
  1. **`privileged: true`.** Every device is visible.
  2. **A `hostPath` volume** of type `CharDevice` for `/dev/net/tun`. hostPath is forbidden by baseline and restricted [1].
  3. **A device plugin.** For example, squat/generic-device-plugin advertises arbitrary host device paths as an extended resource that pods request under `resources.limits` [4].
  4. **`mknod /dev/net/tun c 10 200` in the entrypoint.** MKNOD is baseline-allowed. This works only if the runtime's device cgroup allows char 10:200.
- **Runtime history.** runc removed tun/tap from its default device allowlist in 1.2.0 (#3468). It **re-added it in 1.2.4** because "this regressed a noticeable number of users (and not all higher-level tools provide easy ways to specify devices to allow)" [5].
- **containerd.** containerd separately stopped *creating* the tun node by default: "A container should not have access to tun/tap device, unless it is explicitly specified in configuration" [6]. With current runc the cgroup permits the device, but the node may not exist, so option 4 needs `mknod` *(verify on containerd 2.x and on crun-based nodes)*.

### 2.3 IP forwarding (`net.ipv4.ip_forward`)

- **It is an unsafe sysctl.** Unsafe sysctls must be enabled per node with the kubelet flag `--allowed-unsafe-sysctls`. Pods that request a disallowed one "are scheduled but fail to launch". `net.*` sysctls are refused when `hostNetwork` is on [2].
- **Pod network namespaces usually inherit the setting.** The kernel's `devconf_inherit_init_net` default (0) makes a new network namespace **inherit IPv4 `conf/{all,default}` from init_net**, while IPv6 is reset to defaults [7]. Kubernetes nodes normally forward IPv4, so a pod's network namespace will usually already have IPv4 forwarding on *(inference, verify per CNI; the CNI may also create the namespace differently)*. The Edge should check `/proc/sys/net/ipv4/ip_forward` at startup and fail with a clear message rather than rely on this.
- **Other ways to set it.**
  - The CNI `tuning` meta-plugin can set any `/proc/sys/net/*` key in the pod's network namespace, optionally limited by a node allowlist at `/etc/cni/tuning/allowlist.conf` [8].
  - A privileged init container can write `/proc/sys`. That is what the surveyed charts do (§3).

### 2.4 iptables in the pod network namespace

- **Rules stay inside the pod.** Each pod has its own network namespace, so the entrypoint's rules (including `FORWARD DROP`) affect only that pod. This holds **unless the pod uses `hostNetwork`**. Then the same script would set the *node's* FORWARD policy to DROP and add MASQUERADE on the node's `eth0`, breaking pod networking for the whole node *(inference from the entrypoint)*. hostNetwork is therefore not an option without rewriting the entrypoint.
- **Kernel modules must already be loaded on the node.** Pods cannot load modules. In a user-namespaced pod, `CAP_SYS_MODULE` "has no effect" [9]. The rules need the netfilter NAT, conntrack, REDIRECT, TCPMSS and multiport matches available *(verify; usually present where kube-proxy runs in iptables or nftables mode)*.
- **Non-root containers do not get added capabilities.** Kubernetes puts `capabilities.add` into the bounding set, not the ambient set. The open issue is "Kubernetes should configure the ambient capability set" (kubernetes/kubernetes#56374) [10]. The existing root entrypoint that calls `setpriv` with ambient caps is the reliable way to run the Edge daemon unprivileged, so keep it.
- **`no_new_privs` is not a problem.** `allowPrivilegeEscalation: false` sets `no_new_privs`. Compose already runs the Edge with `no-new-privileges:true`, so the setpriv path is proven under it.

### 2.5 Exposing UDP 51820 and TCP 8443/8444 at a stable address

**Service options** [11][12][13]:

| Option | Source IP | Address stability | Notes |
|---|---|---|---|
| `type: LoadBalancer`, `externalTrafficPolicy: Cluster` | **Lost**: "source NAT'd by default" [12] | LB IP, stable while the Service exists | Traffic can cross nodes; extra conntrack hops |
| `type: LoadBalancer`, `externalTrafficPolicy: Local` | **Preserved** for packet-forwarding LBs; proxy-style LBs never preserve it [12] | Same | Kubernetes allocates `healthCheckNodePort` (`/healthz` → 200 only on nodes with a local ready endpoint) [12][13]; brief drops while health checks converge |
| `type: NodePort` | Lost with Cluster, kept with Local | A node IP: unstable unless the pod is pinned with `nodeSelector` | Default range 30000-32767 [11], so clients see a non-standard port, which works because `wgEndpoint` and `sessionUrl` carry ports |
| `hostPort` (CNI portmap) | **Preserved**: portmap SNATs only loopback and hairpin traffic unless `masqAll` [14] | The node IP; pod pinned to the node | Docs: avoid "unless absolutely necessary"; ports must be unique per node [15] |
| `hostNetwork: true` | Preserved | Node IP | **Breaks the node** with the current entrypoint (§2.4); `net.*` sysctls refused [2] |

**Facts that matter for the choice:**

- **Mixed protocols are allowed by the API.** One `LoadBalancer` Service with both UDP and TCP ports is stable since 1.26. But "the set of protocols that can be used for load balanced Services is defined by your cloud provider" [11].
- **Pinning the IP.** `spec.loadBalancerIP` has been deprecated since 1.24 ("under-specified ... cannot support dual-stack"). Use the implementation's annotation instead [11]. For example, MetalLB uses `metallb.io/loadBalancerIPs` [16].
- **`externalIPs`.** These are deprecated since 1.36 [11].
- **MetalLB modes (open-source bare-metal LB) [16]:**
  - **L2 with `Local`.** Only pods on the leader node get traffic, and they see the real client IP.
  - **BGP with `Local`.** Only nodes with pods attract traffic.
  - **Sharing one IP between two Services** (for example, one UDP and one TCP Service) needs the same `allow-shared-ip` key, different ports, and either both `Cluster` or exactly the same pod selector.
- **Session affinity is per Service.** `sessionAffinity: ClientIP` defaults to 10800 s [13]. It does **not** tie a client's TCP 8443 to the same pod as its UDP 51820 across two Services or protocols *(inference)*. With more than one Edge replica behind one address, a client's PSK session (TCP) and tunnel (UDP) could land on different pods. **One Edge identity should map to exactly one pod and one public address.** Scale out by adding Edge identities (more `edges.json` entries), not replicas.
- **Gateway API cannot carry the WireGuard port.** `TLSRoute` with a `Passthrough` listener is GA in the Standard channel since Gateway API v1.5.0 [17]. Passthrough only routes by SNI and never terminates TLS. This page does not give TCPRoute's or UDPRoute's status, so check it before relying on either for 8444 or 51820.
- **Source IP matters to OpenSASE in two places:**
  1. **The Control Plane enrolment limiter keys on the TCP peer.** Behind SNAT, every client shares one node IP, so a few failed enrolments throttle *everyone* (429). Use `externalTrafficPolicy: Local` (or a passthrough path that keeps the source IP) for 9443.
  2. **The Edge logs Connector remote addresses**, and WireGuard roaming learns peer endpoints from packet sources. SNAT still works through conntrack reverse-NAT, but logs become meaningless.

### 2.6 Control Plane TLS cannot be terminated by a classic ingress

- **Why termination is impossible.** The server accepts only TLS 1.3 with X25519MLKEM768, and it authenticates devices, Edges and Connectors by client certificate on the same port. An ingress that terminates TLS would both downgrade the key exchange and strip mTLS.
- **The only workable shapes:**
  - L4 passthrough: a `LoadBalancer` Service or a Gateway API `TLSRoute` in `Passthrough` mode [17];
  - a dedicated LoadBalancer IP.
- **Avoid ingress-nginx.** Its `--enable-ssl-passthrough` exists but "bypasses NGINX completely and introduces a non-negligible performance penalty" [18]. More importantly, **Ingress NGINX was retired by SIG Network on 24 March 2026** and receives no security fixes [19]. Do not build on it.
- **Kubelet probes work against the PQ-only server.**
  - Kubelet HTTP probes use `tls.Config{InsecureSkipVerify: true}` with no `CurvePreferences` (`pkg/probe/http/http.go`) [20].
  - Since Go 1.24, X25519MLKEM768 "is enabled by default when `Config.CurvePreferences` is nil" [21].
  - Kubernetes builds with `godebug default=go1.24` (release-1.33) and `go1.27` (master), not an older default [22].
  - So an `httpGet` with `scheme: HTTPS` on an unauthenticated path such as `/v1/pki/ca` negotiates PQ on kubelets built with Go ≥1.24 (Kubernetes ≥1.33) *(inference; verify on the minimum supported version)*.
  - The fallback is an `exec` probe with `/opensasectl pq-check`, which also proves PQ.
  - Cloud LB HTTPS health checks will likely fail the handshake. Use TCP health checks, or `healthCheckNodePort` with `Local`.

### 2.7 Control Plane storage and secrets

- **No network filesystems for the database.** SQLite warns that over network filesystems "locking ... [has] been known to operate incorrectly ... [and] has led to database corruption" [23]. WAL mode, which OpenSASE uses, "does not work over a network filesystem" because the wal-index is shared memory [24]. The chart must:
  - require a block-backed RWO PVC;
  - run exactly **1 replica**;
  - use `strategy: Recreate` (or a StatefulSet of 1), so an old and a new pod never open the database together. The upstream single-instance stateful tutorial uses `Recreate` with one replica [25].
- **Secrets are not encrypted at rest by default.** "Kubernetes Secrets are, by default, stored unencrypted in the API server's underlying data store (etcd) ... anyone who is authorized to create a Pod in a namespace can use that access to read any Secret in that namespace" [26]. The upstream recommendations [26]:
  - enable encryption at rest;
  - apply least-privilege RBAC;
  - restrict Secret access to specific containers;
  - consider external secret stores.
- **What this means for OpenSASE:**
  - The **root CA key** in a Secret is readable by anyone who can create pods in that namespace. That is one more reason to keep the Control Plane out of the privileged Edge namespace.
  - Secrets mounted as volumes are read-only, but **`pki/tenants/` must be writable**. Tenant CAs therefore belong on the PVC, or the Control Plane needs a configurable tenants directory.
- **Generating secrets inside the chart.** Helm's `randAlphaNum` is crypto/rand [27]. But templates re-render on every upgrade, and "when a template run generates data that differs from the last run, that will trigger an update of that resource" [28]. `lookup` lets a chart reuse an existing Secret, but "when used with the helm template command it always returns an empty response" [27], which breaks GitOps renderers.
- **Hooks are an alternative, with caveats.** Hook resources "are not tracked or managed as part of the release" [29]. `helm.sh/resource-policy: keep` stops a resource being deleted on uninstall, but leaves it "orphaned" [28].
- **Rolling on config changes.** Use a `checksum/config` annotation so pods restart when a ConfigMap or Secret changes [28].

### 2.8 Conntrack, UDP and MTU pitfalls

- **Conntrack timeouts and keepalive.**
  - Kernel defaults are 30 s for unreplied UDP and 120 s for an assured UDP "stream" [30].
  - kube-proxy can override both (`conntrack.udpTimeout`, `udpStreamTimeout`) and sizes the table with `maxPerCore` and `min` [31].
  - WireGuard's advice is a 25 s keepalive to "keep the NAT/firewall mapping valid" [32], which OpenSASE clients already send. That keeps LB and SNAT conntrack entries alive.
  - The Edge's own MASQUERADE for tunnelled traffic adds entries to the **node's** conntrack table. The global limit is set at node level by kube-proxy [31], so a busy Edge competes with every other pod on the node *(inference)*. Document the sizing, and consider a dedicated node pool.
- **Stale UDP conntrack after endpoint changes.** Kubernetes has a long history of stale UDP conntrack entries black-holing traffic when a Service's endpoints change. Two triggers are recorded: "an endpoint that was receiving traffic gets removed or replaced, or a service that wasn't forwarding starts forwarding" (kubernetes/kubernetes#106163, #106239, #104009, #105657) [33]. After an Edge pod restart, clients that keep sending to 51820 can stay pinned to the dead pod IP until their entry expires. The 25 s keepalive means it may *never* expire.
  - Recent kube-proxy versions clear these entries.
  - Other dataplanes (eBPF CNIs, portmap for hostPort) have their own behaviour.
  - Add this to the upgrade test plan *(verify)*.
- **MTU.** WireGuard adds 80 bytes of overhead in the worst (IPv6) case; `wg-quick` sets interface MTU to "route MTU − 80" [34]. Overlay CNIs lower the pod MTU further. One surveyed operator documents a 1380 MTU requirement on a managed platform [35]. OpenSASE's default of 1280, plus the entrypoint's TCPMSS clamp, leaves headroom (1280 + 80 = 1360). Keep `-mtu` configurable in values for overlays with large encapsulation.

### 2.9 Probes and upgrades

- **Edge probes.** The Edge has no health endpoint.
  - A `tcpSocket` probe on 8443 checks the listener only.
  - An `exec` probe for `wg0` being up is what the surveyed chart uses (`ip link show dev wg0 | grep -s up`) [36].
  - A proper `/healthz` on a localhost-only port would be better *(design suggestion)*.
- **Draining during a rollout.** With `externalTrafficPolicy: Local`, terminating endpoints keep receiving traffic only if **all** local endpoints are terminating (ProxyTerminatingEndpoints, stable since 1.28) [13]. That allows graceful drain.
- **Edge rollouts drop tunnels.** A single Edge per address means a rollout is a short outage. Clients must reconnect: a new PQ session gives a new PSK. Use `Recreate` (or `RollingUpdate` with `maxSurge: 0`) because hostPort, PKI identity and the WireGuard key are per Edge.
- **Use a PodDisruptionBudget with care.** `minAvailable: 1` with one replica blocks node drains. Document this instead of shipping it by default.

---

## 3. How comparable open-source WireGuard projects package for Kubernetes

| Project | Workload | Exposure | Privileges | Keys | Notes |
|---|---|---|---|---|---|
| **bryopsida/wireguard-chart** (Helm) [36][37] | Deployment (DaemonSet optional), `replicaCount: 3`, HPA 3-10, PDB `minAvailable: 2`, RollingUpdate `maxUnavailable: 0` | `service.type: LoadBalancer` by default; `nodePort`, `externalTrafficPolicy`, `loadBalancerIP`, `loadBalancerClass`; options `useHostPort` and `runPodOnHostNetwork` | Main container `drop: ALL`, `add: NET_ADMIN, NET_RAW, SETUID, SETGID`, `runAsNonRoot`, read-only root; **privileged init container** runs `sysctl -w net.ipv4.ip_forward=1` | **`pre-install` hook Job** with a namespaced Role allowed only to `create` Secrets generates the private key if `secretName` is unset | Exec probe on `wg0`; replicas share one key and config, which works because plain WireGuard holds no per-session server state |
| **jodevsa/wireguard-operator** [35][38] | Operator (CRDs `Wireguard`, `WireguardPeer`) creates the Deployment | `LoadBalancer` by default; waits for `status.loadBalancer.ingress` and **then** writes the address into peer configs; `NodePort` documented for LBs **without UDP support** | Containers `drop: ALL`, `add: NET_ADMIN`; a **privileged init container** writes `/proc/sys/net/ipv4/ip_forward` | Generated and stored in Secrets | Falls back to wireguard-go if the kernel module is missing; `spec.mtu` exposed (1380 example); repository now archived |
| **squat/kilo** (WireGuard mesh / CNI) [39] | DaemonSet | Host network | `privileged: true` (CNI-level component) | n/a | Userspace mode runs wireguard-go as a sidecar; shown for contrast: privileged+hostNetwork is normal for a CNI, not for an application gateway |

**Patterns across them:**

1. **LoadBalancer by default, with NodePort, hostPort and hostNetwork as escape hatches.**
2. **A privileged init container for `ip_forward`**, rather than asking admins to allow unsafe sysctls.
3. **Keys created in-cluster** by a hook Job or an operator.
4. **Exec probes on the interface.**
5. **No surveyed chart solves source IP preservation for you.** They pass through `externalTrafficPolicy`.
6. **None uses a TUN device plugin.** Kernel WireGuard needs no TUN at all; userspace fallbacks rely on privileged containers.
7. **Horizontal scaling only works when servers are stateless.** That holds for plain WireGuard with a shared key. OpenSASE's per-session PSK negotiated over TCP 8443 breaks it.

---

## 4. Implications for OpenSASE (input to a decision)

### 4.1 Chart shape

**Option A: one chart, two namespaces.**

- Two components, each with `enabled` flags: `controlplane` and `edge` (and later `connector`, `ocr`).
- The chart can label two namespaces, or document that the Edge namespace needs `pod-security.kubernetes.io/enforce: privileged` and the Control Plane namespace `restricted`.
- Simple for trials.
- Helm installs a release into one namespace, so creating cross-namespace objects is awkward.

**Option B: two charts (`opensase-controlplane`, `opensase-edge`).**

- Each installs into its own namespace. This matches the PSA split and the existing image split.
- Edges can be installed once per identity (`edge-1`, `edge-2`, …) on different clusters or regions.
- Costs a second chart to version.

**Recommendation: B.**

- It mirrors the security boundary that the compose file already draws: the Control Plane never sees `pki/edge`, and the Edge never sees `root.key`.
- It gives "one release = one Edge identity = one public address" for free.
- An umbrella chart can come later.
- Publish both as OCI charts next to the images in the same OCI registry (`helm push <chart>.tgz oci://<registry>/<path>`) [41].
- Ship a `values.schema.json` (validated on install, upgrade, lint and template) and a `kubeVersion` constraint [42].

### 4.2 Edge privileges

| Option | PSA | Works today? | Trade-off |
|---|---|---|---|
| E1: `privileged: true` | privileged | Yes | Simplest, and what the surveyed charts do for init containers. The whole container gets every capability and device. Too broad for a policy-enforcing gateway that parses untrusted traffic |
| **E2: caps `NET_ADMIN, NET_BIND_SERVICE, SETUID, SETGID, MKNOD` (drop ALL) + `mknod /dev/net/tun` in the entrypoint when it is missing + check `ip_forward`, with an optional privileged init container only for the sysctl** | privileged (because of NET_ADMIN) | Needs a small entrypoint change | Closest to today's compose least privilege; no hostPath. Depends on the runtime allowing char 10:200 (runc ≥1.2.4 does [5]) |
| E3: E2 + hostPath `CharDevice /dev/net/tun` instead of mknod | privileged | Yes | No reliance on the runtime's mknod behaviour; one more host-coupling |
| E4: E2 + generic device plugin resource | privileged | Yes | Cleanest device grant, but asks cluster admins to run a DaemonSet first |

**Recommendation:** E2 by default, with `edge.tun.mode: mknod|hostPath|devicePlugin` in values, so E3 and E4 are a switch away. For IP forwarding:

- default to "verify and fail clearly";
- offer `edge.sysctlInit.enabled` (a privileged init container, the common pattern) and document the `--allowed-unsafe-sysctls` alternative [2].

Keep the root-then-setpriv entrypoint. Kubernetes cannot give a non-root container ambient capabilities [10]. Set `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, and a read-only root with emptyDir for `/tmp`. Never offer `hostNetwork` unless the entrypoint becomes hostNetwork-safe; today it would set the node's FORWARD policy to DROP.

### 4.3 Edge exposure

| Option | Pros | Cons |
|---|---|---|
| **X1: one `LoadBalancer` Service, mixed UDP 51820 + TCP 8443/8444, `externalTrafficPolicy: Local`, implementation-specific IP annotation** | Stable address independent of nodes; source IP preserved on packet-forwarding LBs; standard ports | Needs an LB that supports UDP *and* mixed protocols [11]; brief convergence after reschedule; some LBs need two Services sharing an IP [16] |
| X2: `hostPort` on a node pinned by `nodeSelector` (+ DNS name pointing at the node) | Works on bare metal with no LB; source IP preserved [14]; standard ports | Node is a single point of failure; docs discourage it [15]; UDP conntrack behaviour of portmap on pod restart needs testing |
| X3: `NodePort` (+ Local) | Works almost everywhere | Ports 30000-32767; node IP still the address; fine for labs |
| X4: hostNetwork | — | Unsafe with the current entrypoint; rejected |

**Recommendation:**

- **X1 as the default**, with `service.type`, `externalTrafficPolicy` (default `Local`), `annotations`, `loadBalancerClass` and per-port `nodePort` exposed. **X2 is the documented bare-metal fallback**, and X3 is for labs.
- Run **one replica per release**, with `strategy: Recreate`, and document that scaling means more Edge identities.
- Advertise a **DNS name** in `pki init` (`-session-url`, `-wg-endpoint`, `-broker-addr`, `-edge-san`), not an IP. This breaks the chicken-and-egg problem of an LB IP that only exists after install. The operator surveyed instead reads the LB status and rewrites configs [38], which OpenSASE cannot do because the address sits in signed PKI.

### 4.4 Control Plane

- **Workload.** StatefulSet of 1 (or a Deployment with `Recreate`) and an RWO block PVC for `/data`. Document clearly that the storage must not be NFS or another network filesystem, because WAL and locking break [23][24]. Plan an external database before any HA.
- **Exposure.** A `LoadBalancer` with `externalTrafficPolicy: Local` (the enrolment rate limiter needs real peer IPs), or a Gateway API `TLSRoute` with `Passthrough` [17]. Never an Ingress that terminates TLS, and not ingress-nginx, which is retired [19].
- **Probes.** `httpGet` with HTTPS on `/v1/pki/ca` (PQ-capable kubelets on Kubernetes ≥1.33 [20][21][22]), or an exec probe with `opensasectl pq-check` as the version-independent fallback. A dedicated `/healthz` would be better.
- **PKI handling.** Two supported modes:
  1. **`existingSecret`** (recommended for production): the operator runs `opensasectl pki init` offline and creates the Secrets. Root key separation stays in human hands.
  2. **Generated** (trials): a `pre-install` hook Job with a Role limited to `create` on Secrets runs `pki init`, as the surveyed chart does [37]. Annotate it `helm.sh/resource-policy: keep` and document the orphaning [28][29].

  Do not generate secrets with `randAlphaNum` + `lookup` in templates. They are unstable under `helm template` and GitOps [27][28].
- **Writable tenant CAs.** Move `tenants/` onto the PVC, or add a `-tenants-dir` flag, because Secret volumes are read-only.
- **Admin token.** Read it from a mounted file rather than the environment, matching the `-key-file` pattern used elsewhere. Recommend encryption at rest plus tight RBAC on the Control Plane namespace [26].

### 4.5 Test plan before calling it supported

Run each of these on kind or k3s (or similar), and on one MetalLB bare-metal cluster:

1. **Start-up:** the Edge starts under E2 with no privileged main container.
2. **Device:** the `/dev/net/tun` mknod path works on containerd 2.x with runc and with crun.
3. **Forwarding:** `ip_forward` is inherited in the pod network namespace.
4. **Restart:** the Edge pod restarts while clients are connected, with no stale UDP conntrack black hole (§2.8).
5. **Source IP:** Control Plane enrolment sees real client IPs with `Local`.
6. **Probes:** the HTTPS probe succeeds against the PQ-only listener on the minimum supported Kubernetes version.
7. **Upgrade:** `helm upgrade` does not regenerate PKI or the admin token.

---

## Sources

1. Kubernetes, *Pod Security Standards* — https://kubernetes.io/docs/concepts/security/pod-security-standards/
2. Kubernetes, *Using sysctls in a Kubernetes Cluster* — https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/
3. Kubernetes, *Pod Security Admission* — https://kubernetes.io/docs/concepts/security/pod-security-admission/
4. squat/generic-device-plugin README — https://github.com/squat/generic-device-plugin
5. runc CHANGELOG, 1.2.0 (#3468) and 1.2.4 (#4555, #4556) — https://github.com/opencontainers/runc/blob/main/CHANGELOG.md
6. containerd PR #7267 (backport of #6923), "remove tun/tap from the default devices" — https://github.com/containerd/containerd/pull/7267
7. Linux kernel, *Documentation for /proc/sys/net/* (`devconf_inherit_init_net`) — https://docs.kernel.org/admin-guide/sysctl/net.html
8. CNI, *tuning plugin* — https://www.cni.dev/plugins/current/meta/tuning/
9. Kubernetes, *User Namespaces* — https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/
10. kubernetes/kubernetes#56374, "Kubernetes should configure the ambient capability set" (open) — https://github.com/kubernetes/kubernetes/issues/56374
11. Kubernetes, *Service* — https://kubernetes.io/docs/concepts/services-networking/service/
12. Kubernetes, *Using Source IP* — https://kubernetes.io/docs/tutorials/services/source-ip/
13. Kubernetes, *Virtual IPs and Service Proxies* — https://kubernetes.io/docs/reference/networking/virtual-ips/
14. CNI, *portmap plugin* — https://www.cni.dev/plugins/current/meta/portmap/
15. Kubernetes, *Configuration Best Practices* ("Avoid hostPort and hostNetwork unless absolutely necessary") — https://kubernetes.io/docs/concepts/configuration/overview/
16. MetalLB, *Usage* — https://metallb.universe.tf/usage/
17. Gateway API, *TLS* guide — https://gateway-api.sigs.k8s.io/guides/tls/
18. ingress-nginx, *TLS/HTTPS* (SSL passthrough) — https://kubernetes.github.io/ingress-nginx/user-guide/tls/
19. Kubernetes blog, *Ingress NGINX Retirement* (2025-11-11) and *v1.36 Sneak Peek* (retired 2026-03-24) — https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/ , https://kubernetes.io/blog/2026/03/30/kubernetes-v1-36-sneak-peek/
20. Kubernetes source, `pkg/probe/http/http.go` — https://github.com/kubernetes/kubernetes/blob/master/pkg/probe/http/http.go
21. Go 1.24 release notes, crypto/tls — https://go.dev/doc/go1.24
22. Kubernetes `go.mod` (`godebug default=go1.24` on release-1.33; `go1.27` on master) — https://github.com/kubernetes/kubernetes/blob/release-1.33/go.mod
23. SQLite, *SQLite Over a Network, Caveats and Considerations* — https://sqlite.org/useovernet.html
24. SQLite, *Write-Ahead Logging* — https://sqlite.org/wal.html
25. Kubernetes, *Run a Single-Instance Stateful Application* — https://kubernetes.io/docs/tasks/run-application/run-single-instance-stateful-application/
26. Kubernetes, *Secrets* — https://kubernetes.io/docs/concepts/configuration/secret/
27. Helm, *Template Function List* (`lookup`, `randAlphaNum`) — https://helm.sh/docs/chart_template_guide/function_list/
28. Helm, *Chart Development Tips and Tricks* — https://helm.sh/docs/howto/charts_tips_and_tricks/
29. Helm, *Chart Hooks* — https://helm.sh/docs/topics/charts_hooks/
30. Linux kernel, *Netfilter Conntrack Sysfs variables* — https://docs.kernel.org/networking/nf_conntrack-sysctl.html
31. Kubernetes, *kube-proxy Configuration (v1alpha1)*, `KubeProxyConntrackConfiguration` — https://kubernetes.io/docs/reference/config-api/kube-proxy-config.v1alpha1/
32. WireGuard, *Quick Start* (persistent keepalive) — https://www.wireguard.com/quickstart/
33. kubernetes/kubernetes PRs #106163, #106239, #104009 and issue #105657 (stale UDP conntrack) — https://github.com/kubernetes/kubernetes/pull/106163 , https://github.com/kubernetes/kubernetes/pull/106239 , https://github.com/kubernetes/kubernetes/pull/104009 , https://github.com/kubernetes/kubernetes/issues/105657
34. wireguard-tools, `src/wg-quick/linux.bash` (`mtu - 80`) — https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/linux.bash
35. jodevsa/wireguard-operator README — https://github.com/jodevsa/wireguard-operator
36. bryopsida/wireguard-chart, `helm/wireguard/values.yaml` and `templates/deployment.yaml` — https://github.com/bryopsida/wireguard-chart/tree/main/helm/wireguard
37. bryopsida/wireguard-chart, `templates/privatekey-gen-job.yaml` — https://github.com/bryopsida/wireguard-chart/blob/main/helm/wireguard/templates/privatekey-gen-job.yaml
38. jodevsa/wireguard-operator, `pkg/controllers/wireguard_controller.go` — https://github.com/jodevsa/wireguard-operator/blob/main/pkg/controllers/wireguard_controller.go
39. Kilo, *Userspace WireGuard* and `manifests/kilo-k3s-userspace.yaml` — https://kilo.squat.ai/docs/userspace-wireguard , https://github.com/squat/kilo/blob/main/manifests/kilo-k3s-userspace.yaml
41. Helm, *Use OCI-based registries* — https://helm.sh/docs/topics/registries/
42. Helm, *Charts* (`values.schema.json`, `kubeVersion`) — https://helm.sh/docs/topics/charts/
