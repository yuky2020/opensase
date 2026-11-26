# Download

Every release is built by CI from a tag and published on
[GitHub Releases](https://github.com/yuky2020/opensase/releases), with a `SHA256SUMS` file for
all downloads. Container images go to the GitHub Container Registry. From v0.3.0 on, checksums
and images are signed: see [Verify a download](verify.md).

!!! warning "Pre-release"
    Versions `0.x` are pre-releases: APIs and on-disk formats can still change. Do not run them
    in production yet.

## Latest: v0.2.0

[Release notes and files](https://github.com/yuky2020/opensase/releases/tag/v0.2.0){ .md-button .md-button--primary }
[All releases](https://github.com/yuky2020/opensase/releases){ .md-button }

### Clients

| Platform | File | Notes |
|---|---|---|
| Windows (x64) | [`opensase-0.2.0-x64.msi`](https://github.com/yuky2020/opensase/releases/download/v0.2.0/opensase-0.2.0-x64.msi) | Installs the `OpenSASE` service, Wintun, the desktop app and `opensase-cli.exe`. Not code-signed yet: SmartScreen warns. |
| Debian, Ubuntu (amd64) | [`opensase_0.2.0_amd64.deb`](https://github.com/yuky2020/opensase/releases/download/v0.2.0/opensase_0.2.0_amd64.deb) | Installs the `opensased` service, the `opensase` group, the `opensase` CLI and the desktop app (`opensase-app`). `sudo apt install ./opensase_0.2.0_amd64.deb` |
| Android | [`opensase-0.2.0-android-debug.apk`](https://github.com/yuky2020/opensase/releases/download/v0.2.0/opensase-0.2.0-android-debug.apk) | Debug-signed build. |

See [Client](components/client.md) for enrolment and how the desktop daemon works.

### Server components (container images)

Images for `linux/amd64`, tagged with the version and `latest`:

```bash
docker pull ghcr.io/yuky2020/opensase-quickstart:0.2.0     # all in one: Control Plane + Edge, trials only
docker pull ghcr.io/yuky2020/opensase-controlplane:0.2.0   # Control Plane + admin portal
docker pull ghcr.io/yuky2020/opensase-edge:0.2.0           # Edge
docker pull ghcr.io/yuky2020/opensase-connector:0.2.0      # Connector (ZTNA)
docker pull ghcr.io/yuky2020/opensase-ocr:0.2.0            # optional OCR service for DLP
```

See [Quick start (all in one)](containers.md#quick-start-all-in-one) to run the Control Plane and Edge in a single container for trials. [Run the container images](containers.md) explains the first setup (PKI and first tenant) and a
`docker run` example for each component.

### Standalone binaries

| Platform | File | Contents |
|---|---|---|
| Linux amd64 | [`opensase-0.2.0-linux-amd64.tar.gz`](https://github.com/yuky2020/opensase/releases/download/v0.2.0/opensase-0.2.0-linux-amd64.tar.gz) | controlplane, edge, connector, opensasectl, opensase-client, opensased, opensase (CLI) |
| Linux arm64 | [`opensase-0.2.0-linux-arm64.tar.gz`](https://github.com/yuky2020/opensase/releases/download/v0.2.0/opensase-0.2.0-linux-arm64.tar.gz) | the same for arm64 |
| Windows amd64 | [`opensase-0.2.0-windows-amd64.zip`](https://github.com/yuky2020/opensase/releases/download/v0.2.0/opensase-0.2.0-windows-amd64.zip) | opensasectl, opensase-client, opensased, opensase (CLI) |

## Verify a download

```bash
curl -LO https://github.com/yuky2020/opensase/releases/download/v0.2.0/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

## Build from source

See [Getting started](getting-started.md) for the dev stack, and the repository `Makefile` for
the client and portal builds.
