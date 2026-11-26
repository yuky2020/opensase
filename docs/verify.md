# Verify a download

Releases from v0.3.0 on are signed by the release workflow with [cosign](https://docs.sigstore.dev/)
in keyless mode: there is no long-lived signing key. The signature certificate names the
workflow file and the tag that built the release, and it is logged in the public Sigstore
transparency log.

You need `cosign` (v2 or later) and `sha256sum`. To check build provenance, you also need the
`gh` command line tool.

## Release files (MSI, packages, APK, binaries)

1. Download the files you want, `SHA256SUMS` and `SHA256SUMS.sigstore.json` from the release.
2. Check the signature of `SHA256SUMS`:

    ```bash
    cosign verify-blob SHA256SUMS \
      --bundle SHA256SUMS.sigstore.json \
      --certificate-identity-regexp '^https://github.com/yuky2020/opensase/.github/workflows/release.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    ```

    The command prints `Verified OK`. Any other output means the file was not produced by the
    OpenSASE release workflow: do not install it.

3. Check your downloads against the signed checksums:

    ```bash
    sha256sum -c SHA256SUMS --ignore-missing
    ```

The Windows MSI is not code-signed, so Windows SmartScreen shows a warning when you open it.
Install it only after the two checks above pass.

## Container images

```bash
cosign verify ghcr.io/yuky2020/opensase-edge:0.3.0 \
  --certificate-identity-regexp '^https://github.com/yuky2020/opensase/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use the same command for `opensase-controlplane`, `opensase-connector`, `opensase-ocr` and
`opensase-quickstart`. In production, pin images by the digest that the command prints.

## SBOM

Every image carries an SPDX SBOM as a signed attestation:

```bash
cosign verify-attestation --type spdxjson ghcr.io/yuky2020/opensase-edge:0.3.0 \
  --certificate-identity-regexp '^https://github.com/yuky2020/opensase/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r .payload | base64 -d | jq .predicate
```

Each release also includes an SBOM of the source tree, `opensase-<version>-source.spdx.json`.

## Build provenance

Each release file and image also has a GitHub build provenance attestation (SLSA):

```bash
gh attestation verify opensase-0.3.0-x64.msi --repo yuky2020/opensase
gh attestation verify oci://ghcr.io/yuky2020/opensase-edge:0.3.0 --repo yuky2020/opensase
```
