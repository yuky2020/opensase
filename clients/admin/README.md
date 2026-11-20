# OpenSASE admin portal

Flutter web app for the Control Plane admin API (`/v1/admin/...`, see `pkg/api/types.go`).
It uses Material 3, Riverpod and go_router, with Italian and English translations, the same as
`clients/mobile`. The Control Plane serves the release build at `https://<cp>:9443/admin/`, so
the portal has the same origin as the API and needs no CORS.

Screens: Overview, Tenants, Users (with provisioning keys and the enrollment QR code), Policy
(a form and a raw JSON tab kept in sync), Private apps (ZTNA), Connectors, Devices, Edges,
Activity, and Settings.

## Build

```sh
make portal          # flutter build web --release --base-href /admin/ --no-web-resources-cdn
make portal-test     # flutter analyze && flutter test
```

Or run it by hand:

```sh
export PATH=~/opt/flutter/bin:$PATH
cd clients/admin
flutter pub get
flutter build web --release --base-href /admin/ --no-web-resources-cdn   # output: build/web
```

`--no-web-resources-cdn` and the bundled Roboto fonts (`assets/fonts`, Apache 2.0) are
required. The Control Plane sends a same-origin-only CSP
(`script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; font-src 'self' data:`), so
CanvasKit and fonts from Google CDNs would be blocked.

## Run against the dev stack

```sh
make portal
cd deploy/dev && ./bootstrap.sh          # once: PKI, admin token and demo tenant in deploy/dev/.env
```

Start the Control Plane with `-portal-dir`, pointing at the build. In `deploy/dev`, mount
`clients/admin/build/web` into the controlplane container and add the flag, for example:

```yaml
    volumes:
      - ../../clients/admin/build/web:/portal:ro
    command: [..., "-portal-dir", "/portal"]
```

Or run the binary directly: `bin/controlplane ... -portal-dir clients/admin/build/web`.

Then:

1. Open `https://localhost:9443/admin/`. The dev CA is `deploy/dev/pki/root.crt`; trust it in
   the browser or accept the warning. The browser must support X25519MLKEM768, which current
   Chrome, Edge and Firefox do.
2. Paste `OPENSASE_ADMIN_TOKEN` from `deploy/dev/.env`. Tick "Remember for this tab" to keep
   it in this tab's `sessionStorage`. Otherwise it stays in memory only and a reload signs
   you out. The token is never written to `localStorage`.
3. In **Settings**, set the control URL used in enrollment QR codes to
   `OPENSASE_CONTROL_URL` from `.env` (`https://<host>:9443#sha256=<root CA pin>`). For the
   Android emulator, use the `10.0.2.2` form.

For UI work without a Control Plane, `flutter run -d chrome` also works. API calls go to the
dev server's origin, though, so they fail unless something serves `/v1/admin` there.

## Layout

- `lib/src/api/`: wire models (hand-written `fromJson`/`toJson`, matching the Go struct tags
  and `omitempty`) and `AdminApi` (Bearer token, paths resolved against `Uri.base`).
- `lib/src/data/`: session (token), settings, Riverpod providers, the policy editor model
  (form/JSON sync), client-side validation that mirrors the server, the enrollment deep link
  and flow statistics.
- `lib/src/ui/`: screens and dialogs. `lib/src/l10n/`: ARB files (`flutter gen-l10n`).
- `test/`: model round trips, logic and API client tests, and widget tests for login, the
  policy editor sync, provisioning QR codes and revoking Connectors.
