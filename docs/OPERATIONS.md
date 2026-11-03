# Operations

## Prerequisites on the box

```bash
useradd --system --home /var/lib/mng-cloud --shell /usr/sbin/nologin mng || true
install -d -o root -g root -m 0755 /var/www/mng-cloud-app/releases
install -d -o mng  -g mng  -m 0750 /var/lib/mng-cloud
install -d -o root -g root -m 0755 /etc/mng-cloud
install -m 0644 ops/mngd.toml.example /etc/mng-cloud/mngd.toml
install -m 0644 ops/systemd/mngd.service /etc/systemd/system/mngd.service
systemctl daemon-reload
```

`/var/lib/mng-cloud` already exists with application data; adjust ownership only
if `mngd` needs read/write access. The phase-1 service only stats it.

## Build locally (Windows or Linux)

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p mngd --release --target armv7-unknown-linux-musleabihf
```

Expected binary: `target/armv7-unknown-linux-musleabihf/release/mngd`.

## Build the WASM engine

Install once:

```bash
cargo install wasm-bindgen-cli --version 0.2.130 --locked
```

Build:

```bash
cargo build -p mng-wasm --release --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript \
  --out-dir web/assets/wasm \
  target/wasm32-unknown-unknown/release/mng_wasm.wasm
```

## Create the offline signing key (once)

On a machine that is not the server and is not CI:

```bash
cargo run -p mng-sign --release -- keygen \
  --out /secure/offline/mng-update-key.json \
  --pub-out ops/update-public.jwk
```

- Back up the private JSON offline.
- Copy only the public JWK to the server at
  `/etc/mng-cloud/update-public.jwk`.
- Never commit the private key; `.gitignore` blocks the default paths.

## Sign a release

```bash
cargo run -p mng-sign --release -- package \
  --web web \
  --out dist/app \
  --version 1.2.3 \
  --key /secure/offline/mng-update-key.json
```

`dist/app` now contains `manifest.json`, `manifest.sig` and the stamped
`sw.js`. Verify before uploading:

```bash
cargo run -p mng-sign --release -- verify \
  --public-key ops/update-public.jwk \
  --dir dist/app
```

## Deploy

Upload only `mngd` and the signed `dist/app` directory, then on the server:

```bash
ops/deploy-mngd.sh \
  --binary /root/incoming/mngd \
  --app /root/incoming/app \
  --version 1.2.3
```

The script verifies the signature if `mng-sign` and the public key are present,
installs the binary, creates an immutable release, swaps `current` atomically
and restarts `mngd`. If `/healthz` does not answer, it restores the previous
binary and symlink.

Enable nginx only after the health check passes:

```bash
# add ops/nginx/mngd.conf inside the TLS server block
nginx -t && systemctl reload nginx
```

## Verify

```bash
curl -fsS http://127.0.0.1:8090/healthz
curl -fsS http://127.0.0.1:8090/readyz
curl -sI https://cloud.example.com/app/ | grep -i -E 'content-security-policy|cache-control|strict-transport'
```

In a private browser profile:

1. Open `/app/`; confirm the service worker is activated.
2. DevTools → Application → Cache Storage contains `mng-app-<version>`.
3. Change an asset on the server without re-signing; reload should keep the
   cached signed version, and a new install/update must fail verification.
4. Confirm the console has no CSP or Trusted Types violations.

## Current canary (2026-11-03)

The first canary is installed but **not exposed through nginx** yet:

- user: `mng` (system account, no login shell)
- binary: `/usr/local/bin/mngd`
- app: `/var/www/mng-cloud-app/releases/0.1.3` (`current` symlink)
- config: `/etc/mng-cloud/mngd.toml`
- public key: `/etc/mng-cloud/update-public.jwk`
- unit: `/etc/systemd/system/mngd.service` (enabled, `127.0.0.1:8090`)
- writable state: none yet; `/var/lib/mng-cloud` is only stat'ed for readiness

The PHP tree and the existing nginx vhost are untouched. `/app/` is not
public until the nginx location is added deliberately.

```bash
systemctl status mngd
curl -fsS http://127.0.0.1:8090/healthz
curl -fsS http://127.0.0.1:8090/readyz
journalctl -u mngd --since -10min
```

## Rollback

- App: point `current` at the previous release and restart `mngd`.
- Service: `systemctl stop mngd`; nginx `/app/` returns 502 until removed.
- nginx: remove the `/app/` location; legacy PHP is untouched.
- Never roll back Seafile data as part of an application rollback.

## Monitoring

- `systemctl status mngd`
- `journalctl -u mngd -f`
- `curl /healthz` every minute from a local probe
- Alert on `MemoryMax` pressure, restart count and 5xx rate at nginx.

## Key rotation

1. Generate a new key offline.
2. Build and sign a transition release; ship the new public key in a new
   `sw.js` and keep the old key valid until clients have updated.
3. After the transition window, retire the old key.
4. Rotate any session/database secrets separately.

Losing the private key is not a data-loss event for E2EE libraries, but it
blocks new signed releases until a new key is bootstrapped.
