# Operations

## Prerequisites on the box

```bash
useradd --system --home /var/lib/mng-cloud --shell /usr/sbin/nologin mng || true
install -d -o root -g root -m 0755 /var/www/mng-cloud-app/releases
install -d -o mng  -g mng  -m 0750 /var/lib/mng-cloud
install -d -o root -g root -m 0755 /etc/mng-cloud
install -d -o root -g root -m 0755 /usr/local/libexec
install -m 0644 ops/mngd.toml.example /etc/mng-cloud/mngd.toml
install -m 0644 ops/systemd/mngd.service /etc/systemd/system/mngd.service
install -m 0755 ops/mng-cloud-snapshot.sh /usr/local/libexec/mng-cloud-snapshot
install -m 0644 ops/systemd/mng-cloud-snapshot.service /etc/systemd/system/mng-cloud-snapshot.service
install -m 0644 ops/systemd/mng-cloud-snapshot.timer /etc/systemd/system/mng-cloud-snapshot.timer
systemctl daemon-reload
systemctl enable --now mng-cloud-snapshot.timer

# Session signing secret. Authentication fails closed until this exists:
# login returns 503, while /healthz, /readyz and /app/ keep serving.
openssl rand -base64 48 > /etc/mng-cloud/session.key
chown root:mng /etc/mng-cloud/session.key
chmod 0440 /etc/mng-cloud/session.key

# Alternative: keep the secret out of the filesystem.
# printf 'MNGD_SESSION_SECRET=%s\n' "$(openssl rand -base64 48)" \
#   > /etc/mng-cloud/mngd.env
# chmod 0600 /etc/mng-cloud/mngd.env
```

Rotating `session.key` invalidates every issued session. Keep the file out of
backups that are less protected than the database. `MNGD_SESSION_SECRET` takes
precedence over `MNGD_SESSION_SECRET_FILE`, which overrides
`session_key_file`.

`/var/lib/mng-cloud` already exists with application data; adjust ownership only
if `mngd` needs read/write access. `mngd` only stats it; database bytes come
from the read-only snapshot below.

## Read-only database snapshot

The PHP application owns `/var/lib/mng-cloud/mng-cloud.sqlite` in WAL mode.
`mngd` must not open that file: it cannot traverse the `www-data` directory and
a live WAL reader needs write access to the `-shm`/`-wal` files.

Instead, a root systemd timer copies the database through SQLite's online
backup API into tmpfs:

```
/var/lib/mng-cloud/mng-cloud.sqlite        (PHP, writer, www-data)
        │  sqlite3 .backup + PRAGMA quick_check   every minute
        ▼
/run/mng-cloud-snapshot/mng-cloud.sqlite  (root-owned, 0440 root:mng)
        │  immutable=1, read-only
        ▼
      mngd (mng)
```

Install the helper and timer once with the prerequisites above, then verify:

```bash
systemctl start mng-cloud-snapshot.service
ls -l /run/mng-cloud-snapshot/mng-cloud.sqlite
sudo -u mng sqlite3 /run/mng-cloud-snapshot/mng-cloud.sqlite 'SELECT COUNT(*) FROM users;'
journalctl -u mng-cloud-snapshot -n 20
```

Configure `mngd`:

```toml
database = "/run/mng-cloud-snapshot/mng-cloud.sqlite"
database_immutable = true
```

Properties of this design:

- The snapshot is replaced atomically; a request uses either the old or the new
  complete file.
- The refresh costs about 0.2 s of CPU and 8 MB of tmpfs per minute on the
  RK3229; it does not write to the SD/eMMC card.
- `/run` is cleared on reboot. The timer runs 15 s after boot; `mngd` stays up
  and reports `degraded` until the first snapshot exists, then recovers without
  a restart.
- Data can be up to one minute stale: user creation, password changes and
  deactivation take effect within that window. Do not use this model for data
  that must be read immediately after a write.
- `last_login_at` is never updated by `mngd`; the live database stays
  read-only.

## Build locally (Windows or Linux)

The ARMv7 binary links SQLite from source, so the build needs Zig's C compiler
and archiver wrappers in `tools/cross/`. Install Zig once with:

```bash
python -m pip install --user ziglang==0.16.0
```

Then:

```bash
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
./tools/build-armv7.sh          # Linux/macOS
# Windows: .\tools\build-armv7.ps1
```

Expected binary: `target/armv7-unknown-linux-musleabihf/release/mngd`.

The wrappers strip the `--target` flag the `cc` crate adds and select Zig's
`arm-linux-musleabihf` triple. Do not replace this with a plain `cargo build`;
bundled SQLite would be compiled for the build host.

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
- The extension build pins the same public JWK into `config.js`; rotating the
  key requires rebuilding and redistributing the extension.

## Sign a release

Package the app and create the signed release pointer:

```bash
cargo run -p mng-sign --release -- package \
  --web web \
  --out dist/app \
  --version 1.2.3 \
  --key /secure/offline/mng-update-key.json

cargo run -p mng-sign --release -- release \
  --app dist/app \
  --out dist/release \
  --version 1.2.3 \
  --sequence 42 \
  --app-base /app/ \
  --key /secure/offline/mng-update-key.json

cargo run -p mng-sign --release -- verify-release \
  --public-key ops/update-public.jwk \
  --dir dist/release \
  --app dist/app
```

`dist/app` contains `manifest.json`, `manifest.sig` and the stamped `sw.js`.
`dist/release` contains `release.json`, `release.sig` and copies of the signed
manifest files. `sequence` must increase with every published release; the
extension stores the highest sequence seen per browser and rejects a lower one.

`mng-sign release` refuses an existing output directory. Remove `dist/release`
before re-signing, and remove `dist/app` before repackaging.

## Publish the release metadata

GitHub Pages is the trusted transport for signed metadata. The production
repository is `https://github.com/AnhNguyenS/mng-cloud-rs` and the branch is
`gh-pages`; the extension reads:

```
https://anhnguyens.github.io/mng-cloud-rs/releases/current/
```

The branch contains only signed metadata and a small index page:

```
releases/current/release.json
releases/current/release.sig
releases/current/manifest.json
releases/current/manifest.sig
releases/<version>/...        immutable copy of the same four files
```

Publish from the offline signing machine after `mng-sign release`:

```powershell
.\tools\publish-release-metadata.ps1 -ReleaseDir dist\release
```

The script verifies the signatures again, refuses to overwrite a version
directory with different bytes, updates `releases/current/`, commits, and pushes
`gh-pages`. Use `-NoPush` to inspect the commit first. It never reads the
private key.

The cloud origin keeps serving only the app assets (`/app/`). Publishing the
app assets on GitHub is optional; the extension hashes the bytes it reads from
the cloud origin, not from GitHub. A GitHub Pages change can take a minute to
propagate, so check the URL before deploying the matching app release.

After publishing, verify the public metadata and the extension's pinned key:

```bash
cargo run -p mng-sign --release -- verify-release \
  --public-key ops/update-public.jwk \
  --dir dist/release
curl -fsS https://anhnguyens.github.io/mng-cloud-rs/releases/current/release.json
```

## Build the extension

The production config is checked in as `extension/config.production.json`. It
pins the cloud origin, `appBase`, the Pages release base and the update public
key. Change it only when the origin or key rotates; every change requires a new
extension build and version bump.

```bash
python tools/build-extension.py \
  --config extension/config.production.json \
  --production \
  --zip
```

`--production` refuses loopback origins and placeholder hostnames. The build
stamps `manifest.json`, writes `config.js` with the pinned public key, generates
the icons, and optionally writes `dist/extension.zip` with a SHA-256.

Load `dist/extension` as an unpacked extension. In Orion, use the extension
developer/load-unpacked flow; in Chromium, open `chrome://extensions`, enable
developer mode and choose **Load unpacked**. Chrome branded builds ignore
`--load-extension`; use Playwright's bundled Chromium for automated tests.

For local testing, `extension/config.local.json` (gitignored) points at
`http://127.0.0.1:8090` and the local release server. Build it with:

```bash
python tools/build-extension.py \
  --config extension/config.local.json \
  --out dist/extension
```

## Deploy

Upload only `mngd` and the signed `dist/app` directory, then on the server:

```bash
ops/deploy-mngd.sh \
  --binary /root/incoming/mngd \
  --app /root/incoming/app \
  --version 1.2.3
```

The script verifies the package signature if `mng-sign` and the public key are
present, installs the binary, creates an immutable release, swaps `current`
atomically and restarts `mngd`. If `/healthz` does not answer, it restores the
previous binary and symlink.

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

`/readyz` reports `status: ready` only when the web root, data directory,
readable database and session configuration are all present. A missing session
secret yields `status: degraded` with
`auth: { "available": false, "error": "..." }`.

### Authentication API

```bash
# Login (stores the HttpOnly cookie in a jar)
curl -sS -c /tmp/mng.jar -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}' \
  https://cloud.example.com/api/v1/auth/login | tee /tmp/mng-login.json

# Current user; the CSRF token is also returned here
curl -sS -b /tmp/mng.jar https://cloud.example.com/api/v1/auth/me

# Logout requires the CSRF token from the login/me response
CSRF=$(python -c 'import json;print(json.load(open("/tmp/mng-login.json"))["csrf"])')
curl -sS -b /tmp/mng.jar -H "X-CSRF-Token: $CSRF" -X POST \
  https://cloud.example.com/api/v1/auth/logout
```

### Read-only library API

```bash
# Identity, libraries and grouped counters in one response
curl -sS -b /tmp/mng.jar https://cloud.example.com/api/v1/bootstrap

# Owner-scoped listings and item detail
curl -sS -b /tmp/mng.jar 'https://cloud.example.com/api/v1/items?cloud=seafile&limit=20'
curl -sS -b /tmp/mng.jar https://cloud.example.com/api/v1/items/123
curl -sS -b /tmp/mng.jar https://cloud.example.com/api/v1/counts
curl -sS -b /tmp/mng.jar https://cloud.example.com/api/v1/stats

# Admin metadata; a non-admin session receives 403 forbidden
curl -sS -b /tmp/mng.jar https://cloud.example.com/api/v1/admin/users
```

A `cloud` the session user does not own returns `404`, including to an admin.
Item and count responses never contain password hashes or another owner's rows.
These routes are `GET` only and do not modify `thumb_state` or any other data.

Login is throttled per client IP and per IP+username; a blocked client gets
`429` with `Retry-After`. Behind nginx, `mngd` trusts `X-Forwarded-For` only
when the direct peer is loopback. Configure nginx to set
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

The legacy database is opened read-only, so a successful login does not update
`users.last_login_at` yet. That write moves to a dedicated native writer when
the PHP layer is retired.

In a private browser profile with the extension installed:

1. Open `/app/`; the badge should become `✓` and the banner should say
   `MNG Cloud đã xác minh v<version>`.
2. The extension popup should show the signed version, page version, source
   `GitHub (đã ký)` and the release sequence.
3. DevTools → Application → Cache Storage contains `mng-app-<version>`.
4. The page console has no CSP or Trusted Types violations.

### Tamper test

1. With the page verified, append a byte to a signed asset on the server
   (for example `app.css`).
2. Reload `/app/` in the same profile.
3. The badge must become `!`, the banner must say `KHÔNG AN TOÀN`, and the popup
   must list the hash/size mismatch. The page service worker's cached copy must
   not mask the change: the extension fetches the origin bytes directly.
4. Restore the file and re-sign or redeploy the original release.

### Rollback test

1. Keep the browser profile that has verified sequence N.
2. Serve signed release metadata with sequence N-1 (same `app_base`).
3. Reload `/app/`; the badge must become `!` and the popup must show the
   `rollback` error. The cached release must not be used to hide it.
4. Restore the current metadata.

### Unlisted resource test

1. With the page verified, inject an unlisted stylesheet or script into the DOM
   (for example a `<link rel="stylesheet" href="/app/assets/unlisted.css">`).
2. The content script's DOM/PerformanceObserver watch must report
   `unlisted_resource`; the badge must become `!` and the banner must switch to
   the red bar.
3. Remove the element; use **Kiểm tra lại** in the popup to re-verify.

## Current canary (2026-11-04)

The canary is installed but **not exposed through nginx** yet:

- user: `mng` (system account, no login shell)
- binary: `/usr/local/bin/mngd` (auth + RBAC + read API)
- app: `/var/www/mng-cloud-app/releases/0.1.4` (`current` symlink,
  directories `0555`, files `0444`)
- config: `/etc/mng-cloud/mngd.toml`
- session key: `/etc/mng-cloud/session.key` (`root:mng`, `0440`)
- database: `/run/mng-cloud-snapshot/mng-cloud.sqlite` (`mng`, `0440`,
  refreshed by `mng-cloud-snapshot.timer` every 60 s)
- public key: `/etc/mng-cloud/update-public.jwk`
- unit: `/etc/systemd/system/mngd.service` (enabled, `127.0.0.1:8090`)
- writable state: none; `/var/lib/mng-cloud` is only stat'ed for readiness

`readyz` reports `status: ready`, `database.mode: snapshot`, three users and
`auth.available: true`. A login probe with an unknown user returns
`401 bad_credentials`, which proves the snapshot and bcrypt path work without
touching a real account. Unauthenticated requests to `/api/v1/bootstrap`,
`/api/v1/clouds`, `/api/v1/items` and `/api/v1/admin/users` return
`401 auth_required`; the read routes are live on the loopback canary but not
exposed through nginx.

The signed app is `0.1.4` (sequence 4). Its metadata is published at
`https://anhnguyens.github.io/mng-cloud-rs/releases/current/` and every signed
asset hash was compared with
`/var/www/mng-cloud-app/releases/0.1.4` after deployment. The PHP tree and the
existing nginx vhost are untouched. `https://anh-cloud.duckdns.org/app/` still
returns 404: `/app/` and `/api/v1/*` are not public until nginx locations are
added deliberately.

Rollback point for this canary:
`/root/mng-cloud-backup-rbac-20261104-004457` (binary, config, unit).

```bash
systemctl status mngd
systemctl status mng-cloud-snapshot.timer
curl -fsS http://127.0.0.1:8090/healthz
curl -fsS http://127.0.0.1:8090/readyz
journalctl -u mngd --since -10min
journalctl -u mng-cloud-snapshot --since -10min
```

## Rollback

- App: point `current` at the previous release and restart `mngd`.
- Service: `systemctl stop mngd`; nginx `/app/` returns 502 until removed.
- nginx: remove the `/app/` location; legacy PHP is untouched.
- Never roll back Seafile data as part of an application rollback.
- Never lower the signed release `sequence`. Publish a new release with a new
  version and a higher sequence instead.

## Monitoring

- `systemctl status mngd`
- `journalctl -u mngd -f`
- `curl /healthz` every minute from a local probe
- Alert on `MemoryMax` pressure, restart count and 5xx rate at nginx.

The extension keeps its state locally (`chrome.storage.local`): the highest
verified release sequence and the last verified metadata. It sends no telemetry
and does not forward page content.

## Key rotation

1. Generate a new key offline.
2. Build and sign a transition release; ship the new public key in a new
   extension build and keep the old extension/key valid until users update.
3. After the transition window, retire the old key.
4. Rotate any session/database secrets separately.

Losing the private key is not a data-loss event for E2EE libraries, but it
blocks new signed releases until a new key is bootstrapped and the extension is
rebuilt.
