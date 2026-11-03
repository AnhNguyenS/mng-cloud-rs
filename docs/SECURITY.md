# Security model

## Trust source

The cloud origin is **not** trusted to describe itself. The trust anchor is the
P-256 public key pinned in the browser extension at build time:

```
offline signing machine                 GitHub repository / Pages
  mng-sign package ──┐                   release.json + release.sig
  mng-sign release ──┴── signed bytes ──► manifest.json + manifest.sig
                                                │
                                                ▼
                                   Orion / Chromium + MNG Trusted extension
                                     pinned P-256 key (config.js)
                                     ├── verify release + manifest signatures
                                     ├── enforce monotonic release sequence
                                     ├── fetch every signed asset directly
                                     ├── SHA-256 the actual response bytes
                                     ├── observe navigation status/MIME
                                     └── scan DOM/performance for unlisted files
                                                │
                                                ▼
                                        Cloud / mng-cloud origin
                                     (frontend · API · Seafile)
```

The extension is authoritative for the green badge. The PWA's own service
worker still verifies the signed manifest before caching (defense in depth),
but it is no longer the update trust anchor.

## Boundaries

| Asset | Where it lives | Who can read it |
| --- | --- | --- |
| Library password | browser memory | user only |
| Derived content key/IV | Rust/WASM linear memory | browser tab only |
| Encrypted blocks | Seafile storage | server and storage admins |
| Update private key | offline signing machine | release signer only |
| Update public key | extension `config.js` + `sw.js` | public |
| Release metadata | GitHub repository / Pages | public |
| Session signing secret | `/etc/mng-cloud/session.key` or `MNGD_SESSION_SECRET` | root, `mng` process |
| Password hashes | legacy SQLite `users` table | `mng` process, read-only |

`mngd` never accepts a library password. There is no server-side fallback that
can decrypt blocks; a compromised server can delete or withhold ciphertext,
but cannot recover plaintext without the user's password.

## E2EE engine

- The exact Seafile v2/v3 derivation is implemented once in
  `crates/mng-core/src/crypto/e2ee.rs`.
- `mng-wasm` exposes only `unlock`, `encryptBlock`, `decryptBlock`,
  `ciphertextLen` and `blockId`.
- Key material is held in `Zeroizing` buffers and dropped with the session.
- Known-answer tests are generated with the browser's WebCrypto implementation,
  so a change in padding, PBKDF2 rounds or concatenation order fails CI.
- JavaScript is limited to UI and the browser adapter; it does not reimplement
  crypto.

## Authentication

- `mng-auth` verifies legacy PHP-compatible password hashes: bcrypt `$2y$`,
  `$2b$`, `$2a$` and Argon2 (`$argon2id$`, `$argon2i$`, `$argon2d$`).
- Unknown usernames and inactive accounts perform the same bcrypt work as a
  real check before returning `401`, so response timing does not leak account
  existence.
- Sessions are stateless HMAC-SHA256 cookies (`HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/`) with a random nonce and per-session CSRF token.
  Only the secret is stored; there is no server-side session table to steal.
- Every unsafe `/api/v1` request requires `X-CSRF-Token` matching the token
  bound into the signed cookie. Login is the only unauthenticated write route.
- Login attempts are throttled in memory per client IP and per IP+username.
  Multi-process deployments need a shared limiter before scaling out.
- The session secret must be at least 32 bytes. If it is missing, login fails
  closed with `503`; the static PWA and health probes remain available.
- `last_login_at` is not written while SQLite is opened read-only.

## Authorization

- Authentication answers *who* is calling; authorization uses the `users` row
  loaded on that same request. The cookie carries the uid but never the role,
  so demoting an admin or deactivating an account takes effect on the next
  request instead of waiting for session expiry.
- `/api/v1/items`, `/api/v1/counts`, `/api/v1/clouds`, `/api/v1/bootstrap` and
  `/api/v1/stats` are constrained to `owner_id = session user`. A `cloud`
  parameter must be present in that user's `user_clouds` rows.
- A missing, unowned or unknown library returns `404`; it never returns `403`
  with a name, so one user cannot enumerate another user's library keys.
- `/api/v1/admin/users` and `/api/v1/admin/users/{id}` require the admin role.
  Admin access is limited to account and aggregate metadata. It does **not**
  grant access to another owner's item rows; encrypted-library metadata stays
  owner-only even for administrators.
- The read API is strictly `GET`; it cannot mutate item state, thumbnails,
  users or Seafile data. Unsafe routes will require CSRF when mutations are
  added.

## Read-only database snapshot

The legacy SQLite database is owned by `www-data` and stays in WAL mode for the
PHP application. `mngd` never opens it. A root systemd timer copies it with
SQLite's online backup API, runs `PRAGMA quick_check`, and atomically replaces
`/run/mng-cloud-snapshot/mng-cloud.sqlite` (mode `0440`, owner `root:mng`).
`mngd` opens the snapshot with `immutable=1`.

- The snapshot is tmpfs-only: no extra eMMC/SD writes and no persistent copy of
  password hashes outside the original database.
- The `mng` account gets read-only access to a single database file, not to
  `/var/lib/mng-cloud`, the WAL/SHM files, or the PHP secrets.
- Snapshot contents are at most one minute old. A deactivated account or
  changed password can remain valid for that window.
- A corrupted or unreadable source leaves the previous snapshot in place; the
  timer fails loudly in the journal instead of publishing partial bytes.

## Immutable frontend

- Releases are copied to `/var/www/mng-cloud-app/releases/<version>/`, owned by
  `root`, mode `0555` for directories and `0444` for files.
- `current` is an atomic symlink.
- `mngd` runs as `mng` with `ProtectSystem=strict`; it can read the release but
  not write it.
- PHP-FPM, if still present during the transition, must not be in the `mng`
  group and has no write path into the release tree.

## Signed releases

`mng-sign package` performs the offline packaging step:

1. Copy the web template.
2. Stamp `APP_VERSION` and the public P-256 JWK into `sw.js`.
3. Hash every asset with SHA-256 and record its browser-facing MIME type.
4. Sign the canonical manifest bytes with ECDSA P-256 / SHA-256.
5. Write `manifest.json` and `manifest.sig` (raw `r||s`, hex).

`mng-sign release` then publishes the release pointer:

1. Verify the package against the same public key.
2. Write `release.json` containing the version, monotonic `sequence`,
   `app_base`, manifest SHA-256 and manifest file names.
3. Sign `release.json` into `release.sig`.
4. Copy `manifest.json` and `manifest.sig` next to the release metadata for a
   self-contained GitHub Pages directory.

Only the four files in the release directory and the signed app assets go to
GitHub. The private key is generated by `mng-sign keygen` on an offline machine.
It is never committed, never uploaded to GitHub and never copied to the server.
CI artifacts are unsigned; deployment refuses a directory without a manifest.

### Extension verification

Before showing a green badge the extension:

1. Fetches `release.json` and `release.sig` from `releaseBase` (GitHub), not
   from the cloud origin.
2. Verifies the ECDSA signature with the pinned public JWK.
3. Validates schema, semver version, positive sequence, `app_base` and all
   relative paths.
4. Rejects `sequence` lower than the highest sequence this browser has seen, or
   a reused sequence with a different version (rollback guard in
   `chrome.storage.local`).
5. Fetches `manifest.json`/`manifest.sig`, verifies the signature and checks the
   manifest SHA-256 against `release.json`.
6. Fetches every manifest asset **directly from the cloud origin** using the
   extension's host permission. This bypasses a page-controlled service worker
   and gives the extension the origin's actual bytes. SHA-256, size and MIME are
   compared with the signed manifest.
7. In parallel, the content script re-fetches every signed asset in the page's
   origin. This catches a page service worker that serves modified bytes to the
   document even when the origin's stored files are genuine.
8. Hashes the HTML document against the signed `index.html` and checks the
   visible `mng-version` meta tag against the signed release.
9. Watches `webNavigation`/`webRequest` for navigation status, MIME and
   `X-Content-Type-Options: nosniff`.
10. Watches DOM mutations and resource timing entries for critical resources
    (scripts, stylesheets, manifests, fonts, WASM) that are not in the signed
    manifest.

### Failure classification

| Condition | State |
| --- | --- |
| Signatures, manifest hash, version, `app_base` or rollback guard fail | **NOT SAFE** (red) |
| Any signed asset hash, size or MIME differs; unlisted critical resource; failed load; document mismatch | **NOT SAFE** (red) |
| Release metadata cannot be fetched / transport error | **Unverified** (amber); a previously verified release may be used with a visible warning |
| Page or content script cannot complete in time | **Unverified** (amber) |
| All checks complete | **Verified** (green) |

A bad signature or rollback is never hidden by the cached release. Cache
fallback exists for connectivity failures only.

### Known limitations

- A page-controlled service worker can make subresource requests appear to the
  extension's `webRequest` listener as worker traffic with no tab id. The
  extension therefore does not depend on `webRequest` for asset integrity: it
  hashes the origin bytes itself and the content script watches what the DOM
  actually requests.
- Browser extension APIs do not expose every response body. Integrity coverage
  is the signed static release, the document, navigation metadata and observed
  resource loads. API responses are protected by TLS and the session model, not
  by the release manifest.
- The extension itself is the trust anchor. It must be installed and updated
  from a trusted distribution channel. Sideloaded builds should be compared
  with a published SHA-256.
- The first visit before the PWA service worker is installed is protected by
  the extension's direct fetch; a previously compromised browser profile with a
  malicious controlling worker is outside the model.
- Key rotation requires shipping a new extension build with the new pinned key
  (or a transition release that trusts both keys). Plan rotation before the
  first production release.

## CSP and Trusted Types

`mngd` enforces on every response:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
worker-src 'self';
style-src 'self';
img-src 'self' blob: data:;
media-src 'self' blob:;
connect-src 'self';
font-src 'self';
object-src 'none';
base-uri 'none';
frame-ancestors 'none';
form-action 'self';
require-trusted-types-for 'script';
trusted-types mng-ui;
```

The shell has no inline script, no inline style, no `eval` and no `innerHTML`.
DOM updates use `textContent` and explicit element creation. If a future
component needs an HTML sink, it must create the named `mng-ui` policy and
sanitize its input; do not add `'unsafe-inline'` or `'unsafe-eval'`.

## Build and supply chain

- Source lives in a private Git repository, not on the server.
- GitHub Actions builds ARMv7 from a tagged commit and publishes SHA-256
  checksums.
- The server receives only the binary and the signed static release.
- GitHub Pages (or the repository's release branch) hosts the signed
  `release.json`, `release.sig`, `manifest.json` and `manifest.sig`.
- The extension is built from `extension/src` by `tools/build-extension.py`,
  which pins the public key and stamps allowed deployment origins.
- `Cargo.lock` is committed; dependency updates are reviewed.
- `#![forbid(unsafe_code)]` is set in the native and WASM crates.
- Release binaries are stripped and statically linked against musl.

## Secrets and logging

- Never log passwords, derived keys, `magic`, `random_key` or block URLs with
  tokens.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, with a
  per-session CSRF token. Rotate the signing secret to revoke every session.
- The blank-media audit log records owner id, filename, size and quarantine
  path; it contains no file content.
- Rotate the update signing key if the offline machine is lost. A new key
  requires a new extension build (or a signed transition release); plan this
  before the first production release.
