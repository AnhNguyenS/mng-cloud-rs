# Architecture

## Target shape

```
                         TLS 1.2/1.3 (ChaCha20-Poly1305)
Internet ───────────────────────────────────────────────► nginx
                                                            │
                     ┌──────────────────────────────────────┼─────────────────────┐
                     │                                      │                     │
                     ▼                                      ▼                     ▼
              /app/  mngd (Rust)                    /seafhttp/ seaf-server   /seahub/ Seahub
                     │                              127.0.0.1:8082           127.0.0.1:8000
                     ├── signed PWA (defense in depth)       (C, upstream)          (Python, upstream)
                     ├── /api/v1/* auth, RBAC, media
                     └── /healthz /readyz
```

The browser is not just a client of the origin. Before trusting `/app/`, the
MNG Trusted extension reads signed release metadata from GitHub and compares it
with bytes fetched directly from the cloud origin:

```
        GitHub repository / Pages                      Cloud origin
   release.json · release.sig                    /app/ · /api/v1/* · Seafile
   manifest.json · manifest.sig                           │
                 │ signed bytes                           │
                 ▼                                        │
   Orion / Chromium + MNG Trusted extension                │
     pinned P-256 public key                               │
     verify signatures + sequence ─────────────────────────┘
     hash assets + watch DOM/requests          (extension sees both sides)
```

GitHub is only transport for signed bytes. The extension makes the trust
decision; the cloud origin is never trusted to describe itself.

- **Seafile stays upstream.** `seaf-server` owns repositories, blocks and the
  encrypted-library format. Seahub remains available for upstream admin and
  compatibility while the custom UI is ported.
- **The custom layer moves to Rust.** PHP (`api.php`, `lib/*.php`, `bin/*.php`)
  is replaced slice by slice by `mngd`. No PHP is introduced in the new tree.
- **E2EE is client-side.** Plaintext, passwords and derived keys never reach
  `mngd`. The browser calls the Rust/WASM engine; `mngd` only relays Seafile
  metadata and one-time block URLs.
- **The frontend is immutable.** Releases live in versioned, read-only
  directories. `mngd` serves them; no runtime process has write access.
- **Updates are verified outside the origin.** The PWA service worker still
  verifies the signed manifest before caching, but the extension is the trust
  anchor and fails closed to red when signatures, hashes, MIME, sequence or
  resource lists differ.

## Ports and trust zones

| Component | Bind | Trust |
| --- | --- | --- |
| nginx | `0.0.0.0:443` | public edge, TLS termination |
| `mngd` | `127.0.0.1:8090` | loopback only, unprivileged `mng` user |
| `seaf-server` | `127.0.0.1:8082` | loopback, upstream |
| Seahub | `127.0.0.1:8000` | loopback, upstream |
| MariaDB / Redis | loopback | upstream state |

`mngd` runs with `ProtectSystem=strict`, an empty capability set and a
read-only view of `/var/www/mng-cloud-app` and `/etc/mng-cloud`. Only
`/var/lib/mng-cloud` is writable.

## E2EE data flow

1. Browser asks `mngd` for library metadata (`enc_version`, `magic`,
   `random_key`, optional v3 salt).
2. Browser passes the password and public metadata to `mng-wasm`.
3. Rust verifies `magic`, decrypts the 48-byte random key, derives the content
   key/IV and keeps them in WASM memory.
4. Browser reads encrypted blocks from `/seafhttp/blks/<token>/<id>`, decrypts
   them in WASM and renders the result.
5. Uploads encrypt each 8 MiB plaintext block in WASM, hash the ciphertext for
   the block id, request missing-block URLs, upload raw blocks and commit the
   file.

The fixed salt, PBKDF2 iteration counts and AES-CBC layout are documented in
`crates/mng-core/src/crypto/e2ee.rs` and locked by WebCrypto-generated vectors
in `crates/mng-core/tests/fixtures/e2ee_kat.json`.

## Authentication and API sessions

```
POST /api/v1/auth/login   ── bcrypt/Argon2 verify against users.password_hash
                          └─► HMAC-SHA256 session cookie + CSRF token
GET  /api/v1/auth/me      ── signed cookie → fresh user row (active flag)
POST /api/v1/auth/logout  ── requires X-CSRF-Token, clears the cookie
```

- `mng-auth` contains the password, session and rate-limit primitives. `mngd`
  provides the SQLite row, client address and HTTP mapping.
- Sessions are stateless: the cookie carries uid, username, expiry, nonce and
  CSRF token, signed with a key derived from `/etc/mng-cloud/session.key`.
- Passwords never leave the request body; logs contain only the username, uid
  and client IP.
- The database connection used for login is read-only. `last_login_at` stays
  untouched until a dedicated native writer replaces PHP.
- The read model comes from a root timer that copies the live WAL database into
  `/run/mng-cloud-snapshot/mng-cloud.sqlite` every minute. `mngd` opens that
  immutable snapshot as `mng`, so it never needs access to the `www-data`
  directory or the live WAL/SHM files.
- `readyz` exposes whether auth is configured and whether the snapshot is
  readable, so a missing secret or stale snapshot is visible without exposing
  secrets.

## Read-only library API

```
GET  /api/v1/bootstrap        identity, CSRF, libraries, counts
GET  /api/v1/clouds           libraries owned by the session user
GET  /api/v1/counts           grouped photo/video counts (optional cloud)
GET  /api/v1/items            filters: cloud, type, favorite, limit, offset
GET  /api/v1/items/{id}       one item plus its Live Photo companion
GET  /api/v1/stats            owner counters and thumbnail-state counts
GET  /api/v1/admin/users      all accounts and aggregate counts (admin only)
GET  /api/v1/admin/users/{id} one account, libraries and counts (admin only)
```

- The session middleware loads the `users` row on every protected request.
  Roles and the `active` flag therefore come from the database, not from the
  cookie; a deactivated account or a revoked admin role is rejected on the
  next request.
- Item and count queries are always constrained by `owner_id = session user`.
  A `cloud` parameter must also exist in that user's `user_clouds` rows.
  Unowned libraries and other users' item ids return `404`, which avoids
  confirming that a library exists for someone else.
- Admin rights unlock only `/api/v1/admin/*` metadata. They never bypass the
  owner scope for items or libraries; encrypted-library metadata remains
  private even to an administrator.
- `.backup` snapshots are immutable and read-only. No handler writes
  `last_login_at`, item state, thumbnails or anything else. All mutations stay
  in the PHP layer until the native writer slice.

## Why not rewrite `seaf-server`

`seaf-server` is the storage engine and the compatibility boundary for the
on-disk format. Replacing it would put existing libraries at risk and would not
improve the browser E2EE boundary. The migration therefore replaces the
**custom** PHP layer, not upstream Seafile. This is the scope confirmed for this
project.

## Release chain

```
developer machine                 GitHub Actions                 offline machine
-----------------                 --------------                 ---------------
commit/tag ─────────────────────► test + clippy
                                  tools/build-armv7.sh (Zig)
                                  wasm build
                                        │
                                        ▼
                                  unsigned artifact
                                        │
                                        ▼
                                  mng-sign package ── private P-256 key
                                  mng-sign release ── (never uploaded)
                                        │
                                        ▼
                                  signed app + signed release metadata
                                        │
                       ┌────────────────┴────────────────┐
                       ▼                                 ▼
              GitHub Pages (release/)            server: deploy-mngd.sh
              release.json / release.sig         verify, install read-only
              manifest.json / manifest.sig
                       │
                       ▼
              extension fetches, verifies, hashes cloud bytes
```

GitHub Actions never receives the signing key. The server receives a native
ARMv7 binary, the signed static release and the public key only. The extension
receives no secret: it pins the public key and reads public, signed metadata.

## Non-goals in this slice

- Replacing Seahub's admin UI.
- Moving MariaDB/Redis.
- Changing the existing Seafile or E2EE on-disk format.
- Making the legacy PHP UI Trusted-Types compliant; it is retired rather than
  patched.
