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
                     ├── immutable signed PWA                 (C, upstream)          (Python, upstream)
                     ├── /api/v1/* auth, RBAC, media
                     └── /healthz /readyz
```

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
                                  cargo build --target armv7
                                  wasm-pack build
                                        │
                                        ▼
                                  unsigned artifact
                                        │
                                        ▼
                                  mng-sign package ── private P-256 key
                                        │              (never uploaded)
                                        ▼
                                  signed manifest + assets
                                        │
                                        ▼
                                  server: deploy-mngd.sh
                                  verify public key → install read-only
```

GitHub Actions never receives the signing key. The server receives a native
ARMv7 binary, the signed static release and the public key only.

## Non-goals in this slice

- Replacing Seahub's admin UI.
- Moving MariaDB/Redis.
- Changing the existing Seafile or E2EE on-disk format.
- Making the legacy PHP UI Trusted-Types compliant; it is retired rather than
  patched.
