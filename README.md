# MNG Cloud — Rust / WASM

Private rewrite of the `mng-cloud` layer in front of the upstream Seafile
storage engine (`seaf-server` + Seahub). The server only receives native
binaries and signed static assets; source lives in this repository, never on
the production box.

## Layout

| Path | Purpose |
| --- | --- |
| `crates/mng-core` | Config, Seafile E2EE crypto, chunk and manifest primitives |
| `crates/mng-auth` | Password verification, signed sessions, CSRF and login rate limiting |
| `crates/mng-db` | Read-only SQLite models for users, libraries and items |
| `crates/mngd` | Native HTTP service: immutable PWA, health, auth, RBAC, read-only library API |
| `crates/mng-wasm` | Browser-facing E2EE engine compiled to WebAssembly |
| `crates/mng-sign` | Offline release signer (P-256 ECDSA) and verifier |
| `extension/` | MNG Trusted browser extension (Chromium MV3 / Orion) |
| `web/` | PWA shell + JavaScript browser adapter |
| `ops/` | systemd, nginx, deploy, snapshot and verification scripts |
| `docs/` | Architecture, migration plan, security and operations |

## Local checks

```powershell
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
node --test extension/tests/trust.test.mjs
```

ARMv7 static release (source stays on the build machine):

```powershell
python -m pip install --user ziglang==0.16.0
.\tools\build-armv7.ps1
```

The GitHub Actions workflow in `.github/workflows/` runs the same commands,
plus the extension tests and browser build.

## Trust boundaries

- Library passwords and derived keys exist only in the browser, inside the
  Rust/WASM engine. `mngd` never receives them.
- The update signing key is generated and used offline. CI and the server only
  see the public key.
- The MNG Trusted extension verifies signed release metadata from GitHub,
  hashes the bytes the cloud origin returns, and fails closed to a red warning.
- The PWA service worker still verifies the signed manifest before caching an
  update; it is defense in depth, not the trust anchor.

See `docs/SECURITY.md` for the full model and current limitations.
