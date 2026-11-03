# MNG Cloud — Rust / WASM

Private rewrite of the `mng-cloud` layer in front of the upstream Seafile
storage engine (`seaf-server` + Seahub). The server only receives native
binaries and signed static assets; source lives in this repository, never on
the production box.

## Layout

| Path | Purpose |
| --- | --- |
| `crates/mng-core` | Config, Seafile E2EE crypto, chunk and manifest primitives |
| `crates/mngd` | Native HTTP service: immutable PWA, health, future API/auth/RBAC |
| `crates/mng-wasm` | Browser-facing E2EE engine compiled to WebAssembly |
| `crates/mng-sign` | Offline release signer (P-256 ECDSA) and verifier |
| `web/` | PWA shell + JavaScript browser adapter |
| `ops/` | systemd, nginx, deploy and verification scripts |
| `docs/` | Architecture, migration plan, security and operations |

## Local checks

```powershell
cargo test -p mng-core
cargo build -p mngd -p mng-sign
```

ARMv7 static release (source stays on the build machine):

```powershell
cargo build -p mngd --release --target armv7-unknown-linux-musleabihf
```

The GitHub Actions workflow in `.github/workflows/` runs the same commands and
publishes checksummed artifacts.

## Trust boundaries

- Library passwords and derived keys exist only in the browser, inside the
  Rust/WASM engine. `mngd` never receives them.
- The update signing key is generated and used offline. CI and the server only
  see the public key.
- The PWA verifies the signed manifest, every asset hash and the version before
  caching an update.

See `docs/SECURITY.md` for the full model and current limitations.
