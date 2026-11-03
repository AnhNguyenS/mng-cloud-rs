# Migration plan

The migration is sliced so production keeps working after every step. Each
slice has a rollback path and no slice rewrites Seafile data.

| # | Slice | State | Exit criteria |
| --- | --- | --- | --- |
| 0 | Baseline, blank-media guard, perf/stability | done | importers quarantine all-NUL sources; services healthy |
| 1 | Monorepo, CI, ARMv7 `mngd`, signed PWA shell | done | `mngd` canary on `127.0.0.1:8090`; `/app/` signed and served read-only |
| 2 | Rust/WASM E2EE engine parity | core done | decrypt/encrypt vectors match WebCrypto; browser adapter loads WASM |
| 3 | Config + SQLite read model + sessions | done | users, items, thumbnails readable without PHP |
| 4 | Auth + RBAC parity | read-only done | login, roles, per-library ACL, CSRF, rate limits, timeline/albums |
| 5 | API parity (library/file/trash/import) | next | existing UI works against `/api/v1` |
| 6 | Seafile E2EE bridge in Rust | planned | unlock, list, download, upload, move, import flows |
| 7 | Image/chunk pipeline native | planned | thumbnails, HEIC/ffmpeg fallbacks, chunk hashing |
| 8 | PWA cutover + immutable frontend | shell done | nginx serves `/app/`; PHP cannot write it |
| 9 | Decommission PHP, rotate secrets | planned | no PHP-FPM dependency; source removed from server |

## Current PHP surface to port

| PHP | Responsibility | Rust destination |
| --- | --- | --- |
| `api.php` | request dispatch, JSON envelope | `mngd` routes + typed handlers |
| `lib/bootstrap.php` | config, helpers, blank-media guard | `mng-core::config` + media module |
| `lib/db.php` | SQLite access | `mng-core::db` (rusqlite or pure-Rust layer) |
| `lib/users.php` | sessions, roles, login | `mng-auth` + `mngd::{auth, rbac, read}` |
| `lib/indexer.php` | item index, metadata | `mng-core::items` |
| `lib/media.php` | thumbnails, previews, MIME | `mng-core::media` |
| `lib/seafile_e2ee.php` | Seafile bridge | `mng-core::seafile` |
| `lib/icloud.php` | import jobs | `mng-core::import` + worker binary |
| `bin/worker.php` | background jobs | native worker binary |
| `bin/import.php` | iCloud importer | native importer |
| `assets/app.js` | UI + browser crypto | UI JS + `mng-wasm` adapter |

## Cutover order

1. Deploy `mngd` on `127.0.0.1:8090`; verify `/healthz` and `/readyz`.
2. Add the nginx `/app/` location only; legacy `/` is untouched.
3. Sign and serve the PWA shell. Check CSP, Trusted Types, SW install and
   update verification in a private browser profile.
4. Port `/api/v1` endpoints behind a query flag; keep `api.php` as fallback.
5. Move one read-only feature (library list) and compare responses.
6. Move mutations one at a time with idempotency keys and server-side audit.
7. Freeze PHP writes, make `/var/www/mng-cloud` read-only, then stop PHP-FPM.
8. Remove the PHP tree and any build tooling from the server; keep only signed
   native binaries and releases.

## Rollback

- nginx: remove the `/app/` location; legacy PHP still serves `/`.
- service: `systemctl stop mngd`; no Seafile state is touched.
- app: `deploy-mngd.sh` restores the previous symlink and binary if health
  checks fail.
- signing: keep the previous signed release until the new one is verified.

## Data safety rules

- Never reset `thumb_state=3` or delete failed thumbnail rows automatically.
- Never upload all-NUL staging files; quarantine them outside the scan tree.
- Never rewrite Seafile repositories or block files as part of a deploy.
- Never run a migration against production SQLite without a backup and a
  dry-run count comparison.
