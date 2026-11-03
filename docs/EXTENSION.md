# MNG Cloud Trusted extension

The extension is the trust anchor for the custom frontend. It independently
verifies the release published from GitHub, hashes the bytes the cloud origin
actually returns, and switches the browser UI to **NOT SAFE** when anything
disagrees with the signed release.

It is plain WebExtensions (Chromium MV3) with no bundler and no remote code. The
same source is intended to load in Orion.

## Why the trust anchor moved out of the server

A PWA necessarily bootstraps from the origin that serves `sw.js`. If that origin
is compromised on the first visit, the served worker can lie about every update.
Pinning a key inside the worker only protects later updates, not the initial
bytes.

The extension is installed separately from the cloud origin. It pins the
release public key at build time, reads signed metadata from GitHub, and
compares that metadata with content fetched directly from the cloud origin. The
server can withhold or delete content, but it cannot forge a release.

## Files

| File | Role |
| --- | --- |
| `extension/src/trust.js` | Pure verification: signatures, release/manifest validation, MIME and URL mapping. Shared with Node tests. |
| `extension/src/background.js` | Service worker: fetch/verify release metadata, sequence guard, direct asset hashing, `webRequest`/`webNavigation` observation, badge state. |
| `extension/src/content.js` | Same-origin document checks, asset hashing, DOM/PerformanceObserver scan for unlisted resources, warning banner. |
| `extension/src/popup.html` / `popup.js` | Status detail, issue list, manual recheck. |
| `extension/src/manifest.template.json` | MV3 template; permissions and matches are stamped by the build. |
| `extension/config.example.json` | Deployment origins, release base, pinned JWK, limits. |
| `tools/build-extension.py` | Stamps config/manifest, pins the public key, generates icons and an optional ZIP. |

## Trust flow

1. **Release metadata** comes from `releaseBase` (GitHub Pages or a release
   branch), never from the cloud origin.
2. `release.json` is verified with the pinned P-256 key. It pins the version,
   monotonic `sequence`, `app_base`, and the manifest SHA-256.
3. `manifest.json` is verified separately and checked against the release hash
   and version.
4. **Network verification**: the extension service worker fetches every signed
   asset from the cloud origin with its host permission. These requests bypass
   the page's service worker, so the extension sees the origin's stored bytes.
   SHA-256, size and `Content-Type` are compared with the signed manifest.
5. **Page verification**: the content script re-fetches the same assets in the
   page origin. This catches a page service worker that serves modified bytes
   to the document while the origin files are genuine. It also hashes the HTML
   document and checks the `mng-version` meta tag.
6. **Resource observation**: `webNavigation`/`webRequest` provide navigation
   status, MIME and `nosniff`. A DOM `MutationObserver` plus a
   `PerformanceObserver` report scripts, stylesheets, manifests, fonts and WASM
   that are not in the signed manifest.
7. **Sequence guard**: the highest verified sequence is stored in
   `chrome.storage.local`. A lower sequence, or a reused sequence with a
   different version, is rejected as a rollback.

A page-controlled service worker makes subresource requests appear to
`webRequest` as worker traffic without a tab id. That is why the extension does
not rely on `webRequest` for asset integrity; direct hashing and DOM observation
cover the case.

## States

| State | Badge | UI | Meaning |
| --- | --- | --- | --- |
| `checking` | `…` | dark pill | Verification is running. |
| `verified` | `✓` | green pill (auto-hides) | Signatures, hashes, document and resource checks passed. |
| `unsafe` | `!` | red bar, details expandable | Positive mismatch: bad signature, hash/size/MIME, rollback, unlisted critical resource, failed load. |
| `unverified` | `?` | amber bar | Verification could not complete (offline metadata, timeout, content script unavailable). |

Bad signatures and rollback failures are never masked by the cached release.
The cache is only used when GitHub metadata cannot be reached.

## Configuration

```json
{
  "schema": 1,
  "extensionVersion": "0.1.0",
  "deployments": [
    { "origin": "https://cloud.example.com", "appBase": "/app/" }
  ],
  "releaseBase": "https://example.github.io/mng-cloud-rs/releases/current/",
  "pinnedPublicJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "limits": {
    "maxAssetBytes": 33554432,
    "maxTotalBytes": 134217728,
    "releaseTimeoutMs": 15000,
    "pageTimeoutMs": 45000
  },
  "requireOnlineVerification": false
}
```

- `deployments[].origin` must be HTTPS (HTTP only for loopback development).
- `appBase` must start and end with `/`.
- `releaseBase` must be HTTPS and end with `/`. The extension fetches
  `release.json`, `release.sig`, and the manifest names from this directory.
- `requireOnlineVerification: true` disables the cached-release fallback.
- Limits are enforced while streaming; oversized responses abort verification.
- `extensionVersion` is stamped into `manifest.json` by the build.

`tools/build-extension.py --production` rejects loopback origins and placeholder
hostnames. `extension/config.local.json` is gitignored and is only for local
testing.

## Build and load

```bash
cp extension/config.example.json extension/config.production.json
# edit deployments[0].origin, releaseBase, pinnedPublicJwk
python tools/build-extension.py \
  --config extension/config.production.json \
  --production \
  --zip
```

Load `dist/extension`:

- Orion: extension developer/load-unpacked flow.
- Chromium: `chrome://extensions` → developer mode → **Load unpacked**.
- Chrome branded: command-line `--load-extension` is ignored; use Chromium or
  Playwright's bundled Chromium.

Do not load a build whose `config.js` still contains `example.com` or
`YOUR_GITHUB_USER`.

## Tests

Pure verification tests (Node 22+):

```bash
node --test extension/tests/trust.test.mjs
```

They cover signatures, tampering, manifest hashing, path safety, MIME aliases,
version comparison, URL mapping and config validation.

Browser end-to-end tests (local, headed Chromium):

```bash
cd tools/e2e && npm install && npx playwright install chromium
cd ../..
python tools/build-extension.py --config extension/config.local.json --out dist/extension
# mngd must serve dist/app on 127.0.0.1:8090
node tools/e2e/extension-e2e.mjs
```

The runner starts its own CORS release server for `dist/release`, then checks:

1. initial load is verified;
2. an unlisted stylesheet flips the badge and banner;
3. a tampered signed asset flips the badge and banner;
4. restoring the asset verifies again.

The rollback path is documented in `docs/OPERATIONS.md`; it needs a second
signed release with a lower sequence.

## Privacy and permissions

- `storage`: last verified sequence and release metadata.
- `scripting`: inject the content script if the declared content script did not
  run.
- `webNavigation`, `webRequest`: navigation and response metadata.
- Host permissions: only the configured deployments and release base.
- No telemetry, no analytics, no page content leaves the browser. The extension
  reads signed public metadata and the signed static assets; it does not read
  application API responses.

## Known limits

- Extension APIs do not expose every response body. API responses are outside
  the manifest's integrity coverage.
- The extension itself must be installed/updated from a trusted channel. Publish
  a SHA-256 for the ZIP and prefer store distribution when available.
- A browser profile already controlled by a malicious service worker before the
  extension is installed is outside the model.
- Key rotation requires a new extension build (or a transition release that
  pins both keys).
