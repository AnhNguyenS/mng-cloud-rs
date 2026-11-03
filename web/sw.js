/*
 * MNG Cloud service worker.
 *
 * Bootstraps trust from a P-256 public key pinned at package time, verifies the
 * signed manifest and every asset hash, then serves only that immutable cache.
 * This file is a template: `mng-sign package` stamps APP_VERSION and the public
 * key before signing the release.
 */

const APP_VERSION = '__MNG_VERSION__';
const PINNED_UPDATE_KEY = /*__MNG_UPDATE_PUBKEY__*/ null;

const APP_BASE = new URL('./', self.location.href);
const CACHE_PREFIX = 'mng-app-';
const META_CACHE = 'mng-meta';
const META_VERSION_URL = new URL('__mng_version', APP_BASE).href;
const REQUIRED_ASSETS = [
  'index.html',
  'sw.js',
  'manifest.webmanifest',
  'assets/app.js',
  'assets/app.css',
  'assets/trusted-types.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    try {
      const { manifest } = await fetchVerifiedManifest();
      if (manifest.version !== APP_VERSION) {
        throw new Error(`manifest ${manifest.version} does not match worker ${APP_VERSION}`);
      }
      await verifyWorkerSelf(manifest);
      await assertNotRollback(manifest.version);
      await cacheManifest(manifest);
      await rememberVersion(manifest.version);
      await self.skipWaiting();
    } catch (error) {
      // The page console cannot see service worker exceptions, so report a
      // short reason before the browser discards this registration.
      await notifyClients({
        type: 'mng-install-error',
        message: String((error && error.message) || error),
      });
      throw error;
    }
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keep = CACHE_PREFIX + APP_VERSION;
    const names = await caches.keys();
    await Promise.all(
      names
        .filter((name) => name.startsWith(CACHE_PREFIX) && name !== keep)
        .map((name) => caches.delete(name)),
    );
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith(APP_BASE.pathname)) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_PREFIX + APP_VERSION);
    const hit = await cache.match(request, { ignoreSearch: true });
    if (hit) return hit;

    if (request.mode === 'navigate') {
      const shell = await cache.match(new URL('index.html', APP_BASE));
      if (shell) return shell;
    }

    return fetch(request);
  })());
});

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'mng-check-update') {
    event.waitUntil(checkForUpdate(event.source));
  }
  if (data.type === 'mng-skip-waiting') {
    event.waitUntil(self.skipWaiting());
  }
});

async function checkForUpdate(source) {
  try {
    const { manifest } = await fetchVerifiedManifest();
    const relation = compareVersions(manifest.version, APP_VERSION);
    if (relation > 0) {
      reply(source, {
        type: 'mng-update-status',
        status: 'available',
        version: manifest.version,
      });
    } else if (relation < 0) {
      reply(source, {
        type: 'mng-update-status',
        status: 'rollback',
        version: manifest.version,
      });
    } else {
      reply(source, {
        type: 'mng-update-status',
        status: 'current',
        version: manifest.version,
      });
    }
  } catch (error) {
    reply(source, {
      type: 'mng-update-status',
      status: 'error',
      message: String((error && error.message) || error),
    });
  }
}

function reply(source, payload) {
  if (source && typeof source.postMessage === 'function') {
    source.postMessage(payload);
  }
}

async function notifyClients(payload) {
  const clients = await self.clients.matchAll({
    type: 'window',
    includeUncontrolled: true,
  });
  for (const client of clients) {
    client.postMessage(payload);
  }
}

async function fetchVerifiedManifest() {
  if (!PINNED_UPDATE_KEY) {
    throw new Error('update public key is not pinned; serve a signed release');
  }
  const manifestUrl = new URL('manifest.json', APP_BASE);
  const signatureUrl = new URL('manifest.sig', APP_BASE);
  const [manifestResponse, signatureResponse] = await Promise.all([
    fetch(manifestUrl, { cache: 'no-store' }),
    fetch(signatureUrl, { cache: 'no-store' }),
  ]);
  if (!manifestResponse.ok) {
    throw new Error(`manifest HTTP ${manifestResponse.status}`);
  }
  if (!signatureResponse.ok) {
    throw new Error(`signature HTTP ${signatureResponse.status}`);
  }

  const manifestBytes = await manifestResponse.arrayBuffer();
  const signature = hexToBytes((await signatureResponse.text()).trim(), 64);
  const key = await crypto.subtle.importKey(
    'jwk',
    PINNED_UPDATE_KEY,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature,
    manifestBytes,
  );
  if (!valid) throw new Error('manifest signature is invalid');

  const manifest = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes),
  );
  validateManifest(manifest);
  return { manifest, manifestBytes };
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest.version !== 'string') {
    throw new Error('manifest version is missing');
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version)) {
    throw new Error('manifest version is not semver');
  }
  if (!Array.isArray(manifest.assets) || manifest.assets.length === 0) {
    throw new Error('manifest has no assets');
  }

  const seen = new Set();
  for (const asset of manifest.assets) {
    if (!asset || typeof asset.path !== 'string' || typeof asset.sha256 !== 'string') {
      throw new Error('manifest asset is malformed');
    }
    if (!/^[A-Za-z0-9._@+/-]+$/.test(asset.path)) {
      throw new Error(`unsafe asset path: ${asset.path}`);
    }
    if (asset.path.startsWith('/') || asset.path.split('/').includes('..')) {
      throw new Error(`unsafe asset path: ${asset.path}`);
    }
    if (!/^[0-9a-f]{64}$/.test(asset.sha256)) {
      throw new Error(`invalid hash for ${asset.path}`);
    }
    if (seen.has(asset.path)) {
      throw new Error(`duplicate asset: ${asset.path}`);
    }
    seen.add(asset.path);
  }
  for (const required of REQUIRED_ASSETS) {
    if (!seen.has(required)) throw new Error(`manifest is missing ${required}`);
  }
}

async function verifyWorkerSelf(manifest) {
  const asset = manifest.assets.find((item) => item.path === 'sw.js');
  if (!asset) throw new Error('manifest does not cover sw.js');
  const response = await fetch(new URL('sw.js', APP_BASE), { cache: 'no-store' });
  if (!response.ok) throw new Error(`worker self-fetch HTTP ${response.status}`);
  const digest = await sha256Hex(await response.arrayBuffer());
  if (digest !== asset.sha256) {
    throw new Error('worker bytes do not match the signed manifest');
  }
}

async function cacheManifest(manifest) {
  const cache = await caches.open(CACHE_PREFIX + manifest.version);
  for (const asset of manifest.assets) {
    const url = new URL(asset.path, APP_BASE).href;
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`${asset.path} HTTP ${response.status}`);
    const bytes = await response.arrayBuffer();
    const digest = await sha256Hex(bytes);
    if (digest !== asset.sha256) {
      throw new Error(`hash mismatch for ${asset.path}`);
    }
    await cache.put(
      url,
      new Response(bytes, {
        status: 200,
        headers: {
          'content-type':
            response.headers.get('content-type') || 'application/octet-stream',
        },
      }),
    );
  }
}

async function assertNotRollback(version) {
  const previous = await readRememberedVersion();
  if (previous && compareVersions(version, previous) < 0) {
    throw new Error(`refusing rollback from ${previous} to ${version}`);
  }
}

async function readRememberedVersion() {
  const meta = await caches.open(META_CACHE);
  const response = await meta.match(META_VERSION_URL);
  return response ? (await response.text()).trim() : '';
}

async function rememberVersion(version) {
  const meta = await caches.open(META_CACHE);
  await meta.put(META_VERSION_URL, new Response(version));
}

function compareVersions(left, right) {
  const parse = (value) => value.split('-')[0].split('.').map((part) => Number(part) || 0);
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index += 1) {
    const delta = (a[index] || 0) - (b[index] || 0);
    if (delta !== 0) return delta > 0 ? 1 : -1;
  }
  return 0;
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(text, expectedLength) {
  if (text.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(text)) {
    throw new Error('invalid hex value');
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  if (expectedLength && bytes.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}
