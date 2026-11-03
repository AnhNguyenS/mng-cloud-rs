import test from 'node:test';
import assert from 'node:assert/strict';

import {
  REQUIRED_ASSETS,
  TrustError,
  assetPathForUrl,
  checkObservation,
  compareVersions,
  indexManifest,
  sha256Hex,
  validateConfig,
  validateManifest,
  validateRelease,
  verifyReleaseAndManifest,
} from '../src/trust.js';

const encoder = new TextEncoder();
const PUBLIC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: '3bbemTZFtkodG2JOMOoFzcySEzCLqtnjPxt4__Y0Fis',
  y: 'ntmYDM3Kt-bvBK-7bBP6MvUb8mZExEd97fEiyk-H94U',
};

async function makeKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
}

async function sign(privateKey, bytes) {
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes),
  );
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function fixture() {
  const keyPair = await makeKeyPair();
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const assets = REQUIRED_ASSETS.map((path) => ({
    path,
    sha256: '0'.repeat(64),
    size: 10,
    mime: path.endsWith('.js') ? 'text/javascript' : 'text/html',
  }));
  assets.push({
    path: 'assets/wasm/mng_wasm_bg.wasm',
    sha256: '1'.repeat(64),
    size: 20,
    mime: 'application/wasm',
  });
  const manifest = {
    version: '1.2.3',
    generated_at: 1_760_000_000,
    assets,
  };
  const manifestBytes = encoder.encode(JSON.stringify(manifest));
  const release = {
    schema: 1,
    version: '1.2.3',
    sequence: 7,
    generated_at: 1_760_000_000,
    app_base: '/app/',
    manifest_sha256: await sha256Hex(manifestBytes),
    manifest: 'manifest.json',
    manifest_signature: 'manifest.sig',
  };
  const releaseBytes = encoder.encode(JSON.stringify(release));
  return {
    keyPair,
    publicJwk,
    manifest,
    manifestBytes,
    manifestSignature: await sign(keyPair.privateKey, manifestBytes),
    release,
    releaseBytes,
    releaseSignature: await sign(keyPair.privateKey, releaseBytes),
  };
}

test('verifies a signed release and manifest', async () => {
  const f = await fixture();
  const result = await verifyReleaseAndManifest({
    releaseBytes: f.releaseBytes,
    releaseSignature: f.releaseSignature,
    manifestBytes: f.manifestBytes,
    manifestSignature: f.manifestSignature,
    publicJwk: f.publicJwk,
  });
  assert.equal(result.release.version, '1.2.3');
  assert.equal(result.manifest.assets.length, REQUIRED_ASSETS.length + 1);
});

test('rejects a tampered release signature', async () => {
  const f = await fixture();
  const tampered = encoder.encode(JSON.stringify({ ...f.release, sequence: 8 }));
  await assert.rejects(
    verifyReleaseAndManifest({
      releaseBytes: tampered,
      releaseSignature: f.releaseSignature,
      manifestBytes: f.manifestBytes,
      manifestSignature: f.manifestSignature,
      publicJwk: f.publicJwk,
    }),
    (error) => error instanceof TrustError && error.code === 'bad_release_signature',
  );
});

test('rejects a manifest that does not match release metadata', async () => {
  const f = await fixture();
  const tampered = encoder.encode(JSON.stringify({ ...f.manifest, version: '1.2.4' }));
  const tamperedSignature = await sign(f.keyPair.privateKey, tampered);
  await assert.rejects(
    verifyReleaseAndManifest({
      releaseBytes: f.releaseBytes,
      releaseSignature: f.releaseSignature,
      manifestBytes: tampered,
      manifestSignature: tamperedSignature,
      publicJwk: f.publicJwk,
    }),
    (error) => error instanceof TrustError && error.code === 'manifest_hash_mismatch',
  );
});

test('rejects unsafe, duplicate and incomplete manifests', async () => {
  const base = {
    version: '1.2.3',
    generated_at: 1,
    assets: REQUIRED_ASSETS.map((path) => ({
      path,
      sha256: '0'.repeat(64),
      size: 1,
    })),
  };
  assert.throws(
    () => validateManifest({ ...base, assets: [...base.assets, { ...base.assets[0], path: '../x' }] }),
    (error) => error instanceof TrustError && error.code === 'invalid_manifest',
  );
  assert.throws(
    () => validateManifest({ ...base, assets: [...base.assets, { ...base.assets[0] }] }),
    (error) => /duplicate asset/.test(error.message),
  );
  assert.throws(
    () => validateManifest({ ...base, assets: base.assets.slice(1) }),
    (error) => /missing index\.html/.test(error.message),
  );
});

test('validates release metadata and app base', async () => {
  const f = await fixture();
  assert.equal(validateRelease(f.release).sequence, 7);
  for (const appBase of ['app/', '/app', '/../app/', '/app/?x=1']) {
    assert.throws(
      () => validateRelease({ ...f.release, app_base: appBase }),
      (error) => error instanceof TrustError,
    );
  }
});

test('compares semantic versions including prereleases', () => {
  assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
  assert.equal(compareVersions('1.2.4', '1.2.3'), 1);
  assert.equal(compareVersions('1.2.3-beta.2', '1.2.3-beta.1'), 1);
  assert.equal(compareVersions('1.2.3', '1.2.3-rc.1'), 1);
  assert.equal(compareVersions('1.2.3-rc.1', '1.2.3-beta.9'), 1);
});

test('maps URLs to signed asset paths', () => {
  const deployment = { origin: 'https://cloud.example.com', appBase: '/app/' };
  assert.equal(assetPathForUrl('https://cloud.example.com/app/', deployment), 'index.html');
  assert.equal(assetPathForUrl('https://cloud.example.com/app', deployment), 'index.html');
  assert.equal(
    assetPathForUrl('https://cloud.example.com/app/assets/app.js?v=1.2.3', deployment),
    'assets/app.js',
  );
  assert.equal(assetPathForUrl('https://cloud.example.com/other/app.js', deployment), null);
  assert.equal(assetPathForUrl('https://evil.example/app/assets/app.js', deployment), null);
});

test('flags unlisted critical resources and MIME/status mismatches', async () => {
  const f = await fixture();
  const manifestIndex = indexManifest(f.manifest);
  const deployment = { origin: 'https://cloud.example.com', appBase: '/app/' };

  const unlisted = checkObservation(
    {
      url: 'https://cloud.example.com/app/assets/evil.js',
      type: 'script',
      statusCode: 200,
      mime: 'text/javascript',
      nosniff: true,
    },
    deployment,
    manifestIndex,
  );
  assert.equal(unlisted[0].code, 'unlisted_resource');
  assert.equal(unlisted[0].severity, 'error');

  const wrongMime = checkObservation(
    {
      url: 'https://cloud.example.com/app/assets/app.js',
      type: 'script',
      statusCode: 200,
      mime: 'text/html',
      nosniff: true,
    },
    deployment,
    manifestIndex,
  );
  assert.equal(wrongMime[0].code, 'mime_mismatch');

  const missing = checkObservation(
    {
      url: 'https://cloud.example.com/app/assets/app.js',
      type: 'script',
      statusCode: 404,
      mime: 'text/html',
      nosniff: true,
    },
    deployment,
    manifestIndex,
  );
  assert.ok(missing.some((issue) => issue.code === 'load_failed'));

  const shell = checkObservation(
    {
      url: 'https://cloud.example.com/app/photos/42',
      type: 'main_frame',
      statusCode: 200,
      mime: 'text/html; charset=utf-8',
      nosniff: true,
    },
    deployment,
    manifestIndex,
  );
  assert.deepEqual(shell, []);
});

test('accepts MIME aliases used by static servers', async () => {
  const f = await fixture();
  const manifestIndex = indexManifest(f.manifest);
  const deployment = { origin: 'https://cloud.example.com', appBase: '/app/' };
  const issues = checkObservation(
    {
      url: 'https://cloud.example.com/app/assets/app.js',
      type: 'script',
      statusCode: 200,
      mime: 'application/javascript; charset=utf-8',
      nosniff: true,
    },
    deployment,
    manifestIndex,
  );
  assert.deepEqual(issues, []);
});

test('validates deployment and release configuration', () => {
  const config = validateConfig({
    deployments: [{ origin: 'http://127.0.0.1:8090', appBase: '/app/' }],
    releaseBase: 'http://127.0.0.1:8092/releases/current/',
    pinnedPublicJwk: PUBLIC_JWK,
    limits: {},
  });
  assert.equal(config.deployments[0].origin, 'http://127.0.0.1:8090');
  assert.throws(
    () => validateConfig({
      deployments: [{ origin: 'http://cloud.example.com', appBase: '/app/' }],
      releaseBase: 'https://example.com/releases/',
      pinnedPublicJwk: PUBLIC_JWK,
    }),
    (error) => error.code === 'invalid_config',
  );
  assert.throws(
    () => validateConfig({
      deployments: [{ origin: 'https://cloud.example.com', appBase: '/app/' }],
      releaseBase: 'https://example.com/releases',
      pinnedPublicJwk: PUBLIC_JWK,
    }),
    (error) => /end with/.test(error.message),
  );
});
