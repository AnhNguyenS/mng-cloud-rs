/*
 * Pure verification helpers shared by the background worker and Node tests.
 *
 * No DOM or extension APIs are used here. The trust anchor is the JWK pinned
 * in config.json; GitHub is only a transport for signed bytes.
 */

export const RELEASE_SCHEMA = 1;
export const REQUIRED_ASSETS = [
  'index.html',
  'sw.js',
  'manifest.webmanifest',
  'assets/app.js',
  'assets/app.css',
  'assets/trusted-types.js',
];

const MAX_RELEASE_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_ASSET_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 128 * 1024 * 1024;

export class TrustError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TrustError';
    this.code = code;
  }
}

export function decodeUtf8(bytes, label = 'document') {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TrustError('invalid_utf8', `${label} is not valid UTF-8`);
  }
}

export function parseJsonBytes(bytes, label = 'document') {
  try {
    return JSON.parse(decodeUtf8(bytes, label));
  } catch (error) {
    if (error instanceof TrustError) throw error;
    throw new TrustError('invalid_json', `${label} is not valid JSON`);
  }
}

export function hexToBytes(text, expectedLength) {
  const value = String(text || '').trim();
  if (!/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) {
    throw new TrustError('invalid_hex', 'value is not hexadecimal');
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  if (expectedLength && bytes.length !== expectedLength) {
    throw new TrustError(
      'invalid_hex',
      `expected ${expectedLength} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function base64UrlToBytes(text) {
  const value = String(text || '');
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TrustError('invalid_base64url', 'value is not base64url');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    value.length + ((4 - (value.length % 4)) % 4),
    '=',
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  const chunk = 0x8000;
  for (let index = 0; index < view.length; index += chunk) {
    binary += String.fromCharCode(...view.subarray(index, index + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(text) {
  const binary = atob(String(text || ''));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return bytesToHex(digest);
}

export function validateJwk(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new TrustError('invalid_key', 'pinned key must be an EC P-256 JWK');
  }
  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new TrustError('invalid_key', 'pinned key coordinates must be 32 bytes');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true };
}

export async function importVerifyKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    validateJwk(jwk),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

export async function verifyEcdsaHex(bytes, signatureHex, keyOrJwk) {
  const key = keyOrJwk instanceof CryptoKey
    ? keyOrJwk
    : await importVerifyKey(keyOrJwk);
  const signature = hexToBytes(signatureHex, 64);
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature,
    bytes,
  );
}

export function validateVersion(version) {
  if (typeof version !== 'string' || version.length === 0 || version.length > 64) {
    throw new TrustError('invalid_version', 'release version is missing');
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new TrustError('invalid_version', `invalid semver: ${version}`);
  }
  return version;
}

export function compareVersions(left, right) {
  const parse = (value) => {
    const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(String(value || ''));
    if (!match) return null;
    return {
      core: [Number(match[1]), Number(match[2]), Number(match[3])],
      pre: match[4] ? match[4].split('.') : [],
    };
  };
  const a = parse(left);
  const b = parse(right);
  if (!a || !b) throw new TrustError('invalid_version', 'cannot compare invalid versions');
  for (let index = 0; index < 3; index += 1) {
    if (a.core[index] !== b.core[index]) return a.core[index] > b.core[index] ? 1 : -1;
  }
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1;
  if (b.pre.length === 0) return -1;
  const length = Math.max(a.pre.length, b.pre.length);
  for (let index = 0; index < length; index += 1) {
    const x = a.pre[index];
    const y = b.pre[index];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) return Number(x) > Number(y) ? 1 : -1;
    if (nx) return -1;
    if (ny) return 1;
    return x > y ? 1 : -1;
  }
  return 0;
}

export function isSafeRelativePath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 512) return false;
  if (path.startsWith('/') || path.includes('\\') || path.includes('\0')) return false;
  if (!/^[A-Za-z0-9._@+/-]+$/.test(path)) return false;
  return !path.split('/').some((part) => part === '' || part === '.' || part === '..');
}

export function validateAppBase(appBase) {
  if (
    typeof appBase !== 'string'
    || !appBase.startsWith('/')
    || !appBase.endsWith('/')
    || appBase.length > 512
    || appBase.includes('..')
    || appBase.includes('?')
    || appBase.includes('#')
    || appBase.includes('\\')
    || /[\u0000-\u0020]/.test(appBase)
  ) {
    throw new TrustError('invalid_app_base', `invalid app_base: ${appBase}`);
  }
  return appBase;
}

export function validateRelease(release) {
  if (!release || typeof release !== 'object' || Array.isArray(release)) {
    throw new TrustError('invalid_release', 'release metadata is not an object');
  }
  if (release.schema !== RELEASE_SCHEMA) {
    throw new TrustError('invalid_release', `unsupported release schema: ${release.schema}`);
  }
  validateVersion(release.version);
  if (!Number.isSafeInteger(release.sequence) || release.sequence <= 0) {
    throw new TrustError('invalid_release', 'release sequence must be a positive integer');
  }
  if (!Number.isSafeInteger(release.generated_at) || release.generated_at <= 0) {
    throw new TrustError('invalid_release', 'release generated_at is invalid');
  }
  validateAppBase(release.app_base);
  if (
    typeof release.manifest_sha256 !== 'string'
    || !/^[0-9a-f]{64}$/.test(release.manifest_sha256)
  ) {
    throw new TrustError('invalid_release', 'release manifest_sha256 is invalid');
  }
  for (const field of ['manifest', 'manifest_signature']) {
    if (!isSafeRelativePath(release[field])) {
      throw new TrustError('invalid_release', `release ${field} path is unsafe`);
    }
  }
  if (release.manifest === release.manifest_signature) {
    throw new TrustError('invalid_release', 'manifest and signature paths must differ');
  }
  return release;
}

export function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new TrustError('invalid_manifest', 'manifest is not an object');
  }
  validateVersion(manifest.version);
  if (!Number.isSafeInteger(manifest.generated_at) || manifest.generated_at <= 0) {
    throw new TrustError('invalid_manifest', 'manifest generated_at is invalid');
  }
  if (!Array.isArray(manifest.assets) || manifest.assets.length === 0) {
    throw new TrustError('invalid_manifest', 'manifest has no assets');
  }
  const seen = new Set();
  for (const asset of manifest.assets) {
    if (!asset || typeof asset !== 'object') {
      throw new TrustError('invalid_manifest', 'manifest asset is malformed');
    }
    if (!isSafeRelativePath(asset.path)) {
      throw new TrustError('invalid_manifest', `unsafe asset path: ${asset.path}`);
    }
    if (typeof asset.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(asset.sha256)) {
      throw new TrustError('invalid_manifest', `invalid hash for ${asset.path}`);
    }
    if (!Number.isSafeInteger(asset.size) || asset.size < 0) {
      throw new TrustError('invalid_manifest', `invalid size for ${asset.path}`);
    }
    if (asset.mime !== undefined && (typeof asset.mime !== 'string' || asset.mime.length > 128)) {
      throw new TrustError('invalid_manifest', `invalid mime for ${asset.path}`);
    }
    if (seen.has(asset.path)) {
      throw new TrustError('invalid_manifest', `duplicate asset: ${asset.path}`);
    }
    seen.add(asset.path);
  }
  for (const required of REQUIRED_ASSETS) {
    if (!seen.has(required)) {
      throw new TrustError('invalid_manifest', `manifest is missing ${required}`);
    }
  }
  return manifest;
}

export function indexManifest(manifest) {
  return new Map(manifest.assets.map((asset) => [asset.path, asset]));
}

export async function verifyReleaseAndManifest({
  releaseBytes,
  releaseSignature,
  manifestBytes,
  manifestSignature,
  publicJwk,
  verifyKey,
}) {
  if (releaseBytes.byteLength > MAX_RELEASE_BYTES) {
    throw new TrustError('invalid_release', 'release metadata is too large');
  }
  if (manifestBytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new TrustError('invalid_manifest', 'manifest is too large');
  }
  const key = verifyKey || await importVerifyKey(publicJwk);
  if (!(await verifyEcdsaHex(releaseBytes, releaseSignature, key))) {
    throw new TrustError('bad_release_signature', 'release signature is invalid');
  }
  const release = validateRelease(parseJsonBytes(releaseBytes, 'release.json'));
  if (!(await verifyEcdsaHex(manifestBytes, manifestSignature, key))) {
    throw new TrustError('bad_manifest_signature', 'manifest signature is invalid');
  }
  const digest = await sha256Hex(manifestBytes);
  if (digest !== release.manifest_sha256) {
    throw new TrustError('manifest_hash_mismatch', 'manifest does not match release metadata');
  }
  const manifest = validateManifest(parseJsonBytes(manifestBytes, 'manifest.json'));
  if (manifest.version !== release.version) {
    throw new TrustError('version_mismatch', 'manifest and release versions differ');
  }
  return { release, manifest };
}

const MIME_ALIASES = {
  'text/javascript': [
    'application/javascript',
    'application/x-javascript',
    'text/ecmascript',
    'application/ecmascript',
  ],
  'application/json': ['text/json'],
  'application/manifest+json': ['application/json', 'text/cache-manifest'],
  'image/x-icon': ['image/vnd.microsoft.icon'],
  'font/woff2': ['application/font-woff2'],
  'font/woff': ['application/font-woff'],
  'application/xml': ['text/xml'],
};

function normalizeMime(value) {
  return String(value || '').split(';')[0].trim().toLowerCase();
}

export function mimeMatches(expected, actual) {
  const want = normalizeMime(expected);
  const got = normalizeMime(actual);
  if (!want || !got) return true;
  if (want === got) return true;
  return (MIME_ALIASES[want] || []).includes(got) || (MIME_ALIASES[got] || []).includes(want);
}

export function normalizeDeployment(value) {
  if (!value || typeof value !== 'object') {
    throw new TrustError('invalid_config', 'deployment is not an object');
  }
  let url;
  try {
    url = new URL(value.origin);
  } catch {
    throw new TrustError('invalid_config', `invalid deployment origin: ${value.origin}`);
  }
  if (url.username || url.password || url.pathname !== '/') {
    throw new TrustError('invalid_config', 'deployment origin must not contain a path or credentials');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    throw new TrustError('invalid_config', 'deployments must use HTTPS (HTTP is allowed on loopback only)');
  }
  validateAppBase(value.appBase);
  return { origin: url.origin, appBase: value.appBase };
}

export function validateConfig(config) {
  if (!config || typeof config !== 'object') {
    throw new TrustError('invalid_config', 'config is not an object');
  }
  if (!Array.isArray(config.deployments) || config.deployments.length === 0) {
    throw new TrustError('invalid_config', 'at least one deployment is required');
  }
  const deployments = config.deployments.map(normalizeDeployment);
  let releaseUrl;
  try {
    releaseUrl = new URL(config.releaseBase);
  } catch {
    throw new TrustError('invalid_config', 'releaseBase is not a URL');
  }
  if (releaseUrl.protocol !== 'https:' && !(releaseUrl.protocol === 'http:' && isLoopback(releaseUrl.hostname))) {
    throw new TrustError('invalid_config', 'releaseBase must use HTTPS (HTTP is allowed on loopback only)');
  }
  if (!releaseUrl.pathname.endsWith('/')) {
    throw new TrustError('invalid_config', 'releaseBase must end with /');
  }
  validateJwk(config.pinnedPublicJwk);
  const limits = config.limits || {};
  const maxAssetBytes = limits.maxAssetBytes ?? MAX_ASSET_BYTES;
  const maxTotalBytes = limits.maxTotalBytes ?? MAX_TOTAL_BYTES;
  if (!Number.isSafeInteger(maxAssetBytes) || maxAssetBytes <= 0) {
    throw new TrustError('invalid_config', 'limits.maxAssetBytes is invalid');
  }
  if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes <= 0) {
    throw new TrustError('invalid_config', 'limits.maxTotalBytes is invalid');
  }
  return {
    ...config,
    deployments,
    releaseBase: releaseUrl.href,
    limits: {
      maxAssetBytes,
      maxTotalBytes,
      releaseTimeoutMs: limits.releaseTimeoutMs ?? 15000,
      pageTimeoutMs: limits.pageTimeoutMs ?? 45000,
    },
    requireOnlineVerification: Boolean(config.requireOnlineVerification),
  };
}

function isLoopback(hostname) {
  return hostname === '127.0.0.1' || hostname === '::1' || hostname === 'localhost';
}

export function deploymentForUrl(url, deployments) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  return deployments.find((deployment) => deployment.origin === parsed.origin) || null;
}

export function assetPathForUrl(url, deployment) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.origin !== deployment.origin) return null;
  const base = deployment.appBase;
  const stripped = base.endsWith('/') ? base.slice(0, -1) : base;
  if (parsed.pathname !== base && parsed.pathname !== stripped && !parsed.pathname.startsWith(base)) {
    return null;
  }
  let relative = parsed.pathname.slice(base.length);
  if (relative === '' || relative.endsWith('/')) return 'index.html';
  return relative;
}

export function assetUrl(deployment, path) {
  return new URL(path, deployment.origin + deployment.appBase).href;
}

export const CRITICAL_REQUEST_TYPES = new Set([
  'main_frame',
  'script',
  'stylesheet',
  'worker',
  'sharedworker',
  'font',
  'manifest',
]);

export function isCriticalObservation(observation) {
  if (CRITICAL_REQUEST_TYPES.has(observation.type)) return true;
  if (observation.type === 'other' && /\.wasm(?:$|\?)/i.test(observation.url)) return true;
  return false;
}

/**
 * Compare one webRequest observation with the signed asset list.
 * Returns issue objects with `severity: 'error' | 'warning'`.
 */
export function checkObservation(observation, deployment, manifestIndex) {
  const path = assetPathForUrl(observation.url, deployment);
  if (!path) return [];
  let expectedPath = path;
  if (observation.type === 'main_frame' && !manifestIndex.has(expectedPath)) {
    expectedPath = 'index.html';
  }
  const asset = manifestIndex.get(expectedPath);
  const issues = [];

  if (!asset) {
    if (isCriticalObservation(observation)) {
      issues.push({
        severity: 'error',
        code: 'unlisted_resource',
        message: `Tài nguyên không có trong manifest: ${path}`,
        url: observation.url,
      });
    }
    return issues;
  }

  if (Number.isInteger(observation.statusCode) && observation.statusCode >= 400) {
    issues.push({
      severity: 'error',
      code: 'load_failed',
      message: `Tải thất bại (HTTP ${observation.statusCode}): ${expectedPath}`,
      url: observation.url,
    });
  }

  if (asset.mime && observation.mime && !mimeMatches(asset.mime, observation.mime)) {
    issues.push({
      severity: 'error',
      code: 'mime_mismatch',
      message: `MIME không khớp cho ${expectedPath}: cần ${asset.mime}, nhận ${observation.mime}`,
      url: observation.url,
    });
  } else if (asset.mime && !observation.mime && isCriticalObservation(observation)) {
    issues.push({
      severity: 'warning',
      code: 'mime_missing',
      message: `Thiếu Content-Type cho ${expectedPath}`,
      url: observation.url,
    });
  }

  if (
    isCriticalObservation(observation)
    && observation.nosniff !== true
    && ['main_frame', 'script', 'stylesheet', 'worker', 'sharedworker'].includes(observation.type)
  ) {
    issues.push({
      severity: 'warning',
      code: 'missing_nosniff',
      message: `Thiếu X-Content-Type-Options: nosniff cho ${expectedPath}`,
      url: observation.url,
    });
  }

  return issues;
}
