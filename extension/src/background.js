/*
 * MNG Cloud Trusted — background integrity verifier.
 *
 * Trust flow:
 *   1. read signed release.json + release.sig from GitHub (not from the app origin)
 *   2. verify P-256 signatures with the key pinned in config.js
 *   3. verify the signed manifest hash and version
 *   4. ask the content script to hash every signed asset over the authenticated
 *      same-origin connection and compare the bytes with the manifest
 *   5. observe webRequest metadata for unlisted/critical resources
 *
 * The cloud origin is never trusted to describe itself.
 */

import { CONFIG } from './config.js';
import {
  TrustError,
  checkObservation,
  deploymentForUrl,
  importVerifyKey,
  indexManifest,
  isCriticalObservation,
  mimeMatches,
  parseJsonBytes,
  sha256Hex,
  validateConfig,
  validateRelease,
  verifyEcdsaHex,
  verifyReleaseAndManifest,
} from './trust.js';

const ext = globalThis.browser ?? globalThis.chrome;
const config = validateConfig(CONFIG);
const RELEASE_TIMEOUT = config.limits.releaseTimeoutMs;
const PAGE_TIMEOUT = config.limits.pageTimeoutMs;
const ROLLBACK_KEY = 'mngTrustRollbackV1';
const CACHE_KEY = 'mngTrustedReleaseV1';
const MAX_RELEASE_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;

const tabStates = new Map();
const checks = new Map();
const earlyObservations = new Map();

// Signed metadata that fails verification is a positive mismatch, not an
// inability to check. Those states must be red (NOT SAFE), while transport
// failures remain amber (unverified).
const RELEASE_INVALID_CODES = new Set([
  'app_base_mismatch',
  'bad_manifest_signature',
  'bad_release_signature',
  'invalid_manifest',
  'invalid_release',
  'manifest_hash_mismatch',
  'rollback',
  'version_mismatch',
]);

const requestUrls = [...new Set(config.deployments.map((item) => `${item.origin}/*`))];

ext.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  void onNavigation(details.tabId, details.url);
});

ext.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const deployment = deploymentForUrl(details.url, config.deployments);
    if (!deployment) return;
    const observation = observationFromHeaders(details);
    if (!observation) return;
    const check = checks.get(details.tabId);
    if (check) {
      queueObservation(check, observation);
      if (check.manifestIndex) evaluateObservation(check, observation);
    } else {
      const queue = earlyObservations.get(details.tabId) || [];
      if (queue.length < 200) queue.push(observation);
      earlyObservations.set(details.tabId, queue);
    }
  },
  { urls: requestUrls },
  ['responseHeaders'],
);

ext.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const deployment = deploymentForUrl(details.url, config.deployments);
    if (!deployment) return;
    const observation = {
      url: details.url,
      type: details.type,
      statusCode: 0,
      mime: '',
      nosniff: false,
      error: details.error,
      time: Date.now(),
    };
    if (!isCriticalObservation(observation)) return;
    const check = checks.get(details.tabId);
    if (check) {
      recordIssue(check, {
        severity: 'error',
        code: 'network_error',
        message: `Không tải được ${details.url}: ${details.error || 'network error'}`,
        url: details.url,
      });
      publish(check);
    }
  },
  { urls: requestUrls },
);

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string' || !message.type.startsWith('mng-trust')) {
    return false;
  }
  handleMessage(message, sender)
    .then((value) => sendResponse(value))
    .catch((error) => sendResponse({ error: String((error && error.message) || error) }));
  return true;
});

ext.tabs.onRemoved.addListener((tabId) => {
  clearTab(tabId);
});

async function handleMessage(message, sender) {
  if (message.type === 'mng-trust-hello') {
    const tabId = sender.tab && sender.tab.id;
    const url = (sender.tab && sender.tab.url) || message.url;
    if (!Number.isInteger(tabId) || !url) return { ok: false };
    const deployment = deploymentForUrl(url, config.deployments);
    if (!deployment) return { ok: true, inactive: true };
    let check = checks.get(tabId);
    if (!check || check.url !== url) {
      check = await startVerification(tabId, url);
    } else if (check.manifest) {
      await sendStart(check);
    }
    return { ok: true, state: check ? publicState(check.state) : null };
  }

  if (message.type === 'mng-trust-progress') {
    const check = currentCheck(sender.tab && sender.tab.id, message.checkId);
    if (!check) return { ok: false };
    check.state.progress = {
      done: Number(message.done) || 0,
      total: Number(message.total) || 0,
    };
    publish(check);
    return { ok: true };
  }

  if (message.type === 'mng-trust-page-result') {
    const check = currentCheck(sender.tab && sender.tab.id, message.checkId);
    if (!check) return { ok: false };
    check.pageResult = message;
    for (const issue of asIssueList(message.issues)) recordIssue(check, issue);
    for (const issue of asIssueList(message.warnings)) recordIssue(check, issue);
    check.state.progress = {
      done: Number(message.hashed) || check.state.progress.done,
      total: Number(message.total) || check.state.progress.total,
    };
    check.state.pageVersion = typeof message.version === 'string' ? message.version : null;
    if (check.networkResult) finalize(check);
    return { ok: true };
  }

  if (message.type === 'mng-trust-resource-issue') {
    const check = currentCheck(sender.tab && sender.tab.id, message.checkId);
    if (!check) return { ok: false };
    recordIssue(check, message.issue || {});
    await publish(check);
    return { ok: true };
  }

  if (message.type === 'mng-trust-get') {
    const tabId = Number(message.tabId);
    const url = message.url;
    if (!Number.isInteger(tabId) || !url) return { state: null };
    const deployment = deploymentForUrl(url, config.deployments);
    if (!deployment) return { state: null, releaseBase: config.releaseBase };
    let check = checks.get(tabId);
    if (!check) check = await startVerification(tabId, url);
    return {
      state: check ? publicState(check.state) : null,
      deployment,
      releaseBase: config.releaseBase,
      requireOnlineVerification: config.requireOnlineVerification,
    };
  }

  if (message.type === 'mng-trust-recheck') {
    const tabId = Number(message.tabId);
    const url = message.url;
    if (!Number.isInteger(tabId) || !url) return { ok: false };
    const check = await startVerification(tabId, url, { force: true });
    return { ok: Boolean(check) };
  }

  return { ok: false, error: 'unknown_message' };
}

async function onNavigation(tabId, url) {
  const deployment = deploymentForUrl(url, config.deployments);
  if (!deployment) {
    clearTab(tabId);
    return;
  }
  await startVerification(tabId, url);
}

async function startVerification(tabId, url, { force = false } = {}) {
  const deployment = deploymentForUrl(url, config.deployments);
  if (!deployment) {
    clearTab(tabId);
    return null;
  }
  const existing = checks.get(tabId);
  if (
    !force
    && existing
    && existing.url === url
    && existing.state.status === 'checking'
    && Date.now() - existing.startedAt < 2000
  ) {
    await sendState(existing);
    return existing;
  }
  if (existing) cancelCheck(existing);

  const check = {
    id: crypto.randomUUID(),
    tabId,
    url,
    deployment,
    startedAt: Date.now(),
    state: {
      tabId,
      url,
      checkId: '',
      status: 'checking',
      version: null,
      releaseVersion: null,
      sequence: null,
      source: null,
      pageVersion: null,
      startedAt: Date.now(),
      progress: { done: 0, total: 0 },
      issues: [],
      hasError: false,
    },
    release: null,
    manifest: null,
    manifestIndex: null,
    observations: [],
    pageResult: null,
    networkResult: null,
    timer: null,
    releaseFailed: false,
    releaseInvalid: false,
    cancelled: false,
  };
  check.state.checkId = check.id;
  checks.set(tabId, check);
  tabStates.set(tabId, check.state);

  const queue = earlyObservations.get(tabId) || [];
  earlyObservations.delete(tabId);
  for (const observation of queue) {
    check.observations.push(observation);
  }

  await updateBadge(check);
  await sendState(check);
  void runCheck(check);
  return check;
}

async function runCheck(check) {
  try {
    const trust = await loadTrustedRelease(check.deployment);
    if (check.cancelled) return;
    check.release = trust.release;
    check.manifest = trust.manifest;
    check.manifestIndex = indexManifest(trust.manifest);
    check.state.version = trust.manifest.version;
    check.state.releaseVersion = trust.release.version;
    check.state.sequence = trust.release.sequence;
    check.state.source = trust.source;
    if (trust.warning) {
      recordIssue(check, {
        severity: 'warning',
        code: 'offline_cache',
        message: trust.warning,
      });
    }
    for (const observation of check.observations) {
      evaluateObservation(check, observation, { publish: false });
    }
    await sendStart(check);
    void runNetworkVerification(check);
    await publish(check);
    check.timer = setTimeout(() => {
      if (check.cancelled || (check.pageResult && check.networkResult)) return;
      if (!check.pageResult) {
        recordIssue(check, {
          severity: 'warning',
          code: 'page_check_timeout',
          message: 'Trang không hoàn tất việc kiểm tra nội dung trong thời gian cho phép.',
        });
      }
      if (!check.networkResult) {
        recordIssue(check, {
          severity: 'warning',
          code: 'network_check_timeout',
          message: 'Extension không hoàn tất việc đối chiếu nội dung máy chủ trong thời gian cho phép.',
        });
      }
      finalize(check);
    }, PAGE_TIMEOUT);
  } catch (error) {
    if (check.cancelled) return;
    const code = error instanceof TrustError ? error.code : 'release_unavailable';
    if (RELEASE_INVALID_CODES.has(code)) {
      check.releaseInvalid = true;
    } else {
      check.releaseFailed = true;
    }
    recordIssue(check, {
      severity: 'error',
      code,
      message: `Không xác minh được bản phát hành: ${(error && error.message) || error}`,
    });
    finalize(check);
  }
}

async function loadTrustedRelease(deployment) {
  const key = await importVerifyKey(config.pinnedPublicJwk);
  try {
    const releaseBytes = await fetchBytes(
      new URL('release.json', config.releaseBase).href,
      RELEASE_TIMEOUT,
      MAX_RELEASE_BYTES,
    );
    const releaseSignature = new TextDecoder().decode(
      await fetchBytes(
        new URL('release.sig', config.releaseBase).href,
        RELEASE_TIMEOUT,
        4096,
      ),
    ).trim();

    if (!(await verifyEcdsaHex(releaseBytes, releaseSignature, key))) {
      throw new TrustError('bad_release_signature', 'release signature is invalid');
    }
    const release = validateRelease(parseJsonBytes(releaseBytes, 'release.json'));
    if (release.app_base !== deployment.appBase) {
      throw new TrustError(
        'app_base_mismatch',
        `release targets ${release.app_base}, expected ${deployment.appBase}`,
      );
    }

    const manifestUrl = new URL(release.manifest, config.releaseBase).href;
    const manifestSignatureUrl = new URL(release.manifest_signature, config.releaseBase).href;
    const [manifestBytes, manifestSignatureBytes] = await Promise.all([
      fetchBytes(manifestUrl, RELEASE_TIMEOUT, MAX_MANIFEST_BYTES),
      fetchBytes(manifestSignatureUrl, RELEASE_TIMEOUT, 4096),
    ]);
    const manifestSignature = new TextDecoder().decode(manifestSignatureBytes).trim();
    const checked = await verifyReleaseAndManifest({
      releaseBytes,
      releaseSignature,
      manifestBytes,
      manifestSignature,
      publicJwk: config.pinnedPublicJwk,
      verifyKey: key,
    });
    if (checked.release.app_base !== deployment.appBase) {
      throw new TrustError('app_base_mismatch', 'release app_base does not match deployment');
    }

    await guardRollback(checked.release);
    await cacheRelease({
      releaseBytes,
      releaseSignature,
      manifestBytes,
      manifestSignature,
    });
    return { release: checked.release, manifest: checked.manifest, source: 'github' };
  } catch (error) {
    const code = error instanceof TrustError ? error.code : '';
    // Never paper over a bad signature or a rollback with the cached release.
    // Cache fallback exists for connectivity failures only.
    if (RELEASE_INVALID_CODES.has(code) || config.requireOnlineVerification) throw error;
    const cached = await loadCachedRelease();
    if (!cached) throw error;
    const keyAgain = await importVerifyKey(config.pinnedPublicJwk);
    const checked = await verifyReleaseAndManifest({
      ...cached,
      publicJwk: config.pinnedPublicJwk,
      verifyKey: keyAgain,
    });
    if (checked.release.app_base !== deployment.appBase) {
      throw new TrustError('app_base_mismatch', 'cached release targets another app_base');
    }
    await guardRollback(checked.release);
    return {
      release: checked.release,
      manifest: checked.manifest,
      source: 'cache',
      warning: `Không tải được metadata từ GitHub (${(error && error.message) || error}); đang dùng bản đã xác minh gần nhất.`,
    };
  }
}

async function guardRollback(release) {
  const stored = await ext.storage.local.get(ROLLBACK_KEY);
  const previous = stored[ROLLBACK_KEY];
  if (previous && Number.isSafeInteger(previous.sequence)) {
    if (release.sequence < previous.sequence) {
      throw new TrustError(
        'rollback',
        `release sequence ${release.sequence} is older than ${previous.sequence}`,
      );
    }
    if (release.sequence === previous.sequence && release.version !== previous.version) {
      throw new TrustError(
        'rollback',
        `release sequence ${release.sequence} changed version from ${previous.version} to ${release.version}`,
      );
    }
    if (release.sequence === previous.sequence) return;
  }
  await ext.storage.local.set({
    [ROLLBACK_KEY]: { sequence: release.sequence, version: release.version },
  });
}

async function cacheRelease({ releaseBytes, releaseSignature, manifestBytes, manifestSignature }) {
  await ext.storage.local.set({
    [CACHE_KEY]: {
      releaseBytes: bytesToBase64(releaseBytes),
      releaseSignature,
      manifestBytes: bytesToBase64(manifestBytes),
      manifestSignature,
      savedAt: Date.now(),
    },
  });
}

async function loadCachedRelease() {
  const stored = await ext.storage.local.get(CACHE_KEY);
  const cached = stored[CACHE_KEY];
  if (!cached || typeof cached !== 'object') return null;
  try {
    return {
      releaseBytes: base64ToBytes(cached.releaseBytes),
      releaseSignature: String(cached.releaseSignature || ''),
      manifestBytes: base64ToBytes(cached.manifestBytes),
      manifestSignature: String(cached.manifestSignature || ''),
    };
  } catch {
    return null;
  }
}

async function sendStart(check) {
  if (!check.manifest) return false;
  const payload = {
    type: 'mng-trust-start',
    checkId: check.id,
    appBase: check.deployment.appBase,
    releaseVersion: check.manifest.version,
    assets: check.manifest.assets,
    limits: {
      maxAssetBytes: config.limits.maxAssetBytes,
      maxTotalBytes: config.limits.maxTotalBytes,
    },
  };
  try {
    await ext.tabs.sendMessage(check.tabId, payload);
    return true;
  } catch {
    try {
      await ext.scripting.executeScript({
        target: { tabId: check.tabId },
        files: ['content.js'],
      });
      await ext.tabs.sendMessage(check.tabId, payload);
      return true;
    } catch (error) {
      // This is an inability to verify, not a positive mismatch. It must stay
      // amber rather than claiming the page is malicious.
      check.pageFailed = true;
      recordIssue(check, {
        severity: 'warning',
        code: 'content_script_unavailable',
        message: `Không thể chạy kiểm tra nội dung trong trang: ${(error && error.message) || error}`,
      });
      return false;
    }
  }
}

function queueObservation(check, observation) {
  check.observations.push(observation);
  if (check.observations.length > 500) check.observations.splice(0, 100);
}

function evaluateObservation(check, observation, { publish: shouldPublish = true } = {}) {
  for (const issue of checkObservation(observation, check.deployment, check.manifestIndex)) {
    recordIssue(check, issue);
  }
  if (shouldPublish) void publish(check);
}

function observationFromHeaders(details) {
  if (!details.responseHeaders) return null;
  let mime = '';
  let nosniff = false;
  for (const header of details.responseHeaders) {
    const name = String(header.name || '').toLowerCase();
    const value = String(header.value || '');
    if (name === 'content-type') mime = value;
    if (name === 'x-content-type-options' && value.toLowerCase().includes('nosniff')) {
      nosniff = true;
    }
  }
  return {
    url: details.url,
    type: details.type,
    statusCode: Number(details.statusCode) || 0,
    mime,
    nosniff,
    time: Date.now(),
  };
}

function recordIssue(check, issue) {
  if (!issue || typeof issue.message !== 'string') return;
  const normalized = {
    severity: issue.severity === 'warning' ? 'warning' : 'error',
    code: String(issue.code || 'unknown'),
    message: issue.message.slice(0, 500),
    url: issue.url ? String(issue.url).slice(0, 2048) : undefined,
  };
  if (normalized.severity === 'error') check.state.hasError = true;
  const id = `${normalized.severity}|${normalized.code}|${normalized.url || ''}|${normalized.message}`;
  if (check.state.issues.some((item) => item.id === id)) return;
  if (check.state.issues.length >= 50) return;
  check.state.issues.push({ ...normalized, id });
}

async function runNetworkVerification(check) {
  const assets = check.manifest.assets;
  let hashed = 0;
  let totalBytes = 0;
  try {
    for (const asset of assets) {
      if (check.cancelled) return;
      const url = new URL(asset.path, check.deployment.origin + check.deployment.appBase).href;
      try {
        const result = await fetchAsset(url, 20000, config.limits.maxAssetBytes);
        totalBytes += result.bytes.byteLength;
        if (totalBytes > config.limits.maxTotalBytes) {
          recordIssue(check, {
            severity: 'warning',
            code: 'network_budget_exceeded',
            message: `Extension đã vượt giới hạn ${config.limits.maxTotalBytes} byte khi đối chiếu; dừng phần còn lại.`,
          });
          break;
        }
        if (asset.mime && !mimeMatches(asset.mime, result.mime)) {
          recordIssue(check, {
            severity: 'error',
            code: 'mime_mismatch',
            message: `MIME không khớp cho ${asset.path}: cần ${asset.mime}, máy chủ trả ${result.mime || 'không có'}.`,
            url,
          });
        }
        if (result.bytes.byteLength !== asset.size) {
          recordIssue(check, {
            severity: 'error',
            code: 'size_mismatch',
            message: `Kích thước không khớp cho ${asset.path}: cần ${asset.size}, máy chủ trả ${result.bytes.byteLength}.`,
            url,
          });
        }
        const digest = await sha256Hex(result.bytes);
        if (digest !== asset.sha256) {
          recordIssue(check, {
            severity: 'error',
            code: 'hash_mismatch',
            message: `Máy chủ trả nội dung khác bản đã ký cho ${asset.path} (extension đối chiếu trực tiếp).`,
            url,
          });
        }
      } catch (error) {
        recordIssue(check, {
          severity: 'error',
          code: 'asset_unavailable',
          message: `Extension không đọc được ${asset.path}: ${(error && error.message) || error}`,
          url,
        });
      }
      hashed += 1;
      check.state.networkProgress = { done: hashed, total: assets.length };
      if (check.state.hasError) void publish(check);
    }
  } finally {
    check.networkResult = { complete: !check.cancelled, hashed, total: assets.length };
    if (check.pageResult) finalize(check);
    else void publish(check);
  }
}

async function fetchAsset(url, timeoutMs, maxBytes) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (response.redirected) throw new Error('unexpected redirect');
    const mime = response.headers.get('content-type') || '';
    const declared = Number(response.headers.get('content-length') || 0);
    if (declared > maxBytes) throw new Error(`lớn hơn ${maxBytes} byte`);
    const reader = response.body && response.body.getReader();
    if (!reader) {
      const buffer = new Uint8Array(await response.arrayBuffer());
      if (buffer.byteLength > maxBytes) throw new Error(`lớn hơn ${maxBytes} byte`);
      return { bytes: buffer, mime };
    }
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`lớn hơn ${maxBytes} byte`);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { bytes, mime };
  } finally {
    clearTimeout(timer);
  }
}

function finalize(check) {
  if (check.cancelled) return;
  if (check.timer) {
    clearTimeout(check.timer);
    check.timer = null;
  }
  if (check.releaseInvalid) {
    check.state.status = 'unsafe';
  } else if (check.releaseFailed) {
    check.state.status = 'unverified';
  } else if (check.state.hasError) {
    check.state.status = 'unsafe';
  } else if (
    check.pageResult
    && check.pageResult.complete === true
    && check.networkResult
    && check.networkResult.complete === true
  ) {
    check.state.status = 'verified';
  } else {
    check.state.status = 'unverified';
  }
  void publish(check);
}

async function publish(check) {
  if (check.cancelled) return;
  // An observation can arrive while a previous publish is in flight. Recompute
  // the status here so a hard error is never masked by an older 'checking' UI.
  if (check.state.status !== 'unsafe' && check.state.status !== 'unverified' && !check.releaseFailed) {
    if (check.state.hasError) check.state.status = 'unsafe';
    else if (
      check.pageResult
      && check.pageResult.complete === true
      && check.networkResult
      && check.networkResult.complete === true
    ) {
      check.state.status = 'verified';
    }
  }
  await updateBadge(check);
  await sendState(check);
}

async function updateBadge(check) {
  const status = check.state.status;
  const text = status === 'verified' ? '✓' : status === 'unsafe' ? '!' : status === 'unverified' ? '?' : '…';
  const color = status === 'verified' ? '#0f7b3f' : status === 'unsafe' ? '#b42318' : '#8a5a00';
  try {
    await ext.action.setBadgeText({ tabId: check.tabId, text });
    await ext.action.setBadgeBackgroundColor({ tabId: check.tabId, color });
    await ext.action.setTitle({
      tabId: check.tabId,
      title: `MNG Cloud Trusted — ${statusLabel(status)}`,
    });
  } catch {
    // The tab may have closed between the event and this update.
  }
}

async function sendState(check) {
  await sendToTab(check.tabId, {
    type: 'mng-trust-state',
    state: publicState(check.state),
  });
}

async function sendToTab(tabId, message) {
  try {
    await ext.tabs.sendMessage(tabId, message);
  } catch {
    // Content script not injected yet, or the tab is gone.
  }
}

function publicState(state) {
  return {
    tabId: state.tabId,
    url: state.url,
    checkId: state.checkId,
    status: state.status,
    version: state.version,
    releaseVersion: state.releaseVersion,
    sequence: state.sequence,
    source: state.source,
    pageVersion: state.pageVersion,
    startedAt: state.startedAt,
    progress: state.progress,
    issues: state.issues.map(({ severity, code, message, url }) => ({
      severity,
      code,
      message,
      url,
    })),
    hasError: state.hasError,
  };
}

function statusLabel(status) {
  return {
    checking: 'đang xác minh',
    verified: 'đã xác minh',
    unsafe: 'KHÔNG AN TOÀN',
    unverified: 'chưa thể xác minh',
  }[status] || status;
}

function currentCheck(tabId, checkId) {
  if (!Number.isInteger(tabId) || typeof checkId !== 'string') return null;
  const check = checks.get(tabId);
  return check && check.id === checkId ? check : null;
}

function cancelCheck(check) {
  check.cancelled = true;
  if (check.timer) clearTimeout(check.timer);
  check.timer = null;
}

function clearTab(tabId) {
  const check = checks.get(tabId);
  if (check) cancelCheck(check);
  checks.delete(tabId);
  tabStates.delete(tabId);
  earlyObservations.delete(tabId);
  void resetBadge(tabId);
  void sendToTab(tabId, { type: 'mng-trust-inactive' });
}

async function resetBadge(tabId) {
  try {
    await ext.action.setBadgeText({ tabId, text: '' });
    await ext.action.setTitle({ tabId, title: 'MNG Cloud Trusted' });
  } catch {
    // The tab is already gone.
  }
}

function asIssueList(value) {
  return Array.isArray(value) ? value.slice(0, 50) : [];
}

async function fetchBytes(url, timeoutMs, maxBytes) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'follow',
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`${url} HTTP ${response.status}`);
    }
    const declared = Number(response.headers.get('content-length') || 0);
    if (declared > maxBytes) {
      throw new Error(`${url} is larger than ${maxBytes} bytes`);
    }
    const reader = response.body && response.body.getReader();
    if (!reader) {
      const buffer = new Uint8Array(await response.arrayBuffer());
      if (buffer.byteLength > maxBytes) throw new Error(`${url} is too large`);
      return buffer;
    }
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`${url} is too large`);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    clearTimeout(timer);
  }
}

function bytesToBase64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  const chunk = 0x8000;
  for (let index = 0; index < view.length; index += chunk) {
    binary += String.fromCharCode(...view.subarray(index, index + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(text) {
  const binary = atob(String(text || ''));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
