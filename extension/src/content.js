/*
 * MNG Cloud Trusted — content script.
 *
 * Runs in the page's origin so every verification fetch carries the user's
 * authenticated same-origin cookies. It never trusts page JavaScript: the
 * extension worker supplies the signed asset list and this script only hashes
 * bytes and reports facts.
 *
 * A page-controlled service worker can make subresource requests appear to the
 * extension's webRequest listener as worker traffic rather than tab traffic.
 * The DOM and PerformanceObserver watches below are therefore authoritative
 * for resources loaded by this document.
 */

(() => {
  if (globalThis.__mngTrustContentLoaded) return;
  globalThis.__mngTrustContentLoaded = true;

  const runtime = (globalThis.browser && globalThis.browser.runtime)
    || globalThis.chrome.runtime;
  const MAX_ISSUES = 50;
  let host = null;
  let shadow = null;
  let contentRoot = null;
  let sheet = null;
  let hideTimer = null;
  let guardTimer = null;
  let removalObserver = null;
  let resourceObserver = null;
  let resourceState = null;
  let lastState = null;
  let runningCheckId = null;

  runtime.onMessage.addListener((message) => {
    if (!message || typeof message.type !== 'string') return;
    if (message.type === 'mng-trust-start') {
      void runChecks(message);
      return;
    }
    if (message.type === 'mng-trust-state') {
      lastState = message.state || null;
      render(lastState);
      return;
    }
    if (message.type === 'mng-trust-inactive') {
      lastState = null;
      stopResourceWatch();
      removeBanner();
    }
  });

  send({ type: 'mng-trust-hello', url: location.href });

  async function runChecks(payload) {
    if (!payload || typeof payload.checkId !== 'string') return;
    if (runningCheckId === payload.checkId) return;
    runningCheckId = payload.checkId;

    const issues = [];
    const warnings = [];
    const assets = new Map((payload.assets || []).map((asset) => [asset.path, asset]));
    const maxAssetBytes = Number(payload.limits && payload.limits.maxAssetBytes) || 32 * 1024 * 1024;
    const maxTotalBytes = Number(payload.limits && payload.limits.maxTotalBytes) || 128 * 1024 * 1024;
    let totalFetched = 0;
    let done = 0;

    const addIssue = (severity, code, message, url) => {
      const list = severity === 'warning' ? warnings : issues;
      if (list.length >= MAX_ISSUES) return;
      list.push({ severity, code, message: String(message).slice(0, 500), url });
    };

    try {
      await domReady();
      scanDocument(payload.appBase, assets, addIssue);
      startResourceWatch(payload, assets, addIssue);

      const total = assets.size;
      send({ type: 'mng-trust-progress', checkId: payload.checkId, done, total });

      for (const asset of assets.values()) {
        const url = new URL(asset.path, location.origin + payload.appBase).href;
        try {
          const result = await fetchLimited(url, maxAssetBytes);
          totalFetched += result.bytes.byteLength;
          if (totalFetched > maxTotalBytes) {
            addIssue(
              'warning',
              'hash_budget_exceeded',
              `Đã vượt giới hạn ${maxTotalBytes} byte khi xác minh; dừng kiểm tra phần còn lại.`,
              url,
            );
            break;
          }
          if (asset.mime && !mimeMatches(asset.mime, result.mime)) {
            addIssue(
              'error',
              'mime_mismatch',
              `MIME không khớp cho ${asset.path}: cần ${asset.mime}, nhận ${result.mime || 'không có'}.`,
              url,
            );
          }
          if (result.bytes.byteLength !== asset.size) {
            addIssue(
              'error',
              'size_mismatch',
              `Kích thước không khớp cho ${asset.path}: cần ${asset.size}, nhận ${result.bytes.byteLength}.`,
              url,
            );
          }
          const digest = await sha256Hex(result.bytes);
          if (digest !== asset.sha256) {
            addIssue(
              'error',
              'hash_mismatch',
              `Hash không khớp cho ${asset.path}: nội dung trên máy chủ không phải bản đã ký.`,
              url,
            );
          }
        } catch (error) {
          addIssue(
            'error',
            'asset_unavailable',
            `Không đọc được ${asset.path}: ${(error && error.message) || error}`,
            url,
          );
        }
        done += 1;
        send({ type: 'mng-trust-progress', checkId: payload.checkId, done, total });
      }

      const meta = document.querySelector('meta[name="mng-version"]');
      const pageVersion = meta ? String(meta.getAttribute('content') || '').trim() : '';
      if (!pageVersion) {
        addIssue('error', 'version_missing', 'Trang không công bố phiên bản đã ký (mng-version).');
      } else if (pageVersion !== payload.releaseVersion) {
        addIssue(
          'error',
          'version_mismatch',
          `Trang đang chạy ${pageVersion}, bản đã ký hiện tại là ${payload.releaseVersion}.`,
        );
      }

      if (isShellDocument(payload.appBase)) {
        const indexAsset = assets.get('index.html');
        if (indexAsset) {
          try {
            const documentBytes = await fetchLimited(location.href, maxAssetBytes);
            const digest = await sha256Hex(documentBytes.bytes);
            if (digest !== indexAsset.sha256) {
              addIssue(
                'error',
                'document_mismatch',
                'Nội dung HTML đang hiển thị không khớp với index.html đã ký.',
                location.href,
              );
            }
          } catch (error) {
            addIssue(
              'warning',
              'document_unavailable',
              `Không đọc lại được tài liệu để đối chiếu: ${(error && error.message) || error}`,
              location.href,
            );
          }
        }
      }

      send({
        type: 'mng-trust-page-result',
        checkId: payload.checkId,
        complete: true,
        issues,
        warnings,
        hashed: done,
        total,
        version: pageVersion,
        documentUrl: location.href,
      });
    } catch (error) {
      addIssue(
        'error',
        'page_check_failed',
        `Kiểm tra nội dung thất bại: ${(error && error.message) || error}`,
        location.href,
      );
      send({
        type: 'mng-trust-page-result',
        checkId: payload.checkId,
        complete: true,
        issues,
        warnings,
        hashed: done,
        total: assets.size,
        version: '',
        documentUrl: location.href,
      });
    }
  }

  function scanDocument(appBase, assets, addIssue) {
    const meta = document.querySelector('meta[name="mng-version"]');
    if (!meta) {
      addIssue('error', 'version_missing', 'Thiếu meta mng-version trong tài liệu.');
    }

    const base = document.querySelector('base[href]');
    if (base) {
      addIssue('error', 'unexpected_base', 'Trang có thẻ <base> làm thay đổi đích tài nguyên.');
    }

    let inspected = 0;
    for (const element of document.querySelectorAll('*')) {
      if (++inspected > 5000) break;
      if (element.id === 'mng-trust-host') continue;
      for (const attribute of element.attributes) {
        if (/^on/i.test(attribute.name)) {
          addIssue(
            'error',
            'inline_event_handler',
            `Phát hiện thuộc tính sự kiện nội tuyến: ${element.tagName.toLowerCase()}[${attribute.name}].`,
          );
          break;
        }
      }
    }

    for (const script of document.querySelectorAll('script')) {
      if (!script.src) {
        const type = String(script.getAttribute('type') || '').toLowerCase();
        const executable = !type
          || type === 'module'
          || type.includes('javascript')
          || type.includes('ecmascript');
        if (executable && String(script.textContent || '').trim()) {
          addIssue('error', 'inline_script', 'Phát hiện script nội tuyến không có hash/chữ ký.');
        }
        continue;
      }
      checkDomResource(script.src, appBase, assets, addIssue, 'script');
    }

    for (const link of document.querySelectorAll('link[rel]')) {
      const rel = String(link.getAttribute('rel') || '').toLowerCase();
      if (!rel.split(/\s+/).some((part) => part === 'stylesheet' || part === 'manifest')) continue;
      const href = link.getAttribute('href');
      if (!href) continue;
      checkDomResource(link.href, appBase, assets, addIssue, 'link');
    }

    for (const anchor of document.querySelectorAll('[href^="javascript:"], [src^="javascript:"]')) {
      addIssue('error', 'javascript_url', 'Phát hiện URL javascript: trong tài liệu.');
    }
  }

  function checkDomResource(rawUrl, appBase, assets, addIssue, kind) {
    let url;
    try {
      url = new URL(rawUrl, location.href);
    } catch {
      addIssue('error', 'bad_resource_url', `URL tài nguyên không hợp lệ (${kind}).`, rawUrl);
      return;
    }
    if (url.origin !== location.origin) {
      addIssue(
        'error',
        'cross_origin_resource',
        `Tài nguyên ${kind} nằm ngoài origin: ${url.origin}.`,
        url.href,
      );
      return;
    }
    const path = pathForUrl(url, appBase);
    if (path === null) return;
    if (!assets.has(path)) {
      addIssue(
        'error',
        'unlisted_resource',
        `Tài nguyên ${kind} không có trong manifest: ${path}.`,
        url.href,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Dynamic resource watch
  // -------------------------------------------------------------------------

  function startResourceWatch(payload, assets, addIssue) {
    stopResourceWatch();
    if (!document.documentElement) return;

    const state = {
      checkId: payload.checkId,
      appBase: payload.appBase,
      assets,
      addIssue,
      seen: new Set(),
      perf: null,
    };
    resourceState = state;

    for (const element of document.querySelectorAll('script[src], link[href]')) {
      inspectElement(element, state);
    }

    resourceObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'attributes') {
          inspectElement(mutation.target, state);
          continue;
        }
        for (const node of mutation.addedNodes) {
          if (!(node instanceof Element)) continue;
          inspectElement(node, state);
          for (const child of node.querySelectorAll('script[src], link[href]')) {
            inspectElement(child, state);
          }
        }
      }
    });
    resourceObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'href', 'rel', 'type', 'as'],
    });

    if (typeof PerformanceObserver === 'function') {
      try {
        const perf = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) inspectPerformanceEntry(entry, state);
        });
        perf.observe({ type: 'resource', buffered: true });
        state.perf = perf;
      } catch {
        // PerformanceObserver is optional; the DOM watch still covers markup.
      }
    }
  }

  function stopResourceWatch() {
    if (resourceObserver) {
      resourceObserver.disconnect();
      resourceObserver = null;
    }
    if (resourceState && resourceState.perf) {
      try {
        resourceState.perf.disconnect();
      } catch {
        // Already disconnected.
      }
    }
    resourceState = null;
  }

  function inspectElement(element, state) {
    if (!element || !state) return;
    if (element.id === 'mng-trust-host') return;
    if (typeof element.closest === 'function' && element.closest('#mng-trust-host')) return;

    if (element.tagName === 'SCRIPT') {
      if (element.src) considerResource(element.src, 'script', state);
      return;
    }

    if (element.tagName === 'LINK') {
      const rel = String(element.getAttribute('rel') || '')
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
      const href = element.getAttribute('href');
      if (!href) return;
      if (rel.includes('stylesheet')) {
        considerResource(element.href, 'stylesheet', state);
      } else if (rel.includes('manifest')) {
        considerResource(element.href, 'manifest', state);
      } else if (rel.includes('modulepreload')) {
        considerResource(element.href, 'script', state);
      } else if (rel.includes('preload')) {
        const as = String(element.getAttribute('as') || '').toLowerCase();
        if (as === 'script' || as === 'style' || as === 'font' || as === 'worker') {
          considerResource(element.href, as, state);
        }
      }
    }
  }

  function inspectPerformanceEntry(entry, state) {
    if (!entry || !state) return;
    const initiator = String(entry.initiatorType || '').toLowerCase();
    if (initiator !== 'script' && initiator !== 'link' && initiator !== 'css') return;
    // `link` also covers icons and other non-critical files; the DOM watch
    // checks those precisely, so only consider code-like extensions here.
    if (initiator === 'link' && !/\.(?:css|js|mjs|wasm|webmanifest)(?:$|\?)/i.test(entry.name)) {
      return;
    }
    considerResource(entry.name, initiator === 'link' ? 'stylesheet' : initiator, state, {
      perf: true,
    });
  }

  function considerResource(rawUrl, kind, state, { perf = false } = {}) {
    let url;
    try {
      url = new URL(rawUrl, location.href);
    } catch {
      reportResource(state, {
        severity: 'error',
        code: 'bad_resource_url',
        message: `URL tài nguyên không hợp lệ (${kind}).`,
        url: String(rawUrl).slice(0, 2048),
      });
      return;
    }

    const key = `${url.origin}${url.pathname}`;
    if (state.seen.has(key)) return;
    state.seen.add(key);

    if (url.origin !== location.origin) {
      if (kind === 'script' || kind === 'stylesheet' || kind === 'worker') {
        reportResource(state, {
          severity: 'error',
          code: 'cross_origin_resource',
          message: `Tài nguyên ${kind} nằm ngoài origin: ${url.origin}.`,
          url: url.href,
        });
      }
      return;
    }

    const path = pathForUrl(url, state.appBase);
    if (path === null) return;
    if (state.assets.has(path)) return;

    reportResource(state, {
      severity: 'error',
      code: 'unlisted_resource',
      message: `Tài nguyên không có trong manifest: ${path} (${perf ? 'qua network' : kind}).`,
      url: url.href,
    });
  }

  function reportResource(state, issue) {
    const normalized = {
      severity: issue.severity === 'warning' ? 'warning' : 'error',
      code: String(issue.code || 'unknown'),
      message: String(issue.message || '').slice(0, 500),
      url: issue.url ? String(issue.url).slice(0, 2048) : undefined,
    };
    state.addIssue(normalized.severity, normalized.code, normalized.message, normalized.url);
    send({
      type: 'mng-trust-resource-issue',
      checkId: state.checkId,
      issue: normalized,
    });
  }

  function pathForUrl(url, appBase) {
    const base = appBase.endsWith('/') ? appBase : `${appBase}/`;
    const stripped = base.slice(0, -1);
    if (url.pathname !== base && url.pathname !== stripped && !url.pathname.startsWith(base)) {
      return null;
    }
    const relative = url.pathname.slice(base.length);
    return relative === '' || relative.endsWith('/') ? 'index.html' : relative;
  }

  function isShellDocument(appBase) {
    const base = appBase.endsWith('/') ? appBase : `${appBase}/`;
    return location.pathname === base
      || location.pathname === base.slice(0, -1)
      || location.pathname === `${base}index.html`;
  }

  async function fetchLimited(url, maxBytes) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, {
        cache: 'no-store',
        credentials: 'same-origin',
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
        return { bytes: buffer, mime, status: response.status };
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
      return { bytes, mime, status: response.status };
    } finally {
      clearTimeout(timer);
    }
  }

  async function sha256Hex(bytes) {
    if (!globalThis.crypto || !crypto.subtle) {
      throw new Error('WebCrypto is not available on this origin');
    }
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
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

  function mimeMatches(expected, actual) {
    const want = String(expected || '').split(';')[0].trim().toLowerCase();
    const got = String(actual || '').split(';')[0].trim().toLowerCase();
    if (!want || !got) return true;
    if (want === got) return true;
    return (MIME_ALIASES[want] || []).includes(got)
      || (MIME_ALIASES[got] || []).includes(want);
  }

  function domReady() {
    if (document.readyState !== 'loading') return Promise.resolve();
    return new Promise((resolve) => {
      document.addEventListener('DOMContentLoaded', resolve, { once: true });
    });
  }

  function send(message) {
    try {
      const result = runtime.sendMessage(message);
      if (result && typeof result.catch === 'function') result.catch(() => {});
    } catch {
      // The extension worker may be restarting; the next state poll will retry.
    }
  }

  // -------------------------------------------------------------------------
  // Banner
  // -------------------------------------------------------------------------

  function render(state) {
    if (!state || !state.status || state.status === 'idle') {
      removeBanner();
      return;
    }
    ensureHost();
    if (!shadow || !contentRoot) return;
    host.dataset.mode = state.status === 'unsafe' || state.status === 'unverified' ? 'bar' : 'pill';
    host.dataset.status = state.status;
    host.dataset.version = state.version || state.releaseVersion || '';
    if (hideTimer) {
      clearTimeout(hideTimer);
      hideTimer = null;
    }
    contentRoot.replaceChildren();

    const errors = (state.issues || []).filter((issue) => issue.severity === 'error');
    const warnings = (state.issues || []).filter((issue) => issue.severity === 'warning');
    const first = errors[0] || warnings[0];
    const progress = state.progress && state.progress.total
      ? ` · ${state.progress.done}/${state.progress.total} tệp`
      : '';

    if (state.status === 'verified') {
      const pill = element('div', 'pill ok');
      pill.append(
        element('span', 'icon', '✓'),
        element('span', 'pill-text', `MNG Cloud đã xác minh v${state.version || state.releaseVersion || ''}`),
      );
      if (state.source === 'cache') {
        pill.append(element('span', 'pill-note', 'cache đã ký'));
      }
      contentRoot.append(pill);
      hideTimer = setTimeout(removeBanner, 6000);
      return;
    }

    if (state.status === 'checking') {
      const pill = element('div', 'pill checking');
      pill.append(
        element('span', 'spinner'),
        element('span', 'pill-text', `Đang xác minh bản phát hành${progress}…`),
      );
      contentRoot.append(pill);
      return;
    }

    const unsafe = state.status === 'unsafe';
    const bar = element('div', `bar ${unsafe ? 'unsafe' : 'unverified'}`);
    const inner = element('div', 'inner');
    const icon = element('span', 'icon', unsafe ? '!' : '?');
    const text = element('div', 'text');
    const title = element(
      'strong',
      'title',
      unsafe ? 'MNG Cloud — KHÔNG AN TOÀN' : 'MNG Cloud — Chưa thể xác minh',
    );
    const detail = element(
      'span',
      'detail',
      first ? first.message : (unsafe ? 'Phát hiện sai lệch so với bản phát hành đã ký.' : 'Không có metadata đã ký.'),
    );
    text.append(title, detail);
    inner.append(icon, text);

    const all = [...errors, ...warnings];
    if (all.length > 0) {
      const toggle = element('button', 'details-toggle', 'Chi tiết');
      toggle.type = 'button';
      const panel = element('div', 'details');
      panel.hidden = true;
      const list = element('ul', 'issue-list');
      for (const issue of all.slice(0, 20)) {
        const item = element('li', issue.severity === 'error' ? 'issue error' : 'issue warning');
        item.textContent = issue.message;
        list.append(item);
      }
      panel.append(list);
      toggle.addEventListener('click', () => {
        panel.hidden = !panel.hidden;
        toggle.textContent = panel.hidden ? 'Chi tiết' : 'Ẩn';
      });
      inner.append(toggle);
      bar.append(inner, panel);
    } else {
      bar.append(inner);
    }
    contentRoot.append(bar);

    if (unsafe || state.status === 'unverified') {
      startGuard();
    }
  }

  function ensureHost() {
    if (host && host.isConnected && shadow) return;
    const root = document.documentElement;
    if (!root) return;
    if (!host) {
      host = document.createElement('div');
      host.id = 'mng-trust-host';
      host.setAttribute('data-mng-trust', 'banner');
      shadow = host.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = BANNER_CSS;
      shadow.append(style);
      try {
        sheet = new CSSStyleSheet();
        sheet.replaceSync(BANNER_CSS);
        shadow.adoptedStyleSheets = [sheet];
      } catch {
        // The style element remains as a fallback.
      }
      contentRoot = document.createElement('div');
      contentRoot.className = 'content';
      shadow.append(contentRoot);
    }
    root.append(host);
    if (!removalObserver) {
      removalObserver = new MutationObserver(() => {
        if (host && !host.isConnected && document.documentElement) {
          document.documentElement.append(host);
        }
      });
      removalObserver.observe(root, { childList: true });
    }
  }

  function startGuard() {
    if (guardTimer) return;
    guardTimer = setInterval(() => {
      if (lastState && lastState.status !== 'verified' && lastState.status !== 'checking') {
        ensureHost();
      }
    }, 3000);
  }

  function stopGuard() {
    if (guardTimer) {
      clearInterval(guardTimer);
      guardTimer = null;
    }
  }

  function removeBanner() {
    if (hideTimer) {
      clearTimeout(hideTimer);
      hideTimer = null;
    }
    stopGuard();
    if (host) {
      host.remove();
      host = null;
      shadow = null;
      contentRoot = null;
    }
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const BANNER_CSS = `
    :host {
      all: initial;
      position: fixed;
      z-index: 2147483647;
      inset: auto 16px 16px auto;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.35;
      color: #fff;
      pointer-events: none;
    }
    :host([data-mode="bar"]) {
      inset: 0 0 auto 0;
    }
    * { box-sizing: border-box; }
    .pill {
      display: flex;
      align-items: center;
      gap: 8px;
      max-width: min(520px, calc(100vw - 32px));
      padding: 9px 13px;
      border-radius: 999px;
      background: #0f7b3f;
      box-shadow: 0 8px 28px rgba(0,0,0,.32);
      pointer-events: auto;
    }
    .pill.checking { background: #1f2937; }
    .pill-note { opacity: .72; font-size: 11px; }
    .icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 20px;
      height: 20px;
      flex: 0 0 20px;
      border-radius: 50%;
      background: rgba(255,255,255,.2);
      font-weight: 700;
    }
    .spinner {
      width: 14px;
      height: 14px;
      flex: 0 0 14px;
      border: 2px solid rgba(255,255,255,.35);
      border-top-color: #fff;
      border-radius: 50%;
      animation: mng-spin .8s linear infinite;
    }
    @keyframes mng-spin { to { transform: rotate(360deg); } }
    .bar {
      width: 100%;
      padding: 10px 16px 10px;
      pointer-events: auto;
      box-shadow: 0 8px 24px rgba(0,0,0,.28);
      background: #8a5a00;
    }
    .bar.unsafe { background: #b42318; }
    .bar .inner {
      display: flex;
      align-items: center;
      gap: 10px;
      max-width: 1200px;
      margin: 0 auto;
    }
    .bar .text {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
      flex: 1;
    }
    .bar .title { font-size: 13px; letter-spacing: .01em; }
    .bar .detail {
      opacity: .92;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .details-toggle {
      flex: 0 0 auto;
      padding: 5px 10px;
      border: 1px solid rgba(255,255,255,.45);
      border-radius: 6px;
      background: transparent;
      color: #fff;
      font: inherit;
      cursor: pointer;
    }
    .details-toggle:hover { background: rgba(255,255,255,.12); }
    .details {
      max-width: 1200px;
      margin: 8px auto 0;
      padding: 8px 12px;
      border-top: 1px solid rgba(255,255,255,.25);
    }
    .issue-list { margin: 0; padding-left: 18px; }
    .issue { margin: 4px 0; }
    .issue.warning { opacity: .9; }
    .pill-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  `;
})();
