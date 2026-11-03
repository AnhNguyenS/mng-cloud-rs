#!/usr/bin/env node
/*
 * End-to-end checks for the MNG Cloud Trusted extension.
 *
 * This is a local/manual test: it needs the signed app served by mngd and a
 * bundled Chromium from Playwright. It starts its own CORS release server so
 * GitHub's headers do not need to be simulated.
 *
 * Setup:
 *   cd tools/e2e && npm install
 *   npx playwright install chromium
 *
 * Run (from the repository root, with mngd serving dist/app on :8090):
 *   node tools/e2e/extension-e2e.mjs
 *
 * Environment overrides:
 *   MNG_E2E_EXTENSION  built extension directory (default dist/extension)
 *   MNG_E2E_APP        signed app directory (default dist/app)
 *   MNG_E2E_RELEASE    signed release directory (default dist/release)
 *   MNG_E2E_ORIGIN     app origin (default http://127.0.0.1:8090)
 *   MNG_E2E_PORT       release server port (default 8092)
 */

import { chromium } from 'playwright-core';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const EXTENSION = path.resolve(process.env.MNG_E2E_EXTENSION || path.join(ROOT, 'dist', 'extension'));
const APP = path.resolve(process.env.MNG_E2E_APP || path.join(ROOT, 'dist', 'app'));
const RELEASE = path.resolve(process.env.MNG_E2E_RELEASE || path.join(ROOT, 'dist', 'release'));
const ORIGIN = process.env.MNG_E2E_ORIGIN || 'http://127.0.0.1:8090';
const PORT = Number(process.env.MNG_E2E_PORT || 8092);

const RELEASE_FILES = new Set(['release.json', 'release.sig', 'manifest.json', 'manifest.sig']);
let failures = 0;

function check(condition, label, detail = '') {
  if (condition) {
    console.log(`ok   ${label}`);
  } else {
    failures += 1;
    console.error(`FAIL ${label}${detail ? `: ${detail}` : ''}`);
  }
}

function requireFile(file) {
  if (!fs.existsSync(file)) {
    throw new Error(`missing ${file}; build and sign the extension first`);
  }
}

function startReleaseServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      const name = String(request.url || '/').split('?')[0].replace(/^\//, '');
      if (!RELEASE_FILES.has(name)) {
        response.writeHead(404, { 'Content-Type': 'text/plain' });
        response.end('not found');
        return;
      }
      try {
        const bytes = fs.readFileSync(path.join(RELEASE, name));
        response.writeHead(200, {
          'Content-Type': name.endsWith('.json') ? 'application/json' : 'text/plain',
          'Content-Length': bytes.length,
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        });
        response.end(bytes);
      } catch (error) {
        response.writeHead(500, { 'Content-Type': 'text/plain' });
        response.end(String(error));
      }
    });
    server.once('error', reject);
    server.listen(PORT, '127.0.0.1', () => resolve(server));
  });
}

async function state(sw, page) {
  const worker = await sw.evaluate(async (origin) => {
    const tabs = await chrome.tabs.query({ url: `${origin}/*` });
    const tabId = tabs[0] && tabs[0].id;
    return {
      tabId,
      badge: tabId ? await chrome.action.getBadgeText({ tabId }) : null,
      title: tabId ? await chrome.action.getTitle({ tabId }) : null,
    };
  }, ORIGIN);
  const banner = await page.evaluate(() => {
    const host = document.getElementById('mng-trust-host');
    return host
      ? { status: host.dataset.status, mode: host.dataset.mode, version: host.dataset.version }
      : null;
  });
  return { ...worker, banner };
}

async function main() {
  requireFile(path.join(EXTENSION, 'manifest.json'));
  requireFile(path.join(APP, 'manifest.json'));
  requireFile(path.join(RELEASE, 'release.json'));
  const release = JSON.parse(fs.readFileSync(path.join(RELEASE, 'release.json'), 'utf8'));
  const expectedVersion = release.version;
  const assetFile = path.join(APP, 'assets', 'app.css');
  const originalAsset = fs.readFileSync(assetFile);

  const server = await startReleaseServer();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'mng-e2e-profile-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      headless: false,
      args: [
        `--disable-extensions-except=${EXTENSION}`,
        `--load-extension=${EXTENSION}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
      timeout: 60000,
    });
    let sw = context.serviceWorkers()[0];
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 30000 });

    const page = await context.newPage();
    await page.goto(`${ORIGIN}/app/`, { waitUntil: 'load' });
    await page.waitForTimeout(5000);

    const verified = await state(sw, page);
    check(verified.badge === '✓', 'initial load is verified', JSON.stringify(verified));
    check(verified.banner?.status === 'verified', 'banner reports verified');
    check(verified.banner?.version === expectedVersion, `banner reports ${expectedVersion}`, verified.banner?.version);

    await page.evaluate(() => {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/app/assets/unlisted.css?v=1';
      document.head.append(link);
    });
    await page.waitForTimeout(3000);
    const unlisted = await state(sw, page);
    check(unlisted.badge === '!', 'unlisted stylesheet flips the badge', JSON.stringify(unlisted));
    check(unlisted.banner?.status === 'unsafe', 'unlisted stylesheet shows the red banner');

    fs.writeFileSync(assetFile, Buffer.concat([originalAsset, Buffer.from('\n/* e2e tamper */\n')]));
    await page.reload({ waitUntil: 'load' });
    await page.waitForTimeout(6000);
    const tampered = await state(sw, page);
    check(tampered.badge === '!', 'tampered asset flips the badge', JSON.stringify(tampered));
    check(tampered.banner?.status === 'unsafe', 'tampered asset shows the red banner');

    fs.writeFileSync(assetFile, originalAsset);
    await page.reload({ waitUntil: 'load' });
    await page.waitForTimeout(6000);
    const restored = await state(sw, page);
    check(restored.badge === '✓', 'restored asset verifies again', JSON.stringify(restored));
  } finally {
    fs.writeFileSync(assetFile, originalAsset);
    if (context) await context.close();
    fs.rmSync(profile, { recursive: true, force: true });
    server.close();
  }

  if (failures > 0) {
    console.error(`\n${failures} check(s) failed`);
    process.exitCode = 1;
  } else {
    console.log('\nall extension E2E checks passed');
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
