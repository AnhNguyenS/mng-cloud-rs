import { trustedScriptUrl } from './trusted-types.js';

const statusEl = document.getElementById('status');
const statusDot = document.getElementById('status-dot');
const versionEl = document.getElementById('version');
const shellVersionEl = document.getElementById('shell-version');
const workerStateEl = document.getElementById('worker-state');
const networkStateEl = document.getElementById('network-state');
const updateBanner = document.getElementById('update-banner');
const updateVersion = document.getElementById('update-version');
const updateButton = document.getElementById('update-button');

const shellVersion =
  document.querySelector('meta[name="mng-version"]')?.getAttribute('content') || 'dev';

versionEl.textContent = shellVersion;
shellVersionEl.textContent = shellVersion;

let refreshing = false;

function setStatus(text, tone) {
  statusEl.textContent = text;
  statusDot.classList.remove('ok', 'bad');
  if (tone) statusDot.classList.add(tone);
}

function setWorkerState(text) {
  workerStateEl.textContent = text;
}

function setNetworkState() {
  networkStateEl.textContent = navigator.onLine ? 'online' : 'offline';
}

async function health() {
  const response = await fetch('/api/v1/health', {
    headers: { accept: 'application/json' },
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function showUpdate(version) {
  const label =
    version && version !== shellVersion
      ? `Phiên bản ${version} đã sẵn sàng.`
      : 'Bản cập nhật đã ký đã sẵn sàng.';
  updateVersion.textContent = label;
  updateBanner.hidden = false;
}

function activateUpdate(registration) {
  if (refreshing) return;
  refreshing = true;
  updateButton.disabled = true;
  updateButton.textContent = 'Đang cập nhật…';

  const worker = registration.waiting || registration.active;
  if (worker) worker.postMessage({ type: 'mng-skip-waiting' });
  else window.location.reload();
}

async function registerWorker() {
  if (!('serviceWorker' in navigator)) {
    setWorkerState('không hỗ trợ');
    return null;
  }
  if (!window.isSecureContext) {
    setWorkerState('cần HTTPS');
    return null;
  }

  try {
    const registration = await navigator.serviceWorker.register(
      trustedScriptUrl('/app/sw.js'),
      {
        scope: '/app/',
        updateViaCache: 'none',
      },
    );

    setWorkerState(registration.active ? 'đã kích hoạt' : 'đang cài đặt');

    registration.addEventListener('updatefound', () => {
      const worker = registration.installing;
      if (!worker) return;
      setWorkerState('đang cập nhật');
      worker.addEventListener('statechange', () => {
        if (worker.state === 'redundant') {
          setWorkerState('lỗi xác minh');
          console.error('service worker became redundant; signed release was rejected');
        }
        if (worker.state === 'installed' && navigator.serviceWorker.controller) {
          setWorkerState('bản mới đã sẵn sàng');
          showUpdate('');
        }
        if (worker.state === 'activated') setWorkerState('đã kích hoạt');
      });
    });

    navigator.serviceWorker.addEventListener('message', (event) => {
      const data = event.data || {};
      if (data.type === 'mng-install-error') {
        setWorkerState('lỗi xác minh');
        console.error('service worker install rejected:', data.message);
      }
      if (data.type === 'mng-update-status' && data.status === 'available') {
        showUpdate(data.version || 'mới');
        registration.update().catch(() => {});
      }
    });

    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!refreshing) return;
      window.location.reload();
    });

    updateButton.addEventListener('click', () => activateUpdate(registration));

    const check = () => {
      registration.update().catch(() => {});
      navigator.serviceWorker.controller?.postMessage({ type: 'mng-check-update' });
    };
    window.setTimeout(check, 3000);
    window.setInterval(check, 6 * 60 * 60 * 1000);
    return registration;
  } catch (error) {
    setWorkerState('lỗi cài đặt');
    console.error('service worker registration failed', error);
    return null;
  }
}

async function boot() {
  setNetworkState();
  window.addEventListener('online', setNetworkState);
  window.addEventListener('offline', setNetworkState);

  try {
    const data = await health();
    setStatus(`Hoạt động · ${data.service} ${data.version}`, 'ok');
  } catch (error) {
    setStatus('Không kết nối được dịch vụ. Kiểm tra nginx hoặc mngd.', 'bad');
    console.error('health check failed', error);
  }

  await registerWorker();
}

boot();
