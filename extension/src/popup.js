import { CONFIG } from './config.js';

const ext = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

const STATUS = {
  checking: { icon: '…', title: 'Đang xác minh', className: 'checking' },
  verified: { icon: '✓', title: 'Đã xác minh', className: 'verified' },
  unsafe: { icon: '!', title: 'KHÔNG AN TOÀN', className: 'unsafe' },
  unverified: { icon: '?', title: 'Chưa thể xác minh', className: 'unverified' },
};

let activeTab = null;
let current = null;

void init();

async function init() {
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || null;
  $('release-link').href = new URL('release.json', CONFIG.releaseBase).href;
  $('recheck').addEventListener('click', () => void recheck());
  if (!activeTab || !activeTab.id || !activeTab.url) {
    showInactive('Không đọc được tab đang mở.');
    return;
  }
  const response = await send({
    type: 'mng-trust-get',
    tabId: activeTab.id,
    url: activeTab.url,
  });
  if (!response || !response.state) {
    showInactive('Trang này không thuộc cấu hình MNG Cloud Trusted.');
    return;
  }
  render(response.state);
}

async function recheck() {
  if (!activeTab || !activeTab.id || !activeTab.url) return;
  $('recheck').disabled = true;
  $('recheck').textContent = 'Đang kiểm tra…';
  await send({
    type: 'mng-trust-recheck',
    tabId: activeTab.id,
    url: activeTab.url,
  });
  setTimeout(() => {
    void refresh();
    $('recheck').disabled = false;
    $('recheck').textContent = 'Kiểm tra lại';
  }, 800);
}

async function refresh() {
  if (!activeTab || !activeTab.id || !activeTab.url) return;
  const response = await send({
    type: 'mng-trust-get',
    tabId: activeTab.id,
    url: activeTab.url,
  });
  if (response && response.state) render(response.state);
}

function render(state) {
  current = state;
  const meta = STATUS[state.status] || STATUS.checking;
  const card = $('status-card');
  card.className = `status ${meta.className}`;
  $('status-icon').textContent = meta.icon;
  $('status-title').textContent = meta.title;
  $('release-version').textContent = state.version || state.releaseVersion || '—';
  $('page-version').textContent = state.pageVersion || '—';
  $('source').textContent = sourceLabel(state.source);
  $('sequence').textContent = state.sequence == null ? '—' : String(state.sequence);

  const issues = state.issues || [];
  const first = issues.find((issue) => issue.severity === 'error') || issues[0];
  let detail = 'Đang đối chiếu với release đã ký trên GitHub…';
  if (state.status === 'verified') {
    detail = 'Toàn bộ asset đã ký khớp với nội dung máy chủ trả về.';
    if (state.source === 'cache') {
      detail += ' Đang dùng metadata đã xác minh lưu trong extension.';
    }
  } else if (state.status === 'unsafe') {
    detail = first ? first.message : 'Phát hiện sai lệch so với bản phát hành đã ký.';
  } else if (state.status === 'unverified') {
    detail = first ? first.message : 'Không lấy được metadata đã ký.';
  } else if (state.progress && state.progress.total) {
    detail = `Đang kiểm tra ${state.progress.done}/${state.progress.total} tệp…`;
  }
  $('status-detail').textContent = detail;

  const section = $('issues-section');
  const list = $('issues');
  list.replaceChildren();
  if (issues.length === 0) {
    section.hidden = true;
  } else {
    section.hidden = false;
    for (const issue of issues) {
      const item = document.createElement('li');
      item.className = issue.severity === 'warning' ? 'warning' : 'error';
      item.textContent = issue.message;
      list.append(item);
    }
  }
  $('inactive').hidden = true;
  card.hidden = false;
}

function showInactive(message) {
  $('inactive').hidden = false;
  $('inactive').querySelector('p').textContent = message;
  $('status-card').hidden = true;
  $('issues-section').hidden = true;
  $('subtitle').textContent = 'Không áp dụng';
  $('recheck').disabled = true;
}

function sourceLabel(source) {
  if (source === 'github') return 'GitHub (đã ký)';
  if (source === 'cache') return 'Cache đã xác minh';
  return '—';
}

function send(message) {
  return ext.runtime.sendMessage(message).catch(() => null);
}
