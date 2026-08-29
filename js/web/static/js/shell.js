/* JS Agent — App Shell controller.
   Rail, more menu, command palette (⌘K), theme toggle, session column
   collapse, work-context panel collapse, product-mode layout, model hint.
   All mode/identity state comes from the server-driven store; only the
   theme preference is stored locally. */

import { state } from '../state/store.js';
import { iconSvg } from './icons.js';
import { toggleTheme, initThemeListener } from './theme.js';

/* Full tab registry: id → { label, icon }. Every existing tab keeps its
   route; only the discovery surface changes (rail / more menu / ⌘K). */
export const TAB_REGISTRY = [
  { id: 'chat', label: '对话', icon: 'message-circle' },
  { id: 'bots', label: 'Bots', icon: 'users' },
  { id: 'memory', label: '记忆', icon: 'brain' },
  { id: 'files', label: '文件', icon: 'folder' },
  { id: 'tasks', label: '任务', icon: 'list-checks' },
  { id: 'friends', label: 'Friends', icon: 'users' },
  { id: 'models', label: '模型', icon: 'cpu' },
  { id: 'agents', label: '多Agent', icon: 'users' },
  { id: 'scenarios', label: '场景模板', icon: 'layout-template' },
  { id: 'evolution', label: '进化', icon: 'dna' },
  { id: 'skills', label: 'Skills', icon: 'puzzle' },
  { id: 'search', label: '搜索', icon: 'search' },
  { id: 'dashboard', label: '仪表盘', icon: 'layout-dashboard' },
  { id: 'audit', label: '审计', icon: 'scroll-text' },
  { id: 'approvals', label: '审批', icon: 'shield-check' },
  { id: 'stats', label: '用量统计', icon: 'chart-column' },
  { id: 'status', label: '状态', icon: 'activity' },
  { id: 'cron', label: '定时任务', icon: 'clock' },
];

const RAIL_PRIMARY = ['chat', 'memory', 'files', 'tasks'];

function tabLabel(id) {
  const entry = TAB_REGISTRY.find((t) => t.id === id);
  return entry ? entry.label : id;
}

function tabIcon(id) {
  const entry = TAB_REGISTRY.find((t) => t.id === id);
  return entry ? entry.icon : 'box';
}

/** Replace <span data-icon="name"> placeholders with inline SVG. */
export function hydrateIcons(root) {
  (root || document).querySelectorAll('[data-icon]').forEach((slot) => {
    const name = slot.getAttribute('data-icon');
    const svg = iconSvg(name, slot.getAttribute('data-icon-class') || '');
    if (svg) {
      slot.outerHTML = svg;
    }
  });
}

function enabledTabs() {
  const caps = state.capabilities;
  if (caps && Array.isArray(caps.enabled_tabs) && caps.enabled_tabs.length) {
    return caps.enabled_tabs;
  }
  return TAB_REGISTRY.map((t) => t.id);
}

const SWITCH_HANDOFF_KEY = 'js:switching-to';
const SWITCH_HANDOFF_TIMEOUT_MS = 4000;

export function peekSwitchHandoffProduct() {
  try {
    const product = window.sessionStorage.getItem(SWITCH_HANDOFF_KEY);
    if (product === 'js-work' || product === 'js-agent') return product;
  } catch (e) { /* storage unavailable */ }
  return null;
}

export function writeSwitchHandoff(product) {
  if (product !== 'js-work' && product !== 'js-agent') return;
  try { window.sessionStorage.setItem(SWITCH_HANDOFF_KEY, product); } catch (e) { /* ignore */ }
}

export function clearSwitchHandoff() {
  try { window.sessionStorage.removeItem(SWITCH_HANDOFF_KEY); } catch (e) { /* ignore */ }
  document.documentElement.removeAttribute('data-switch-handoff');
}

export function showModeSwitchOverlay(toLabel) {
  const overlay = document.getElementById('mode-switch-overlay');
  const text = document.getElementById('mode-switch-overlay-text');
  if (text) text.textContent = toLabel ? `正在切换到 ${toLabel} 模式…` : '正在切换模式…';
  if (!overlay) return;
  overlay.classList.remove('mode-switch-overlay-fade');
  overlay.hidden = false;
}

export function hideModeSwitchOverlay({ immediate = false } = {}) {
  const overlay = document.getElementById('mode-switch-overlay');
  if (!overlay) return;
  const finish = () => {
    overlay.hidden = true;
    overlay.classList.remove('mode-switch-overlay-fade');
  };
  if (overlay.hidden && !document.documentElement.hasAttribute('data-switch-handoff')) {
    return;
  }
  if (immediate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    finish();
    return;
  }
  overlay.classList.add('mode-switch-overlay-fade');
  window.setTimeout(finish, 180);
}

export function finishSwitchHandoff() {
  hideModeSwitchOverlay();
  clearSwitchHandoff();
}

function applyEarlySwitchHandoff() {
  const product = peekSwitchHandoffProduct();
  if (!product) return;
  const label = product === 'js-work' ? 'Work' : 'Personal';
  showModeSwitchOverlay(label);
  applyProductMode(product);
  const personalBtn = document.getElementById('product-personal-btn');
  const workBtn = document.getElementById('product-work-btn');
  if (personalBtn) personalBtn.classList.toggle('seg-active', product === 'js-agent');
  if (workBtn) {
    workBtn.hidden = false;
    workBtn.setAttribute('aria-hidden', 'false');
    workBtn.classList.toggle('seg-active', product === 'js-work');
  }
  window.setTimeout(() => {
    if (peekSwitchHandoffProduct()) finishSwitchHandoff();
  }, SWITCH_HANDOFF_TIMEOUT_MS);
}

/* ── Product mode layout ─────────────────────────────────── */
export function applyProductMode(product) {
  const isWork = product === 'js-work';
  document.body.dataset.product = product || 'js-agent';
  const botsBtn = document.getElementById('product-bots-btn');
  if (botsBtn) {
    botsBtn.hidden = isWork;
    botsBtn.setAttribute('aria-hidden', isWork ? 'true' : 'false');
  }
  if (isWork) {
    delete document.body.dataset.surface;
    const botsBand = document.getElementById('bots-context-band');
    if (botsBand) botsBand.hidden = true;
  }
  const band = document.getElementById('work-context-band');
  const panel = document.getElementById('work-context-panel');
  const wsLabel = document.getElementById('workspace-label');
  const wsChip = document.getElementById('chat-workspace-chip');
  if (band) band.hidden = !isWork;
  if (wsLabel) wsLabel.hidden = !isWork;
  if (wsChip) wsChip.hidden = !isWork;
  const handle = document.getElementById('wcp-expand-handle');
  if (panel) {
    if (!isWork) {
      panel.hidden = true;
      if (handle) handle.hidden = true;
      document.getElementById('app-shell')?.classList.remove('context-collapsed');
    } else {
      const collapsed = sessionStorageSafeGet('js-wcp-collapsed') === '1';
      setContextCollapsed(collapsed);
    }
  }
  // Workspace label text (display-only; comes from server capabilities).
  const wsName = document.getElementById('workspace-name');
  const caps = state.appShellCapabilities;
  const handleName = caps && caps.workspace_handles ? caps.workspace_handles.work : null;
  if (wsName) {
    const full = handleName || '工作区';
    wsName.textContent = full.length > 14 ? `${full.slice(0, 11)}…` : full;
    wsName.title = full;
  }
  const wsChipName = document.getElementById('chat-workspace-name');
  if (wsChipName) {
    const full = handleName || '工作区';
    wsChipName.textContent = full.length > 14 ? `${full.slice(0, 11)}…` : full;
  }
  document.dispatchEvent(new CustomEvent('js:product-mode-applied'));
}

function sessionStorageSafeGet(key) {
  try {
    return window.sessionStorage.getItem(key);
  } catch (e) {
    return null;
  }
}

function sessionStorageSafeSet(key, value) {
  try {
    window.sessionStorage.setItem(key, value);
  } catch (e) { /* ignore */ }
}

export function setContextCollapsed(collapsed) {
  const panel = document.getElementById('work-context-panel');
  const handle = document.getElementById('wcp-expand-handle');
  const shell = document.getElementById('app-shell');
  if (!panel || document.body.dataset.product !== 'js-work') return;
  panel.hidden = collapsed;
  if (handle) handle.hidden = !collapsed;
  shell?.classList.toggle('context-collapsed', collapsed);
  sessionStorageSafeSet('js-wcp-collapsed', collapsed ? '1' : '0');
}

export function toggleSessionColumn() {
  document.getElementById('app-shell')?.classList.toggle('session-collapsed');
}

/* ── More menu ───────────────────────────────────────────── */
function buildMoreMenu() {
  const menu = document.getElementById('more-menu');
  if (!menu) return;
  menu.replaceChildren();
  const enabled = new Set(enabledTabs());
  for (const entry of TAB_REGISTRY) {
    if (RAIL_PRIMARY.includes(entry.id)) continue;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.id = `nav-${entry.id}`;
    btn.innerHTML = `${iconSvg(entry.icon)}<span>${entry.label}</span>`;
    if (entry.id === 'approvals') {
      const badge = document.createElement('span');
      badge.id = 'approvals-pending-count';
      badge.className = 'more-badge';
      badge.setAttribute('aria-label', '待审批数量');
      badge.hidden = true;
      btn.appendChild(badge);
    }
    if (!enabled.has(entry.id)) {
      btn.classList.add('hidden');
      btn.setAttribute('aria-disabled', 'true');
    }
    btn.addEventListener('click', () => {
      closeMoreMenu();
      window.switchTab(entry.id);
    });
    menu.appendChild(btn);
  }
}

function openMoreMenu() {
  const menu = document.getElementById('more-menu');
  if (!menu) return;
  menu.hidden = false;
}

function closeMoreMenu() {
  const menu = document.getElementById('more-menu');
  if (menu) menu.hidden = true;
}

/* ── Command palette ─────────────────────────────────────── */
let paletteIndex = 0;
let paletteItems = [];

function paletteEntries(query) {
  const enabled = new Set(enabledTabs());
  const q = (query || '').trim().toLowerCase();
  return TAB_REGISTRY.filter((entry) => {
    if (!enabled.has(entry.id) && entry.id !== 'chat') return false;
    if (!q) return true;
    return (
      entry.label.toLowerCase().includes(q) || entry.id.toLowerCase().includes(q)
    );
  });
}

function renderPaletteList() {
  const list = document.getElementById('command-palette-list');
  if (!list) return;
  list.replaceChildren();
  if (!paletteItems.length) {
    const empty = document.createElement('div');
    empty.className = 'palette-empty';
    empty.textContent = '没有匹配的功能';
    list.appendChild(empty);
    return;
  }
  paletteItems.forEach((entry, idx) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'palette-item' + (idx === paletteIndex ? ' palette-selected' : '');
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', idx === paletteIndex ? 'true' : 'false');
    item.innerHTML = `${iconSvg(entry.icon)}<span>${entry.label}</span>`;
    const hint = document.createElement('span');
    hint.className = 'palette-hint';
    hint.textContent = entry.id;
    item.appendChild(hint);
    item.addEventListener('click', () => {
      closePalette();
      window.switchTab(entry.id);
    });
    list.appendChild(item);
  });
}

export function openPalette() {
  const palette = document.getElementById('command-palette');
  const input = document.getElementById('command-palette-input');
  if (!palette || !input) return;
  const wizard = document.getElementById('setup-wizard');
  const bootstrapFailure = document.getElementById('bootstrap-failure');
  if ((wizard && !wizard.classList.contains('hidden'))
      || (bootstrapFailure && !bootstrapFailure.classList.contains('hidden'))) {
    closePalette();
    return;
  }
  palette.hidden = false;
  input.value = '';
  paletteItems = paletteEntries('');
  paletteIndex = 0;
  renderPaletteList();
  input.focus();
}

export function closePalette() {
  const palette = document.getElementById('command-palette');
  if (palette) palette.hidden = true;
}

function paletteKeydown(e) {
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    paletteIndex = Math.min(paletteIndex + 1, paletteItems.length - 1);
    renderPaletteList();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    paletteIndex = Math.max(paletteIndex - 1, 0);
    renderPaletteList();
  } else if (e.key === 'Enter') {
    e.preventDefault();
    const entry = paletteItems[paletteIndex];
    if (entry) {
      closePalette();
      window.switchTab(entry.id);
    }
  } else if (e.key === 'Escape') {
    e.preventDefault();
    closePalette();
  }
}

/* ── Settings popover ────────────────────────────────────── */
function toggleSettingsPopover() {
  const pop = document.getElementById('settings-popover');
  if (pop) pop.hidden = !pop.hidden;
}

function closeSettingsPopover() {
  const pop = document.getElementById('settings-popover');
  if (pop) pop.hidden = true;
}

/* ── Model hint (persistent, non-blocking) ───────────────── */
function configuredModels() {
  const models = Array.isArray(state.availableModels) ? state.availableModels : [];
  return models.filter((model) => model && !model.isPreset);
}

export function refreshChatEmptyState() {
  const empty = document.getElementById('chat-empty-state');
  const container = document.getElementById('chat-messages');
  if (!empty || !container) return;

  const hasSnapshot = state.modelCatalogHasSnapshot === true;
  const hasConfigured = configuredModels().length > 0;
  const hasConversationContent = Array.from(container.children).some(
    (child) => child !== empty && !child.classList.contains('chat-empty-decoration'),
  );
  const title = empty.querySelector('[data-empty-title]');
  const description = empty.querySelector('[data-empty-description]');
  const action = empty.querySelector('[data-empty-action]');

  if (!hasSnapshot && state.modelCatalogStatus === 'loading') {
    if (title) title.textContent = '正在读取模型配置';
    if (description) description.textContent = '加载完成前不会发送或清空你的内容。';
    if (action) {
      action.textContent = '正在加载…';
      action.disabled = true;
    }
  } else if (!hasSnapshot && state.modelCatalogStatus === 'error') {
    if (title) title.textContent = '模型列表暂时无法加载';
    if (description) description.textContent = '你的输入会保留，可以安全重试。';
    if (action) {
      action.textContent = '重新加载模型';
      action.disabled = false;
    }
  } else {
    if (title) title.textContent = '先配置一个模型';
    if (description) description.textContent = '添加模型后即可开始对话，现有草稿与附件会保留。';
    if (action) {
      action.textContent = '配置模型';
      action.disabled = false;
    }
  }

  empty.hidden = hasConfigured || hasConversationContent;
}

export function refreshModelHint() {
  const models = configuredModels();
  const hint = document.getElementById('model-hint');
  if (hint) {
    const hasConfigured = models.length > 0;
    hint.hidden = hasConfigured;
    if (!state.modelCatalogHasSnapshot && state.modelCatalogStatus === 'loading') {
      hint.textContent = '正在加载模型…';
      hint.disabled = true;
    } else if (!state.modelCatalogHasSnapshot && state.modelCatalogStatus === 'error') {
      hint.textContent = '模型加载失败 · 查看设置';
      hint.disabled = false;
    } else {
      hint.textContent = '尚未配置模型 · 现在设置';
      hint.disabled = false;
    }
  }
  const nameEl = document.getElementById('chat-model-name');
  if (nameEl) {
    const active = state.selectedModel;
    const model = models.find((item) => item.id === active && !item.isPreset);
    nameEl.textContent = model
      ? String(model.name || model.id).split('/').pop()
      : '未配置模型';
  }
  refreshChatEmptyState();
}

/* ── Streaming state (stop button) ───────────────────────── */
export function setStreaming(active) {
  const stop = document.getElementById('chat-stop-button');
  const send = document.getElementById('chat-send-button');
  const log = document.getElementById('chat-messages');
  const liveStatus = document.getElementById('chat-live-status');
  const wasStreaming = state.isStreaming === true;
  state.isStreaming = !!active;
  if (stop) stop.classList.toggle('streaming', !!active);
  if (send) send.style.display = active ? 'none' : '';
  if (log) {
    log.setAttribute('aria-busy', active ? 'true' : 'false');
    // Token-by-token changes must not flood screen-reader users. The separate
    // status node announces one start and one terminal transition instead.
    log.setAttribute('aria-live', active ? 'off' : 'polite');
  }
  if (liveStatus) {
    if (active && !wasStreaming) {
      liveStatus.textContent = 'JS Agent 正在回复';
    } else if (!active && wasStreaming) {
      queueMicrotask(() => { liveStatus.textContent = 'JS Agent 回复完成'; });
    }
  }
}

/* ── Theme toggle icon ───────────────────────────────────── */
function refreshThemeToggleIcon() {
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  const theme = document.documentElement.getAttribute('data-theme');
  toggle.innerHTML = iconSvg(theme === 'dark' ? 'sun' : 'moon');
  toggle.setAttribute('aria-label', theme === 'dark' ? '切换到浅色主题' : '切换到深色主题');
}

/* ── Approval badge → rail notify dot ────────────────────── */
function watchApprovalBadge() {
  const syncDot = () => {
    const badge = document.getElementById('approvals-pending-count');
    const dot = document.getElementById('task-notify-dot');
    if (!badge || !dot) return;
    const count = parseInt(badge.textContent || '0', 10);
    dot.hidden = !(count > 0);
  };
  const menu = document.getElementById('more-menu');
  if (menu) {
    new MutationObserver(syncDot).observe(menu, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    });
  }
  syncDot();
}

/* ── Init ────────────────────────────────────────────────── */
export function initShell() {
  const shell = document.getElementById('app-shell');
  if (!shell) return;

  hydrateIcons(document);

  buildMoreMenu();

  // Rail wiring
  document.querySelectorAll('#nav-rail button.rail-item').forEach((btn) => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      if (tab === '__more__') {
        const menu = document.getElementById('more-menu');
        if (menu) menu.hidden ? openMoreMenu() : closeMoreMenu();
      } else if (tab === '__settings__') {
        toggleSettingsPopover();
      } else if (tab) {
        window.switchTab(tab);
      }
    });
  });

  // Outside click closes popovers
  document.addEventListener('click', (e) => {
    const target = e.target;
    if (!(target instanceof Element)) return;
    if (!target.closest('#more-menu') && !target.closest("[data-tab='__more__']")) {
      closeMoreMenu();
    }
    if (
      !target.closest('#settings-popover') &&
      !target.closest('#user-entry') &&
      !target.closest("[data-tab='__settings__']")
    ) {
      closeSettingsPopover();
    }
  });

  // ⌘K / Ctrl+K
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      const palette = document.getElementById('command-palette');
      if (palette && !palette.hidden) {
        closePalette();
      } else {
        openPalette();
      }
    } else if (e.key === 'Escape') {
      closePalette();
      closeMoreMenu();
      closeSettingsPopover();
    }
  });

  const cmdkBtn = document.getElementById('cmdk-button');
  if (cmdkBtn) cmdkBtn.addEventListener('click', openPalette);

  const paletteInput = document.getElementById('command-palette-input');
  if (paletteInput) {
    paletteInput.addEventListener('input', () => {
      paletteItems = paletteEntries(paletteInput.value);
      paletteIndex = 0;
      renderPaletteList();
    });
    paletteInput.addEventListener('keydown', paletteKeydown);
  }
  const palette = document.getElementById('command-palette');
  if (palette) {
    palette.addEventListener('click', (e) => {
      if (e.target === palette) closePalette();
    });
  }

  // Theme
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      toggleTheme();
      refreshThemeToggleIcon();
    });
  }
  refreshThemeToggleIcon();
  initThemeListener(refreshThemeToggleIcon);

  // Session column / context panel
  const colToggle = document.getElementById('btn-toggle-session-column');
  if (colToggle) colToggle.addEventListener('click', toggleSessionColumn);
  const wcpCollapse = document.getElementById('wcp-collapse');
  if (wcpCollapse) wcpCollapse.addEventListener('click', () => setContextCollapsed(true));
  const wcpExpand = document.getElementById('wcp-expand-handle');
  if (wcpExpand) wcpExpand.addEventListener('click', () => setContextCollapsed(false));

  // Settings popover
  const userEntry = document.getElementById('user-entry');
  if (userEntry) userEntry.addEventListener('click', toggleSettingsPopover);

  // Model hint
  refreshModelHint();
  document.addEventListener('js:models-updated', refreshModelHint);
  document.addEventListener('js:model-catalog-state', refreshModelHint);
  document.addEventListener('js:chat-content-changed', refreshChatEmptyState);
  const emptyAction = document.querySelector('#chat-empty-state [data-empty-action]');
  if (emptyAction) {
    emptyAction.addEventListener('click', () => {
      if (!state.modelCatalogHasSnapshot && state.modelCatalogStatus === 'error') {
        window.loadModels?.();
      } else {
        window.switchTab?.('models');
      }
    });
  }

  // Session search filter
  const sessionSearch = document.getElementById('session-search');
  if (sessionSearch) {
    sessionSearch.addEventListener('input', () => {
      const q = sessionSearch.value.trim().toLowerCase();
      document.querySelectorAll('#session-list .session-item').forEach((item) => {
        const text = (item.textContent || '').toLowerCase();
        item.style.display = !q || text.includes(q) ? '' : 'none';
      });
      document.querySelectorAll('#session-list .session-group-label').forEach((label) => {
        let node = label.nextElementSibling;
        let visible = 0;
        while (node && !node.classList.contains('session-group-label')) {
          if (node.classList.contains('session-item') && node.style.display !== 'none') visible += 1;
          node = node.nextElementSibling;
        }
        label.style.display = visible ? '' : 'none';
      });
    });
  }

  watchApprovalBadge();

  // Default: collapse session column on narrow screens
  if (window.matchMedia('(max-width: 1100px)').matches) {
    shell.classList.add('session-collapsed');
  }

  window.__shellReady = true;
}

applyEarlySwitchHandoff();

export { tabLabel, tabIcon };
