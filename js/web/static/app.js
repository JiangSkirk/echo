import { state } from './state/store.js';
import { escapeHtml, showToast, toggleSidebar, showLoading, showError, el, onDataClick, onDataChange, bindDataClicks, sanitizeRuntimeId } from './utils/dom.js';
import { renderMarkdown } from './utils/markdown.js';
import { loadStats } from './tabs/stats.js';
import { loadSearch, doSearch } from './tabs/search.js';
import { loadDashboard } from './tabs/dashboard.js';
import { loadEvolution, runEvolutionNow, decideEvolutionProposal } from './tabs/evolution.js';
import { loadSkills, showSkillDetail, closeSkillModal, updateTrust, uninstallSkill } from './tabs/skills.js';
import {
  setCurrentModel, toggleAddProvider, discoverModels, loadCloudPresets,
  onCloudPresetChange, testCloudProvider, addCloudProvider,
  saveProvider, deleteProvider, switchModel, loadModels,
  updateProviderKey, hideProviderKeyModal, submitProviderKeyUpdate,
} from './tabs/models.js';
import { loadFiles } from './tabs/files.js';
import { loadStatus, refreshSessionCapsule, clearSessionCapsule } from './tabs/status.js';
import { loadAudit } from './tabs/audit.js';
import { loadApprovals, startApprovalsPolling, stopApprovalsPolling } from './tabs/approvals.js';
import { loadTasks, startTasksPolling } from './tabs/tasks.js';
import { loadScenarios, startScenario, fillScenarioPrompt } from './tabs/scenarios.js';
import {
  loadFriends,
  createFriendInvite,
  acceptFriendInvite,
  completeFriendInvite,
  blockFriend,
  revokeFriend,
  sendFriendMessage,
  sendFriendTask,
} from './js/friends.js';
import { loadAgents } from './tabs/agents.js';
import {
  loadMemory, renderSemanticMemoryItem, editSemanticMemory, saveSemanticMemory,
  deleteSemanticMemory, recoverEmbedder, searchSemantic, showAddSemanticModal,
  submitSemanticMemory, openMemoryFileEditor, closeMemoryFileEditor, saveMemoryFile,
  showMemoryAudit, loadBlockTree, loadBlockMemories, verifyMemory, toggleSearchScope,
  toggleBlockExpand, openBlockDelete, openBlockMove, openBlockMerge,
  onBlockTargetChange, submitBlockModal, closeBlockModal,
  loadProposals, approveProposal, rejectProposal, approveAllProposals,
  organizeNow, openProposalEdit, closeProposalEdit, saveProposalEdit,
  confirmModalYes, closeConfirmModal,
} from './tabs/memory.js';
import {
  refreshCronJobs, renderCronJobs, runCronJob, toggleCronJob, deleteCronJob,
  loadCronTemplates, showCronCreateModal, hideCronCreateModal,
  onCronTemplateChange, parseCronNatural, submitCronJob,
} from './tabs/cron.js';
import {
  initShell, applyProductMode, refreshModelHint, refreshChatEmptyState,
  setStreaming, openPalette, closePalette,
  writeSwitchHandoff, showModeSwitchOverlay, hideModeSwitchOverlay,
  finishSwitchHandoff, clearSwitchHandoff,
} from './js/shell.js';
import { initWorkContext } from './js/work_context.js';
import { enterBotsSurface, exitBotsSurface, initBotsSurface, isBotsSurface } from './js/bots.js';

let wizardStep = state.wizardStep;
let wizardSelectedModel = state.wizardSelectedModel;

// ═══════════════════════════════════════════════════════════════
//  Global fetch wrapper — same-origin cookies only
// ═══════════════════════════════════════════════════════════════
const _origFetch = window.fetch;
window.fetch = async function(url, options = {}) {
  if (typeof url === 'string' && url.startsWith('/api/')) {
    const opts = { ...options };
    // Always send same-origin cookies (including parent js_appshell_session).
    if (!opts.credentials) opts.credentials = 'same-origin';
    return _origFetch(url, opts);
  }
  return _origFetch(url, options);
};

async function saveApiKey(key) {
  const trimmed = (key || '').trim();
  const input = document.getElementById('api-key-input');
  if (!trimmed) {
    // Clearing the key revokes the server-side session; the server also
    // expires the HttpOnly cookie in its response.
    state.apiKey = '';
    try {
      const parentLogout = await fetch('/api/appshell/logout', { method: 'POST' });
      if (parentLogout.status === 404) {
        await fetch('/api/auth/logout', { method: 'POST' });
      }
    } catch (e) { /* best effort */ }
    if (input) input.value = '';
    showToast('API Key 已清除');
    return true;
  }
  try {
    // AppShell exchanges once at the parent. A 404 means this is a standalone
    // child deployment, where the legacy product-scoped session stays valid.
    let res = await fetch('/api/appshell/session', {
      method: 'POST',
      headers: { 'X-API-Key': trimmed },
    });
    if (res.status === 404) {
      res = await fetch('/api/auth/session', {
        method: 'POST',
        headers: { 'X-API-Key': trimmed },
      });
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    // The plaintext is no longer needed after the HttpOnly exchange.
    state.apiKey = '';
    if (input) input.value = '';
    await applyCapabilityManifest();
    showToast('API Key 已保存');
    return true;
  } catch (e) {
    showToast('API Key 登录失败: ' + e.message, 'error');
    return false;
  }
}

function restoreApiKey() {
  // Credentials are no longer persisted in web storage: the server-issued
  // HttpOnly session cookie re-authenticates returning browsers. Purge any
  // legacy copies written by older versions.
  state.apiKey = '';
  try { localStorage.removeItem('js-api-key'); } catch (e) { /* ignore */ }
  try { localStorage.removeItem('js-appshell-active-product'); } catch (e) { /* ignore */ }
  try { localStorage.removeItem('js-appshell-personal-url'); } catch (e) { /* ignore */ }
  try { localStorage.removeItem('js-appshell-work-url'); } catch (e) { /* ignore */ }
  document.cookie = 'x-api-key=; path=/; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT';
}

function _wizardCacheKey() {
  return 'js-wizard-completed';
}

function _setWizardLocalCache(dismissed) {
  // Cache only — server onboarding_status is authoritative.
  try {
    if (dismissed) localStorage.setItem(_wizardCacheKey(), 'true');
    else localStorage.removeItem(_wizardCacheKey());
  } catch (e) { /* ignore storage failures */ }
}

function _isWizardBlocking(data) {
  if (!data || typeof data !== 'object') return true;
  if (typeof data.wizard_blocking === 'boolean') return data.wizard_blocking;
  const status = data.onboarding_status;
  if (status === 'completed' || status === 'skipped') return false;
  if (status === 'pending' || status === 'in_progress') return true;
  return !data.first_run_completed;
}

async function checkFirstStart() {
  // Always ask the server. localStorage is a non-authoritative cache only.
  try {
    const res = await fetch('/api/setup/first-start');
    if (!res.ok) return;
    const data = await res.json();
    if (_isWizardBlocking(data)) {
      _setWizardLocalCache(false);
      showWizard(true);
    } else {
      _setWizardLocalCache(true);
      // Do not let a late first-start response close a dialog that the user
      // explicitly opened while this request was in flight.
      if (!_wizardManuallyOpened) hideWizard();
    }
  } catch (e) {
    console.error('Failed to check first-start status:', e);
  }
}

async function resetWizard() {
  // Settings "重新运行向导": prefer reopen (keeps auth bootstrap closed after
  // skip/complete). Full /reset is only for pre-admin bootstrap recovery.
  _setWizardLocalCache(false);
  try {
    let res = await fetch('/api/setup/reopen', { method: 'POST' });
    if (!res.ok) {
      res = await fetch('/api/setup/reset', { method: 'POST' });
    }
    if (!res.ok) {
      const detail = await res.json().catch(() => ({}));
      const msg = detail.detail || ('HTTP ' + res.status);
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
    showWizard();
    showToast('设置向导已打开（可稍后再次跳过）');
  } catch (e) {
    showToast('打开向导失败: ' + e.message, 'error');
  }
}

let _wizardPreviousFocus = null;
let _wizardShellInertBefore = false;
let _wizardShellAriaHiddenBefore = null;
let _wizardFocusTrapBound = false;
let _wizardManuallyOpened = false;

function _wizardFocusable(root) {
  return Array.from(root.querySelectorAll(
    'button:not([disabled]), input:not([disabled]), select:not([disabled]), '
    + 'textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])',
  )).filter((node) => node instanceof HTMLElement && node.offsetParent !== null);
}

function _trapWizardFocus(event) {
  if (event.key !== 'Tab') return;
  const root = document.getElementById('setup-wizard');
  if (!root || root.classList.contains('hidden')) return;
  const focusable = _wizardFocusable(root);
  if (!focusable.length) {
    event.preventDefault();
    root.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (!root.contains(document.activeElement)) {
    event.preventDefault();
    first.focus();
  } else if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function _setWizardStepFocus(step) {
  const root = document.getElementById('setup-wizard');
  if (!root) return;
  const titleId = `wizard-step-${step}-title`;
  root.setAttribute('aria-labelledby', titleId);
  queueMicrotask(() => {
    const target = step === 1
      ? document.getElementById('wizard-start-button')
      : step === 3
        ? document.getElementById('wizard-finish')
        : document.getElementById(titleId);
    target?.focus();
  });
}

function showWizard(serverDriven = false) {
  hideModeSwitchOverlay({ immediate: true });
  clearSwitchHandoff();
  if (!serverDriven) _wizardManuallyOpened = true;
  wizardStep = 1;
  wizardSelectedModel = '';
  const root = document.getElementById('setup-wizard');
  if (!root) return;
  // The palette lives outside #app-shell and otherwise remains focusable above
  // the onboarding layer. A modal must be the only active focus surface.
  closePalette();
  const wasHidden = root.classList.contains('hidden');
  if (wasHidden) {
    _wizardPreviousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
  }
  // Keep the dialog outside the shell so the entire application behind it can
  // be inert without accidentally making the dialog itself inert.
  if (root.parentElement !== document.body) document.body.appendChild(root);
  const shell = document.getElementById('app-shell');
  if (shell && wasHidden) {
    _wizardShellInertBefore = shell.inert;
    _wizardShellAriaHiddenBefore = shell.getAttribute('aria-hidden');
    shell.inert = true;
    shell.setAttribute('aria-hidden', 'true');
  }
  root.classList.remove('hidden');
  document.getElementById('wizard-step-1')?.classList.remove('hidden');
  document.getElementById('wizard-step-2')?.classList.add('hidden');
  document.getElementById('wizard-step-3')?.classList.add('hidden');
  // Next must never stay permanently disabled from a prior failed test.
  const next2 = document.getElementById('wizard-next-2');
  if (next2) next2.disabled = false;
  if (!_wizardFocusTrapBound) {
    document.addEventListener('keydown', _trapWizardFocus, true);
    _wizardFocusTrapBound = true;
  }
  _setWizardStepFocus(1);
}

function hideWizard() {
  const root = document.getElementById('setup-wizard');
  if (!root || root.classList.contains('hidden')) return;
  _wizardManuallyOpened = false;
  root.classList.add('hidden');
  const shell = document.getElementById('app-shell');
  if (shell) {
    shell.inert = _wizardShellInertBefore;
    if (_wizardShellAriaHiddenBefore == null) shell.removeAttribute('aria-hidden');
    else shell.setAttribute('aria-hidden', _wizardShellAriaHiddenBefore);
  }
  const restore = _wizardPreviousFocus;
  _wizardPreviousFocus = null;
  queueMicrotask(() => {
    if (restore && restore.isConnected && !restore.closest('[inert]')) restore.focus();
    else document.getElementById('chat-input')?.focus();
  });
}

function _setWizardBusy(busy) {
  ['wizard-skip-1', 'wizard-skip-2', 'wizard-skip-3', 'wizard-next-2', 'wizard-finish'].forEach((id) => {
    const elBtn = document.getElementById(id);
    if (elBtn) elBtn.disabled = !!busy;
  });
}

async function wizardSkip() {
  // Persist skipped on the server — never hide-only via localStorage/DOM.
  // On API failure the wizard stays open (no fake skip).
  _setWizardBusy(true);
  let dismissed = false;
  try {
    const res = await fetch('/api/setup/skip', { method: 'POST' });
    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      data = null;
    }
    if (!res.ok) {
      const detail = (data && data.detail) || ('HTTP ' + res.status);
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    if (!data || data.success !== true) {
      throw new Error('服务端未确认跳过，向导保持打开');
    }
    // Authority is server status — only dismiss when terminal skip is confirmed.
    if (data.onboarding_status && data.onboarding_status !== 'skipped') {
      throw new Error('服务端状态异常: ' + data.onboarding_status);
    }
    if (data.admin_key && !state.apiKey) {
      await saveApiKey(data.admin_key);
    }
    _setWizardLocalCache(true);
    hideWizard();
    dismissed = true;
    showToast('已跳过初始设置，可随时在模型设置中配置');
  } catch (e) {
    _setWizardLocalCache(false);
    if (!dismissed) {
      // Ensure modal remains visible — never pretend skip succeeded.
      document.getElementById('setup-wizard')?.classList.remove('hidden');
    }
    showToast('跳过设置失败: ' + (e.message || e), 'error');
  } finally {
    _setWizardBusy(false);
    const next2 = document.getElementById('wizard-next-2');
    if (next2) next2.disabled = false;
  }
}

function wizardNext() {
  console.log('wizardNext called, step=', wizardStep, 'selected=', wizardSelectedModel);
  try {
    const step1 = document.getElementById('wizard-step-1');
    const step2 = document.getElementById('wizard-step-2');
    const step3 = document.getElementById('wizard-step-3');

    if (step1 && !step1.classList.contains('hidden')) {
      step1.classList.add('hidden');
      step2.classList.remove('hidden');
      wizardStep = 2;
      // Mark in_progress server-side (best-effort; do not block UI).
      fetch('/api/setup/start', { method: 'POST' }).catch(() => {});
      loadWizardModels();
      _setWizardStepFocus(2);
    } else if (step2 && !step2.classList.contains('hidden')) {
      // Model selection is optional: allow continue without locking the user.
      if (!wizardSelectedModel) {
        showToast('未选择模型，可在下一步直接进入或稍后再配置', 'warning');
      }
      step2.classList.add('hidden');
      step3.classList.remove('hidden');
      const model = (state.availableModels || []).find(m => m.id === wizardSelectedModel);
      const labelEl = document.getElementById('wizard-selected-model');
      if (labelEl) {
        labelEl.textContent = wizardSelectedModel
          ? (model ? (model.name || model.id) : wizardSelectedModel)
          : '未选择（可稍后配置）';
      }
      wizardStep = 3;
      _setWizardStepFocus(3);
    }
  } catch (e) {
    console.error('wizardNext error:', e);
    showToast('向导出错: ' + e.message, 'error');
    const next2 = document.getElementById('wizard-next-2');
    if (next2) next2.disabled = false;
  }
}

function wizardPrev() {
  if (wizardStep === 2) {
    document.getElementById('wizard-step-2').classList.add('hidden');
    document.getElementById('wizard-step-1').classList.remove('hidden');
    wizardStep = 1;
    _setWizardStepFocus(1);
  } else if (wizardStep === 3) {
    document.getElementById('wizard-step-3').classList.add('hidden');
    document.getElementById('wizard-step-2').classList.remove('hidden');
    wizardStep = 2;
    _setWizardStepFocus(2);
    const next2 = document.getElementById('wizard-next-2');
    if (next2) next2.disabled = false;
  }
}

async function wizardComplete() {
  _setWizardBusy(true);
  try {
    if (wizardSelectedModel) {
      try {
        await switchModel(wizardSelectedModel);
      } catch (modelErr) {
        // Switching model must not trap the user in the wizard.
        showToast('默认模型切换失败，仍将完成设置: ' + (modelErr.message || modelErr), 'warning');
      }
    }
    const res = await fetch('/api/setup/complete', { method: 'POST' });
    if (!res.ok) {
      const detail = await res.json().catch(() => ({}));
      throw new Error(detail.detail || ('HTTP ' + res.status));
    }
    try {
      const data = await res.json();
      // If the server minted an admin key on completion (and we don't already
      // have one), persist it so the now-closed bootstrap window stays usable.
      if (data && data.admin_key && !state.apiKey) {
        await saveApiKey(data.admin_key);
      }
    } catch (_) {}
    _setWizardLocalCache(true);
    hideWizard();
    showToast('设置完成，欢迎使用！');
  } catch (e) {
    showToast('完成设置失败: ' + e.message, 'error');
  } finally {
    _setWizardBusy(false);
  }
}

async function loadWizardModels() {
  const container = document.getElementById('wizard-model-list');
  container.innerHTML = '<div class="text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>加载模型列表...</div>';
  try {
    const res = await fetch('/api/models');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const flatModels = [];
    let hasHealthyConfigured = false;
    // Configured providers only — presets belong in the "add cloud model" area.
    if (data.providers) {
      data.providers.forEach(p => {
        const statusLabel = p.healthy ? '在线' : (p.has_key ? '离线' : '待配置');
        if (p.healthy) hasHealthyConfigured = true;
        p.models.forEach(m => {
          flatModels.push({
            id: `${p.name}/${m.id}`,
            rawId: m.id,
            name: `${p.name}/${m.name || m.id}`,
            provider: p.name,
            contextWindow: m.context_window,
            statusLabel,
            healthy: p.healthy,
            hasKey: p.has_key,
            isPreset: false,
          });
        });
      });
    }
    if (flatModels.length === 0) {
      container.innerHTML = renderWizardNoModels();
      bindDataClicks(container, 'presetId', (rawId) => {
        const presetId = sanitizeRuntimeId(rawId);
        if (!presetId) return;
        wizardSkip().then(() => {
          switchTab('models');
          setTimeout(() => {
            const presetEl = document.getElementById('cloud-preset-select');
            if (presetEl) presetEl.value = presetId;
          }, 100);
        });
      });
      const nextEmpty = document.getElementById('wizard-next-2');
      if (nextEmpty) nextEmpty.disabled = false;
      loadWizardCloudPresets();
      return;
    }
    container.replaceChildren();
    for (const m of flatModels) {
      const modelId = sanitizeRuntimeId(m.id);
      if (!modelId) continue;
      const row = el('div', {
        className: `flex items-center gap-2 bg-gray-800 rounded-lg px-3 py-2 border border-transparent ${wizardSelectedModel === modelId ? 'border-blue-500' : ''}`,
        dataset: { modelId },
      });
      const label = el('label', {
        className: 'flex items-center gap-3 flex-1 cursor-pointer hover:bg-gray-700 transition rounded px-1 py-1',
      });
      const radio = el('input', {
        className: 'accent-blue-500',
        attrs: {
          type: 'radio',
          name: 'wizard-model',
          value: modelId,
          ...(wizardSelectedModel === modelId ? { checked: true } : {}),
        },
        dataset: { modelId },
      });
      onDataChange(radio, 'modelId', (id) => wizardSelectModel(id));
      const meta = el('div', { className: 'flex-1 min-w-0' });
      meta.appendChild(el('div', {
        className: 'text-sm font-medium',
        text: m.name || modelId,
      }));
      meta.appendChild(el('div', {
        className: 'text-xs text-gray-500',
        text: `Provider: ${m.provider || ''} · 上下文: ${m.contextWindow || '--'} tokens · 状态: ${m.statusLabel || '未知'}`,
      }));
      label.appendChild(radio);
      label.appendChild(meta);
      row.appendChild(label);
      if (!m.isPreset) {
        const testBtn = el('button', {
          className: 'text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition whitespace-nowrap',
          attrs: { type: 'button', title: '测试连接' },
          dataset: { modelId },
        });
        testBtn.appendChild(document.createTextNode('测试'));
        onDataClick(testBtn, 'modelId', (id, event) => testWizardModel(id, event.currentTarget));
        row.appendChild(testBtn);
      }
      const resultSpan = el('span', {
        className: 'text-xs hidden whitespace-nowrap',
        attrs: { id: `test-result-${modelId.replace(/[^a-zA-Z0-9]/g, '-')}` },
      });
      row.appendChild(resultSpan);
      container.appendChild(row);
    }
    // Never permanently disable Next — user may continue without a selection
    // or use "稍后再配置". Selection is encouraged, not required.
    const nextBtn = document.getElementById('wizard-next-2');
    if (nextBtn) nextBtn.disabled = false;
    loadWizardCloudPresets();
  } catch (e) {
    container.replaceChildren(el('div', {
      className: 'text-red-400 text-sm',
      text: `加载模型失败: ${e.message || e}`,
    }));
    const nextErr = document.getElementById('wizard-next-2');
    if (nextErr) nextErr.disabled = false;
  }
}

async function loadWizardCloudPresets() {
  const select = document.getElementById('wizard-cloud-select');
  if (!select) return;
  try {
    const res = await fetch('/api/providers/cloud-presets');
    if (!res.ok) return;
    const data = await res.json();
    state.wizardCloudPresets = data.presets || [];
    select.innerHTML = '<option value="">选择云模型...</option>' +
      state.wizardCloudPresets.map(p => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');
  } catch (e) {
    select.innerHTML = '<option value="">加载失败</option>';
  }
}

function onWizardCloudChange() {
  const select = document.getElementById('wizard-cloud-select');
  const details = document.getElementById('wizard-cloud-details');
  const descEl = document.getElementById('wizard-cloud-desc');
  const errEl = document.getElementById('wizard-cloud-error');
  const sucEl = document.getElementById('wizard-cloud-success');
  errEl.classList.add('hidden');
  sucEl.classList.add('hidden');

  const presetId = select.value;
  if (!presetId) { details.classList.add('hidden'); return; }
  const presets = state.wizardCloudPresets || [];
  const preset = presets.find(p => p.id === presetId);
  if (!preset) { details.classList.add('hidden'); return; }

  const models = (preset.models || []).map(m => m.name || m.id).join(', ');
  descEl.textContent = (preset.description || '') + (models ? ' · 模型: ' + models : '');
  details.classList.remove('hidden');
}

async function testWizardCloud() {
  const select = document.getElementById('wizard-cloud-select');
  const keyInput = document.getElementById('wizard-cloud-key');
  const errEl = document.getElementById('wizard-cloud-error');
  const sucEl = document.getElementById('wizard-cloud-success');
  const btn = document.getElementById('wizard-btn-test-cloud');

  const presetId = select.value;
  const apiKey = keyInput.value.trim();
  if (!presetId) { errEl.textContent = '请选择云模型'; errEl.classList.remove('hidden'); return; }
  if (!apiKey) { errEl.textContent = '请输入 API Key'; errEl.classList.remove('hidden'); return; }

  errEl.classList.add('hidden');
  sucEl.classList.add('hidden');
  const existing = _wizardTestControllers.get('__cloud__');
  if (existing) {
    existing.abort();
    return;
  }
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  if (controller) _wizardTestControllers.set('__cloud__', controller);
  btn.disabled = false; // stays clickable as cancel
  btn.innerHTML = '取消';

  try {
    const res = await fetch('/api/providers/test-cloud', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset_id: presetId, api_key: apiKey }),
      signal: controller ? controller.signal : undefined,
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      const detail = data && typeof data.detail === 'string' && !data.detail.startsWith('{')
        ? data.detail
        : '连接失败，请检查网络与 API Key';
      throw new Error(detail);
    }
    const data = await res.json();
    sucEl.textContent = '连接成功，发现 ' + (data.models?.length || 0) + ' 个模型';
    sucEl.classList.remove('hidden');
  } catch (e) {
    errEl.textContent = e && e.name === 'AbortError'
      ? '已取消，可重试或稍后再配置'
      : e.message;
    errEl.classList.remove('hidden');
  } finally {
    if (controller) _wizardTestControllers.delete('__cloud__');
    btn.disabled = false;
    btn.innerHTML = '测试连接';
  }
}

async function addWizardCloud() {
  const select = document.getElementById('wizard-cloud-select');
  const keyInput = document.getElementById('wizard-cloud-key');
  const errEl = document.getElementById('wizard-cloud-error');
  const btn = document.getElementById('wizard-btn-add-cloud');

  const presetId = select.value;
  const apiKey = keyInput.value.trim();
  if (!presetId) { errEl.textContent = '请选择云模型'; errEl.classList.remove('hidden'); return; }
  if (!apiKey) { errEl.textContent = '请输入 API Key'; errEl.classList.remove('hidden'); return; }

  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>添加中...';

  try {
    const res = await fetch('/api/providers/add-cloud', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset_id: presetId, api_key: apiKey })
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || '添加失败: HTTP ' + res.status);
    }
    const data = await res.json();
    showToast('云模型已添加: ' + (data.provider_name || presetId));
    // Refresh model list
    await loadWizardModels();
    // Auto-select first model of this provider if none selected
    if (!wizardSelectedModel && data.models?.length > 0) {
      const firstModelId = data.provider_name + '/' + data.models[0].id;
      wizardSelectModel(firstModelId);
    }
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-plus mr-1"></i>添加并使用';
  }
}

function renderWizardNoModels() {
  return `
    <div class="text-gray-400 text-sm mb-4">未配置模型，您可以选择以下方式添加：</div>
    ${renderWizardCloudHint()}
    <div class="mt-4 text-center space-y-2">
      <button type="button" onclick="wizardSkip().then(() => switchTab('models'))" class="text-sm text-blue-400 hover:text-blue-300 underline">稍后再配置并前往模型设置</button>
    </div>
  `;
}

function renderWizardCloudHint() {
  const presets = [
    { id: 'deepseek', label: 'DeepSeek' },
    { id: 'openai', label: 'OpenAI' },
    { id: 'kimi-cn', label: 'Kimi' },
  ];
  const rows = presets.map((p) =>
    `<button type="button" data-preset-id="${escapeHtml(p.id)}" class="block w-full text-left text-sm px-3 py-2 rounded hover:bg-gray-700 text-gray-300 transition">${escapeHtml(p.label)}</button>`,
  ).join('');
  return `
    <div class="bg-gray-800/50 border border-gray-700 rounded-lg p-3 mt-2">
      <div class="text-sm font-medium text-gray-300 mb-1">没有本地模型？快速添加云模型：</div>
      <div class="space-y-1">${rows}</div>
    </div>
  `;
}

const _wizardTestControllers = new Map();

async function testWizardModel(modelId, btnEl) {
  const resultId = 'test-result-' + modelId.replace(/[^a-zA-Z0-9]/g, '-');
  const resultEl = document.getElementById(resultId);
  if (!resultEl) return;

  // Second click while in flight = user cancel (AbortController).
  const existing = _wizardTestControllers.get(modelId);
  if (existing) {
    existing.abort();
    return;
  }

  const next2 = document.getElementById('wizard-next-2');
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  if (controller) _wizardTestControllers.set(modelId, controller);
  btnEl.disabled = false; // stays clickable as the cancel control
  btnEl.innerHTML = '取消';
  resultEl.classList.remove('hidden');
  resultEl.textContent = '测试中…（可取消）';
  resultEl.className = 'text-xs text-gray-400 whitespace-nowrap';

  // Bound client wait so a hung request cannot lock the UI forever.
  const timer = controller ? setTimeout(() => controller.abort(), 65000) : null;

  try {
    const res = await fetch('/api/setup/test-model', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_id: modelId }),
      signal: controller ? controller.signal : undefined,
    });
    let data = null;
    const rawText = await res.text();
    try {
      data = rawText ? JSON.parse(rawText) : {};
    } catch (_) {
      throw new Error(res.ok ? '模型测试返回了非 JSON 响应' : '连接测试失败，请稍后重试');
    }
    if (!res.ok) {
      const detail = (data && (data.detail || data.error)) || '';
      throw new Error(
        typeof detail === 'string' && detail && !detail.startsWith('{')
          ? detail
          : '连接测试失败，请稍后重试',
      );
    }
    if (data && data.ok) {
      resultEl.innerHTML = `<span class="text-green-400">可用 (${data.latency_ms}ms)</span>`;
      // Auto-select this model after successful test only — never auto-select on failure.
      wizardSelectModel(modelId);
      const safeId = modelId.replace(/"/g, '\\"');
      const radio = document.querySelector('input[name="wizard-model"][value="' + safeId + '"]');
      if (radio) radio.checked = true;
    } else {
      const errText = (data && typeof data.error === 'string' && !data.error.startsWith('{'))
        ? data.error
        : '连接失败';
      resultEl.innerHTML = `<span class="text-red-400">${escapeHtml(errText)}</span>`;
    }
  } catch (e) {
    const msg = e && e.name === 'AbortError'
      ? '已取消或超时，可重试或稍后再配置'
      : (e.message || String(e));
    resultEl.innerHTML = `<span class="text-red-400">${escapeHtml(msg)}</span>`;
  } finally {
    if (timer) clearTimeout(timer);
    if (controller) _wizardTestControllers.delete(modelId);
    btnEl.disabled = false;
    btnEl.innerHTML = '测试';
    // Failure/timeout must never leave Next/Skip locked.
    if (next2) next2.disabled = false;
  }
}

function wizardSelectModel(modelId) {
  wizardSelectedModel = modelId;
  const next2 = document.getElementById('wizard-next-2');
  if (next2) next2.disabled = false;
  // Update visual selection
  document.querySelectorAll('#wizard-model-list label').forEach(el => {
    el.classList.toggle('border-blue-500', el.querySelector('input')?.value === modelId);
  });
}

// ===== File Attachments =====
state.pendingAttachments = []; // { id, path, name, type, size, previewUrl? }

function connectWS() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  // Cookie is sent automatically by the browser — no query param needed.
  const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);
  state.ws = socket;
  socket.onopen = () => {
    if (state.ws !== socket) return;
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> <span class="text-green-400">已连接</span>';
  };
  socket.onclose = () => {
    // A closed transport is terminal for the identity that was active on it.
    // Invalidate before reconnect so old frames cannot attach to a later turn.
    if (state.ws !== socket) return;
    state.streamGeneration += 1;
    state.activeStream = null;
    abortStream('failed');
    state.ws = null;
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500"></span> <span class="text-red-400">断开 - 重连中...</span>';
    setTimeout(() => {
      if (!state.ws || state.ws.readyState !== WebSocket.OPEN) connectWS();
    }, 3000);
  };
  socket.onerror = () => {
    if (state.ws !== socket) return;
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-yellow-500"></span> <span class="text-yellow-400">连接错误</span>';
  };
  socket.onmessage = (e) => {
    if (state.ws !== socket) return;
    let data;
    try {
      data = JSON.parse(e.data);
    } catch (err) {
      console.error('WebSocket JSON parse error:', err);
      return;
    }
    const streamTypes = new Set([
      'token', 'thinking', 'tool_call', 'usage', 'stream_diagnostic',
      'response', 'done', 'status', 'progress', 'error',
    ]);
    if (streamTypes.has(data.type) && !acceptActiveStreamFrame(data)) return;
    if (data.type === 'token') {
      appendToken(data.content);
    } else if (data.type === 'thinking') {
      // PR-4.3: structured thinking_delta from chat_stream_events().
      // Direct path: bypass <think> tag parsing and feed the reasoning
      // panel verbatim. <think> fallback in appendToken() still works
      // for providers that only emit inline tags.
      appendThinkingDelta(data.content);
    } else if (data.type === 'tool_call') {
      // PR-4.3: streamed tool-call fragment; show as a live progress row.
      const tc = data.tool_call || {};
      const toolName = tc.name || tc.id || ('tool#' + (tc.index ?? '?'));
      // Providers may emit an id only on the first fragment.  The index is the
      // stable key across the whole streamed call, so prefer it whenever set.
      const stepKey = tc.index !== undefined && tc.index !== null
        ? `tool-${tc.index}`
        : (tc.id || `tool-${toolName}`);
      showProgress(toolName, tc.arguments_delta || '', null, stepKey);
    } else if (data.type === 'usage') {
      // PR-4.3: stash the structured usage for diagnostics; UI display
      // is intentionally deferred so we don't churn the chat surface.
      state.lastUsage = data.usage || {};
    } else if (data.type === 'stream_diagnostic') {
      state.lastStreamDiagnostic = data.content || '';
    } else if (data.type === 'response') {
      state.sessionId = data.session_id;
      document.dispatchEvent(new CustomEvent('js:session-updated'));
      finishResponse(data.content, data.model);
      state.activeStream = null;
    } else if (data.type === 'done') {
      if (data.session_id) state.sessionId = data.session_id;
      document.dispatchEvent(new CustomEvent('js:session-updated'));
      finishStream();
      state.activeStream = null;
    } else if (data.type === 'status') {
      showTyping();
    } else if (data.type === 'progress') {
      showProgress(data.tool, data.preview, Boolean(data.success));
    } else if (data.type === 'error') {
      abortStream('failed');
      appendMessage('system', '错误: ' + data.content);
      if (data.terminal) state.activeStream = null;
    }
  };
}

function freshClientId(prefix) {
  if (!globalThis.crypto || typeof globalThis.crypto.randomUUID !== 'function') {
    throw new Error('secure random identity unavailable');
  }
  return `${prefix}-${globalThis.crypto.randomUUID()}`;
}

function acceptActiveStreamFrame(frame) {
  const active = state.activeStream;
  if (!active) return false;
  if (!frame || typeof frame.request_id !== 'string' || typeof frame.turn_id !== 'string'
      || typeof frame.run_id !== 'string' || typeof frame.session_id !== 'string') return false;
  if (frame.request_id !== active.requestId || frame.turn_id !== active.turnId
      || frame.session_id !== active.sessionId) return false;
  if (active.runId && frame.run_id !== active.runId) return false;
  if (!active.runId) active.runId = frame.run_id;
  return active.generation === state.streamGeneration;
}

async function cancelActiveStream({ reportFailure = false } = {}) {
  const active = state.activeStream;
  if (!active) return true;
  state.streamGeneration += 1;
  state.activeStream = null;
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({
      type: 'cancel', request_id: active.requestId, turn_id: active.turnId,
      run_id: active.runId, session_id: active.sessionId,
    }));
  }
  abortStream();
  const query = new URLSearchParams({ request_id: active.requestId });
  if (active.runId) query.set('run_id', active.runId);
  try {
    const res = await fetch(`/api/cancel/${encodeURIComponent(active.sessionId)}?${query}`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return true;
  } catch (error) {
    if (reportFailure) appendMessage('system', '停止请求失败：服务端未确认取消');
    return false;
  }
}

function appendMessage(role, content, model) {
  const container = document.getElementById('chat-messages');
  if (!container) return null;
  const div = document.createElement('div');
  div.className = `flex ${role === 'user' ? 'justify-end' : 'justify-start'}`;
  const sender = role === 'user' ? '你' : role === 'assistant' ? 'JS Agent' : '系统消息';
  div.dataset.messageRole = role;
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', sender);
  const bubble = document.createElement('div');
  bubble.className = `max-w-3xl px-4 py-3 rounded-2xl ${role === 'user' ? 'msg-user text-white rounded-br-md' : 'msg-assistant text-gray-200 rounded-bl-md markdown'}`;
  bubble.innerHTML = role === 'user' ? escapeHtml(content) : renderMarkdown(content);
  div.appendChild(bubble);
  // Model label for assistant messages
  if (role === 'assistant' && model) {
    const label = document.createElement('div');
    label.className = 'text-xs text-gray-500 mt-1 ml-1';
    label.textContent = model;
    div.appendChild(label);
  }
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  container.scrollTop = container.scrollHeight;
  return bubble;
}

function showTyping() {
  const container = document.getElementById('chat-messages');
  const existing = document.getElementById('typing-indicator');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'typing-indicator';
  div.className = 'flex justify-start';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'status');
  div.setAttribute('aria-label', 'JS Agent 正在回复');
  div.innerHTML = `<div class="msg-assistant px-4 py-3 rounded-2xl rounded-bl-md flex gap-1"><span class="typing-dot w-2 h-2 bg-gray-400 rounded-full"></span><span class="typing-dot w-2 h-2 bg-gray-400 rounded-full"></span><span class="typing-dot w-2 h-2 bg-gray-400 rounded-full"></span></div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

const TOOL_PROGRESS_LABELS = {
  web_navigate: '正在打开网页',
  web_snapshot: '正在获取页面结构',
  web_click: '正在点击元素',
  web_fill: '正在填写内容',
  web_screenshot: '正在截图',
  web_evaluate: '正在执行脚本',
  web_extract_text: '正在提取页面内容',
  web_find_tab: '正在查找标签页',
  web_list_tabs: '正在列出标签页',
  file_read: '正在读取文件',
  file_write: '正在写入文件',
  file_edit: '正在编辑文件',
  shell: '正在执行命令',
  python: '正在运行代码',
  browser_fetch: '正在获取网页',
  web_search: '正在搜索',
  excel_write: '正在生成表格',
  excel_read: '正在读取表格',
};

function ensureRunProgress() {
  const container = document.getElementById('chat-messages');
  if (!container) return null;
  if (state.currentProgressBlock && state.currentProgressBlock.isConnected) {
    return state.currentProgressBlock;
  }
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  const block = document.createElement('section');
  block.className = 'run-progress';
  block.setAttribute('aria-label', '执行进度');
  block.setAttribute('aria-live', 'polite');
  const heading = document.createElement('div');
  heading.className = 'run-progress-title';
  heading.textContent = '执行进度';
  const list = document.createElement('div');
  list.className = 'run-progress-list';
  block.append(heading, list);
  container.appendChild(block);
  state.currentProgressBlock = block;
  state.progressSteps = new Map();
  return block;
}

function latestRunningStepForTool(tool) {
  const steps = Array.from(state.progressSteps.values());
  for (let index = steps.length - 1; index >= 0; index -= 1) {
    const row = steps[index];
    if (row.dataset.tool === String(tool) && row.dataset.progressState === 'running') {
      return row;
    }
  }
  return null;
}

function renderProgressStep(row, tool, preview, status) {
  const label = TOOL_PROGRESS_LABELS[tool] || (`正在执行: ${tool}`);
  const labelNode = document.createElement('span');
  labelNode.className = 'run-progress-label';
  labelNode.textContent = label;
  const previewNode = document.createElement('span');
  previewNode.className = 'run-progress-preview';
  previewNode.textContent = preview ? String(preview).slice(0, 60) : '';
  const statusNode = document.createElement('span');
  statusNode.className = `run-progress-status ${status}`;
  statusNode.textContent = status === 'done'
    ? '已完成'
    : status === 'failed'
      ? '失败'
      : status === 'cancelled'
        ? '已取消'
        : '进行中';
  row.replaceChildren(labelNode, previewNode, statusNode);
  row.dataset.progressState = status;
}

function showProgress(tool, preview, success = null, requestedKey = null) {
  const block = ensureRunProgress();
  if (!block) return;
  let row = requestedKey ? state.progressSteps.get(String(requestedKey)) : null;
  if (!row && success !== null) row = latestRunningStepForTool(tool);
  if (!row) {
    const key = String(requestedKey || `${tool}-${state.progressSequence++}`);
    row = document.createElement('div');
    row.className = 'run-progress-step';
    row.dataset.progressKey = key;
    row.dataset.tool = String(tool);
    state.progressSteps.set(key, row);
    block.querySelector('.run-progress-list')?.appendChild(row);
  }
  const status = success === null ? 'running' : success ? 'done' : 'failed';
  renderProgressStep(row, tool, preview, status);
  const container = document.getElementById('chat-messages');
  container.scrollTop = container.scrollHeight;
}

function finalizeRunProgress(terminalState) {
  for (const row of state.progressSteps.values()) {
    if (row.dataset.progressState !== 'running') continue;
    renderProgressStep(row, row.dataset.tool || 'tool', '', terminalState);
  }
  state.currentProgressBlock = null;
  state.progressSteps = new Map();
  state.progressSequence = 0;
}

state.currentBubble = null;
state.streamBuffer = '';
state.inThinking = false;
state.thinkingBuffer = '';
state.responseBuffer = '';
state.thinkingBlock = null;
state.responseSpan = null;
state.tokenRAF = null;
state.currentProgressBlock = null;
state.progressSteps = new Map();
state.progressSequence = 0;

const THINK_START_TAGS = ['<think>', '<thinking>', '<reasoning>', '<thought>'];
const THINK_END_TAGS = ['</think>', '</thinking>', '</reasoning>', '</thought>'];

function _checkThinkingTransition(text) {
  for (const tag of THINK_START_TAGS) {
    const idx = text.indexOf(tag);
    if (idx !== -1) return { type: 'start', tag, index: idx };
  }
  for (const tag of THINK_END_TAGS) {
    const idx = text.indexOf(tag);
    if (idx !== -1) return { type: 'end', tag, index: idx };
  }
  return null;
}

function _ensureThinkingBlock() {
  if (!state.thinkingBlock) {
    state.thinkingBlock = document.createElement('details');
    state.thinkingBlock.className = 'thinking-block';
    state.thinkingBlock.open = true;
    state.thinkingBlock.innerHTML = `
      <summary><i class="fas fa-brain mr-1"></i>思考过程 <span class="thinking-status"></span></summary>
      <div class="thinking-content"></div>
    `;
    if (state.currentBubble) {
      state.currentBubble.insertBefore(state.thinkingBlock, state.currentBubble.firstChild);
    }
  }
}

function _setThinkingContent(text) {
  _ensureThinkingBlock();
  if (!state.thinkingBlock) return;
  const tc = state.thinkingBlock.querySelector('.thinking-content');
  if (tc) tc.textContent = text;
  const status = state.thinkingBlock.querySelector('.thinking-status');
  if (status) status.textContent = text ? '生成中' : '';
}

function _ensureResponseSpan() {
  if (!state.responseSpan && state.currentBubble) {
    state.responseSpan = document.createElement('span');
    state.responseSpan.className = 'response-span';
    state.currentBubble.appendChild(state.responseSpan);
  }
  return state.responseSpan;
}

function _flushTokenQueue() {
  state.tokenRAF = null;
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();

  if (!state.currentBubble) {
    state.currentBubble = appendMessage('assistant', '');
    state.currentBubble.id = 'streaming-bubble';
    state.currentBubble.classList.add('typing-cursor');
  }

  const buf = state.streamBuffer;
  state.streamBuffer = '';

  // Process thinking tags in accumulated buffer
  let remaining = buf;
  while (remaining.length > 0) {
    const trans = _checkThinkingTransition(remaining);
    if (!trans) {
      if (state.inThinking) {
        state.thinkingBuffer += remaining;
        _setThinkingContent(state.thinkingBuffer);
      } else {
        state.responseBuffer += remaining;
        const responseSpan = _ensureResponseSpan();
        if (responseSpan) responseSpan.textContent = state.responseBuffer;
      }
      break;
    }

    const before = remaining.slice(0, trans.index);
    if (state.inThinking) {
      state.thinkingBuffer += before;
      _setThinkingContent(state.thinkingBuffer);
    } else {
      state.responseBuffer += before;
      const responseSpan = _ensureResponseSpan();
      if (responseSpan) responseSpan.textContent = state.responseBuffer;
    }

    if (trans.type === 'start') {
      state.inThinking = true;
      state.thinkingBuffer = '';
      _ensureThinkingBlock();
      remaining = remaining.slice(trans.index + trans.tag.length);
    } else {
      state.inThinking = false;
      if (state.thinkingBlock) {
        state.thinkingBlock.open = false;
        const status = state.thinkingBlock.querySelector('.thinking-status');
        if (status) status.textContent = '已完成';
      }
      remaining = remaining.slice(trans.index + trans.tag.length);
    }
  }

  const container = document.getElementById('chat-messages');
  container.scrollTop = container.scrollHeight;
}

function appendToken(token) {
  state.streamBuffer += token;
  if (!state.tokenRAF) {
    state.tokenRAF = requestAnimationFrame(_flushTokenQueue);
  }
}

function _flushPendingTokensNow() {
  if (state.tokenRAF) {
    cancelAnimationFrame(state.tokenRAF);
    state.tokenRAF = null;
  }
  if (state.streamBuffer) {
    _flushTokenQueue();
  }
}

// PR-4.3: direct thinking-delta path from chat_stream_events(). Bypasses
// the <think>...</think> tag scanner in _flushTokenQueue and goes straight
// into state.thinkingBuffer + the <details> reasoning panel. The legacy
// inline-tag fallback in _flushTokenQueue() remains active for providers
// that only emit text deltas with embedded <think> markers.
function appendThinkingDelta(text) {
  if (!text) return;
  if (!state.currentBubble) {
    state.currentBubble = appendMessage('assistant', '');
    state.currentBubble.id = 'streaming-bubble';
    state.currentBubble.classList.add('typing-cursor');
  }
  _ensureThinkingBlock();
  state.thinkingBuffer += text;
  _setThinkingContent(state.thinkingBuffer);
  const container = document.getElementById('chat-messages');
  if (container) container.scrollTop = container.scrollHeight;
}

function _finalizeStreamBubble(model) {
  if (!state.currentBubble) return;
  state.currentBubble.classList.remove('typing-cursor');
  state.currentBubble.id = '';

  if (state.thinkingBlock) {
    const status = state.thinkingBlock.querySelector('.thinking-status');
    if (status) status.textContent = '已完成';
    state.thinkingBlock.open = false;
  }

  if (state.responseSpan) {
    const responseEl = document.createElement('div');
    responseEl.className = 'response-content markdown';
    responseEl.innerHTML = renderMarkdown(state.responseBuffer);
    state.responseSpan.replaceWith(responseEl);
  } else if (state.responseBuffer) {
    const responseEl = document.createElement('div');
    responseEl.className = 'response-content markdown';
    responseEl.innerHTML = renderMarkdown(state.responseBuffer);
    state.currentBubble.appendChild(responseEl);
  }

  // Add model label
  if (model && state.currentBubble.parentElement) {
    const existing = state.currentBubble.parentElement.querySelector('.model-label');
    if (!existing) {
      const label = document.createElement('div');
      label.className = 'model-label text-xs text-gray-500 mt-1 ml-1';
      label.textContent = model;
      state.currentBubble.parentElement.appendChild(label);
    }
  }

  state.currentBubble = null;
  state.streamBuffer = '';
  state.inThinking = false;
  state.thinkingBuffer = '';
  state.responseBuffer = '';
  state.thinkingBlock = null;
  state.responseSpan = null;
}

function finishResponse(content, model) {
  setStreaming(false);
  finalizeRunProgress('done');
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  _flushPendingTokensNow();
  if (!state.currentBubble) {
    appendMessage('assistant', content, model);
  } else {
    if (content && !state.responseBuffer) {
      state.responseBuffer = content;
      const responseSpan = _ensureResponseSpan();
      if (responseSpan) responseSpan.textContent = state.responseBuffer;
    }
    _finalizeStreamBubble(model);
  }
  const container = document.getElementById('chat-messages');
  container.scrollTop = container.scrollHeight;
}

function finishStream() {
  setStreaming(false);
  finalizeRunProgress('done');
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  _flushPendingTokensNow();
  if (state.currentBubble) {
    _finalizeStreamBubble();
  }
}

function abortStream(terminalState = 'cancelled') {
  setStreaming(false);
  finalizeRunProgress(terminalState);
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  _flushPendingTokensNow();
  if (state.currentBubble) {
    _finalizeStreamBubble();
  }
}

function toggleFleetMode() {
  const leavingFleet = state.fleetMode;
  if (leavingFleet) {
    state.fleetGeneration += 1;
    const active = state.activeFleetRun;
    if (state.fleetWS && state.fleetWS.readyState === WebSocket.OPEN && active) {
      state.fleetWS.send(JSON.stringify({ type: 'cancel', ...active }));
    }
    state.activeFleetRun = null;
    setStreaming(false);
  }
  state.fleetMode = !state.fleetMode;
  localStorage.setItem('js-fleet-mode', state.fleetMode ? '1' : '0');

  const singleIndicator = document.getElementById('mode-indicator-single');
  const fleetIndicator = document.getElementById('mode-indicator-fleet');
  const modeSelect = document.getElementById('fleet-mode-select');
  const toggleLabel = document.getElementById('mode-toggle-label');

  if (singleIndicator) singleIndicator.classList.toggle('hidden', state.fleetMode);
  if (fleetIndicator) fleetIndicator.classList.toggle('hidden', !state.fleetMode);
  if (modeSelect) modeSelect.classList.toggle('hidden', !state.fleetMode);
  if (toggleLabel) toggleLabel.textContent = state.fleetMode ? '切换至单模型' : '切换至集群';

  const input = document.getElementById('chat-input');
  if (input) {
    input.placeholder = state.fleetMode
      ? '输入复杂任务，多个AI Agent会分工协作完成...'
      : '输入消息... (Shift+Enter 换行, Enter 发送，或直接拖拽文件到页面)';
  }

  const container = document.getElementById('chat-messages');
  if (container) {
    container.innerHTML = '';
    if (state.fleetMode) {
      appendMessage('system', '🚀 已切换到 Agent 集群协作模式。输入复杂任务，多个AI Agent会分工协作完成。');
    } else {
      appendMessage('system', '💬 已切换到单模型对话模式。');
    }
  }

  state.currentFleetSessionId = null;
  showToast(state.fleetMode ? '已开启 Agent 集群协作模式' : '已切换到单模型对话模式', 'success');
}

function restoreFleetMode() {
  if (localStorage.getItem('js-fleet-mode') === '1') {
    state.fleetMode = true;
    const singleIndicator = document.getElementById('mode-indicator-single');
    const fleetIndicator = document.getElementById('mode-indicator-fleet');
    const modeSelect = document.getElementById('fleet-mode-select');
    const toggleLabel = document.getElementById('mode-toggle-label');
    const input = document.getElementById('chat-input');
    if (singleIndicator) singleIndicator.classList.add('hidden');
    if (fleetIndicator) fleetIndicator.classList.remove('hidden');
    if (modeSelect) modeSelect.classList.remove('hidden');
    if (toggleLabel) toggleLabel.textContent = '切换至单模型';
    if (input) input.placeholder = '输入复杂任务，多个AI Agent会分工协作完成...';
    const container = document.getElementById('chat-messages');
    if (container && container.children.length === 0) {
      appendMessage('system', '🚀 Agent 集群协作模式。输入复杂任务，多个AI Agent会分工协作完成。');
    }
  }
}

function _configuredModelCatalog() {
  const models = Array.isArray(state.availableModels) ? state.availableModels : [];
  return models.filter((model) => model && !model.isPreset);
}

function _allowMessageSubmission() {
  const input = document.getElementById('chat-input');
  if (!state.modelCatalogHasSnapshot) {
    if (state.modelCatalogStatus === 'error') {
      showToast('模型列表加载失败，请重新加载后再发送；草稿和附件已保留', 'error');
    } else {
      showToast('模型列表正在加载，完成前不会发送；草稿和附件已保留', 'warning');
    }
    refreshChatEmptyState();
    input?.focus();
    return false;
  }
  if (_configuredModelCatalog().length === 0) {
    showToast('请先配置模型；草稿和附件已保留', 'warning');
    refreshChatEmptyState();
    input?.focus();
    return false;
  }
  return true;
}

function sendMessage() {
  const input = document.getElementById('chat-input');
  if (!input) return;
  const text = input.value.trim();
  if (!text && state.pendingAttachments.length === 0) return;
  // This guard must remain before every UI, socket and attachment mutation.
  // A healthy=true snapshot is intentionally not required: configured models
  // with unknown/stale health are still adjudicated by the backend.
  if (!_allowMessageSubmission()) return;

  // Build display text with attachment names
  let displayText = text || '';
  if (state.pendingAttachments.length > 0) {
    const attNames = state.pendingAttachments.map(a => `[${a.name}]`).join(' ');
    displayText = (text ? text + ' ' : '') + attNames;
  }

  // Fleet mode: multi-agent collaboration
  if (state.fleetMode) {
    if (state.activeFleetRun) return;
    if (!state.fleetWS || state.fleetWS.readyState !== WebSocket.OPEN) {
      connectFleetWS();
      appendMessage('system', '正在建立协作连接，请稍候再试...');
      return;
    }
    input.value = '';
    appendMessage('user', displayText);

    const modeSelect = document.getElementById('fleet-mode-select');
    const mode = modeSelect ? modeSelect.value : 'auto';
    const requestId = freshClientId('fleet-request');
    const turnId = freshClientId('fleet-turn');
    const sessionId = state.currentFleetSessionId || freshClientId('fleet-session');
    state.fleetGeneration += 1;
    state.activeFleetRun = {
      request_id: requestId,
      turn_id: turnId,
      generation: state.fleetGeneration,
      session_id: sessionId,
    };
    setStreaming(true);

    if (state.currentFleetSessionId) {
      state.fleetWS.send(JSON.stringify({
        type: 'continue',
        task: text,
        session_id: state.currentFleetSessionId,
        request_id: requestId,
        turn_id: turnId,
      }));
    } else {
      state.fleetWS.send(JSON.stringify({
        type: 'collaborate',
        task: text,
        subtasks: [],
        mode: mode,
        request_id: requestId,
        turn_id: turnId,
        session_id: sessionId,
      }));
    }
    clearAttachments();
    return;
  }

  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    appendMessage('system', '连接已断开，请等待重连或刷新页面');
    return;
  }
  if (state.activeStream) return;

  try {
    ensureClientSessionId();
  } catch (error) {
    appendMessage('system', '当前环境无法安全创建会话，请刷新后重试');
    return;
  }

  input.value = '';
  appendMessage('user', displayText);
  showTyping();
  setStreaming(true);
  const requestId = freshClientId('request');
  const turnId = freshClientId('turn');
  state.streamGeneration += 1;
  state.activeStream = {
    requestId,
    turnId,
    runId: null,
    sessionId: state.sessionId,
    generation: state.streamGeneration,
  };

  state.ws.send(JSON.stringify({
    type: 'stream',
    content: text,
    session_id: state.sessionId,
    request_id: requestId,
    turn_id: turnId,
    model: state.selectedModel || null,
    attachments: state.pendingAttachments.map(a => a.path),
    enable_tools: true,
  }));

  // Clear attachments after sending
  clearAttachments();
}

function clearAttachments() {
  state.pendingAttachments.forEach(a => {
    if (a.previewUrl) URL.revokeObjectURL(a.previewUrl);
  });
  state.pendingAttachments = [];
  document.getElementById('attachment-bar').innerHTML = '';
  updateAttachmentBar();
}

function ensureClientSessionId() {
  if (state.sessionId) return state.sessionId;
  if (!globalThis.crypto || typeof globalThis.crypto.randomUUID !== 'function') {
    throw new Error('secure_random_unavailable');
  }
  state.sessionId = globalThis.crypto.randomUUID();
  return state.sessionId;
}

// ===== File Upload =====

function triggerFileSelect() {
  document.getElementById('file-input').click();
}

async function handleFileSelect(files) {
  if (!files || files.length === 0) return;
  const fileList = Array.from(files);

  // Show uploading message in chat
  const uploadMsgId = 'upload-msg-' + Date.now();
  showUploadingMessage(uploadMsgId, fileList.length);

  // Upload all files in parallel
  const results = await Promise.all(fileList.map(file => uploadFileInternal(file)));

  // Remove uploading message
  removeUploadingMessage(uploadMsgId);

  // Collect successes
  const successes = results.filter(r => r.success);
  const failures = results.filter(r => !r.success);

  if (successes.length > 0) {
    // Add to pending attachments
    successes.forEach(r => {
      state.pendingAttachments.push(r.attachment);
      addAttachmentCard(r.attachment);
    });
    // Show in chat messages
    showAttachmentMessage(successes.map(r => r.attachment));
  }

  // Show failures
  failures.forEach(f => {
    appendMessage('system', '❌ 上传失败: ' + f.error);
  });

  // Focus input so user can type or press Enter to send
  const input = document.getElementById('chat-input');
  if (input) input.focus();
}

function detectFileType(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  if (['jpg','jpeg','png','gif','webp','bmp','svg'].includes(ext)) return 'image';
  if (['mp4','mov','avi','mkv','webm'].includes(ext)) return 'video';
  if (['mp3','wav','ogg','m4a','flac'].includes(ext)) return 'audio';
  if (['pdf','docx','txt','md','py','js','ts','json','yaml','yml','csv','html','css','xml','sh','log','go','rs','java','cpp','c','h'].includes(ext)) return 'document';
  return 'file';
}

function formatFileSize(size) {
  for (const unit of ['B','KB','MB','GB']) {
    if (size < 1024) return size.toFixed(1) + ' ' + unit;
    size /= 1024;
  }
  return size.toFixed(1) + ' TB';
}

async function uploadFileInternal(file) {
  ensureClientSessionId();
  const formData = new FormData();
  formData.append('file', file);
  formData.append('session_id', state.sessionId);

  try {
    const res = await fetch('/api/upload', { method: 'POST', body: formData });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || 'HTTP ' + res.status);
    }
    const data = await res.json();

    const fileType = detectFileType(data.saved_as);
    const attachment = {
      id: 'att-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8),
      path: data.path,
      name: data.saved_as,
      originalName: data.filename,
      type: fileType,
      size: data.size,
      contentType: data.content_type,
    };

    if (fileType === 'image') {
      attachment.previewUrl = URL.createObjectURL(file);
    }

    return { success: true, attachment };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Show uploading progress in chat messages
function showUploadingMessage(id, count) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.id = id;
  div.className = 'flex justify-start uploading-indicator';
  div.dataset.messageRole = 'system';
  div.setAttribute('role', 'status');
  div.setAttribute('aria-label', '系统消息');
  div.innerHTML = `
    <div class="msg-assistant px-4 py-2 rounded-2xl rounded-bl-md text-sm text-gray-400 flex items-center gap-2">
      <i class="fas fa-circle-notch fa-spin text-blue-400"></i>
      <span>正在上传 ${count} 个文件...</span>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  container.scrollTop = container.scrollHeight;
}

function removeUploadingMessage(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// Show uploaded files as a message in chat
function showAttachmentMessage(attachments) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = 'flex justify-start';
  div.dataset.messageRole = 'system';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', '系统消息');

  const iconMap = {
    image: ['fa-image', 'text-purple-400'],
    video: ['fa-film', 'text-red-400'],
    audio: ['fa-music', 'text-green-400'],
    document: ['fa-file-alt', 'text-yellow-400'],
    file: ['fa-file', 'text-gray-400'],
  };

  const fileItems = attachments.map(att => {
    const [iconClass, colorClass] = iconMap[att.type] || iconMap.file;
    const typeLabel = { image: '图片', video: '视频', audio: '音频', document: '文档', file: '文件' }[att.type] || '文件';
    return `
      <div class="flex items-center gap-2 py-1">
        <i class="fas ${iconClass} ${colorClass} w-4"></i>
        <span class="text-gray-200">${escapeHtml(att.name)}</span>
        <span class="text-gray-500 text-xs">${typeLabel} · ${formatFileSize(att.size)}</span>
      </div>
    `;
  }).join('');

  div.innerHTML = `
    <div class="max-w-3xl px-4 py-3 rounded-2xl rounded-bl-md bg-gray-800/60 border border-gray-700/50">
      <div class="flex items-center gap-2 mb-2 text-blue-400 text-sm font-medium">
        <i class="fas fa-paperclip"></i>
        <span>已添加 ${attachments.length} 个附件</span>
        <span class="text-gray-500 text-xs">（按 Enter 直接发送，或输入消息后一起发送）</span>
      </div>
      <div class="space-y-0.5 text-sm">
        ${fileItems}
      </div>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  container.scrollTop = container.scrollHeight;
}

function addAttachmentCard(att) {
  const bar = document.getElementById('attachment-bar');
  if (!bar) return;

  const card = document.createElement('div');
  card.id = att.id;
  card.className = 'attachment-card flex items-center gap-2 bg-gray-800/80 border border-gray-700 rounded-lg px-2.5 py-1 text-xs max-w-[220px] animate-fade-in';
  card.style.animation = 'fadeIn 0.2s ease';

  let iconHtml, nameHtml;
  if (att.type === 'uploading') {
    iconHtml = '<i class="fas fa-circle-notch fa-spin text-blue-400 flex-shrink-0"></i>';
    nameHtml = `<span class="truncate text-gray-400">${escapeHtml(att.name)}</span>`;
  } else if (att.type === 'image' && att.previewUrl) {
    iconHtml = `<img src="${att.previewUrl}" class="w-5 h-5 rounded object-cover flex-shrink-0 border border-gray-600">`;
    nameHtml = `<span class="truncate text-gray-300">${escapeHtml(att.name)}</span>`;
  } else {
    const iconMap = {
      image: 'fa-image text-purple-400',
      video: 'fa-film text-red-400',
      audio: 'fa-music text-green-400',
      document: 'fa-file-alt text-yellow-400',
      file: 'fa-file text-gray-400',
    };
    iconHtml = `<i class="fas ${iconMap[att.type] || iconMap.file} flex-shrink-0"></i>`;
    nameHtml = `<span class="truncate text-gray-300" title="${escapeHtml(att.name)} (${formatFileSize(att.size)})">${escapeHtml(att.name)}</span>`;
  }

  card.innerHTML = `${iconHtml}${nameHtml}<button type="button" data-remove-attachment class="ml-1 text-gray-500 hover:text-red-400 transition flex-shrink-0" title="移除"><i class="fas fa-times"></i></button>`;
  const removeBtn = card.querySelector('[data-remove-attachment]');
  if (removeBtn) {
    removeBtn.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      removeAttachment(att.id);
    });
  }
  bar.appendChild(card);
  updateAttachmentBar();
}

function removeAttachment(id) {
  const idx = state.pendingAttachments.findIndex(a => a.id === id);
  if (idx >= 0) {
    if (state.pendingAttachments[idx].previewUrl) {
      URL.revokeObjectURL(state.pendingAttachments[idx].previewUrl);
    }
    state.pendingAttachments.splice(idx, 1);
  }
  const card = document.getElementById(id);
  if (card) card.remove();
  updateAttachmentBar();
}

function removeAttachmentCard(id) {
  const card = document.getElementById(id);
  if (card) card.remove();
  updateAttachmentBar();
}

function updateAttachmentBar() {
  const bar = document.getElementById('attachment-bar');
  if (!bar) return;
  bar.classList.toggle('hidden', bar.children.length === 0);
}

// ===== Drag & Drop =====

function initDragDrop() {
  const overlay = document.getElementById('drag-overlay');
  if (!overlay) return;
  let dragCounter = 0;

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    document.body.addEventListener(eventName, preventDefaults, false);
    document.addEventListener(eventName, preventDefaults, false);
  });

  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  document.body.addEventListener('dragenter', (e) => {
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      dragCounter++;
      overlay.classList.remove('hidden');
    }
  });

  document.body.addEventListener('dragleave', (e) => {
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      overlay.classList.add('hidden');
    }
  });

  document.body.addEventListener('drop', (e) => {
    dragCounter = 0;
    overlay.classList.add('hidden');
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length > 0) {
      handleFileSelect(files);
      // Focus input after drop
      const input = document.getElementById('chat-input');
      if (input) input.focus();
    }
  });
}

function newSession() {
  void cancelActiveStream();
  state.sessionId = null;
  document.getElementById('chat-messages').innerHTML = '';
  appendMessage('system', '新会话已开始');
  document.dispatchEvent(new CustomEvent('js:session-updated'));
}

// ===== Session History =====
let sessionListOpen = false;

function toggleSessionList() {
  // Session history now lives in the always-visible session column.
  switchTab('chat');
  loadSessions();
}

async function loadSessions() {
  const container = document.getElementById('session-list');
  if (!container) return;
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const sessions = data.sessions || [];
    container.replaceChildren();
    if (sessions.length === 0) {
      container.appendChild(el('div', {
        className: 'wcp-empty',
        text: '暂无历史会话',
      }));
      return;
    }
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const groups = [
      { label: '今天', items: [] },
      { label: '更早', items: [] },
    ];
    for (const s of sessions) {
      const sessionId = sanitizeRuntimeId(s.session_id);
      if (!sessionId) continue;
      let ts = 0;
      const raw = s.created_at;
      if (typeof raw === 'number') {
        ts = raw > 1e12 ? raw : raw * 1000;
      } else if (typeof raw === 'string') {
        const parsed = Date.parse(raw);
        ts = Number.isNaN(parsed) ? 0 : parsed;
      }
      groups[ts >= startOfToday ? 0 : 1].items.push({ s, sessionId, ts });
    }
    for (const group of groups) {
      if (!group.items.length) continue;
      container.appendChild(el('div', { className: 'session-group-label', text: group.label }));
      for (const { s, sessionId, ts } of group.items) {
        const summary = String(s.summary || '无摘要').replace(/\n/g, ' ').slice(0, 40);
        const isActive = sessionId === state.sessionId;
        const row = el('div', {
          className: `session-item${isActive ? ' session-active' : ''}`,
          attrs: { title: summary, role: 'listitem' },
          dataset: { sessionId },
        });
        const label = el('span', {
          className: 'truncate flex-1 cursor-pointer',
          text: summary + (summary.length >= 40 ? '…' : ''),
          dataset: { sessionId },
        });
        onDataClick(label, 'sessionId', (sid) => { switchSession(sid); });
        row.appendChild(label);
        if (ts) {
          const d = new Date(ts);
          const timeText = ts >= startOfToday
            ? d.toTimeString().slice(0, 5)
            : `${d.getMonth() + 1}月${d.getDate()}日`;
          row.appendChild(el('span', { className: 'session-time', text: timeText }));
        }
        const delBtn = el('button', {
          className: 'session-del',
          attrs: { title: '删除会话', type: 'button', 'aria-label': '删除会话' },
          dataset: { sessionId },
          text: '×',
        });
        onDataClick(delBtn, 'sessionId', (sid) => { deleteSession(sid); });
        row.appendChild(delBtn);
        container.appendChild(row);
      }
    }
  } catch (e) {
    container.replaceChildren();
    container.appendChild(el('div', {
      className: 'wcp-empty',
      text: '加载失败',
    }));
  }
}

async function switchSession(sid) {
  await cancelActiveStream();
  state.sessionId = sid;
  switchTab('chat');
  const container = document.getElementById('chat-messages');
  container.innerHTML = '';

  // Load historical messages
  showLoading('chat-messages', '加载历史消息...');
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(sid) + '/messages');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const messages = data.messages || [];
    container.innerHTML = '';
    if (messages.length === 0) {
      // Empty session — auto-delete and refresh list
      appendMessage('system', '该会话为空，已自动清理');
      try {
        await fetch('/api/sessions/' + encodeURIComponent(sid), { method: 'DELETE' });
        if (state.sessionId === sid) state.sessionId = null;
      } catch (e) {
        console.error('Auto-delete empty session failed:', e);
      }
    } else {
      for (const m of messages) {
        if (m.role === 'user') {
          appendMessage('user', m.content || '');
        } else if (m.role === 'assistant') {
          appendMessage('assistant', m.content || '');
        }
      }
    }
  } catch (e) {
    container.innerHTML = '';
    appendMessage('system', '加载历史消息失败: ' + e.message);
  }
  document.dispatchEvent(new CustomEvent('js:session-updated'));
  loadSessions(); // refresh active highlight
}

async function deleteSession(sid) {
  if (!confirm('确定彻底删除该会话吗？此操作不可恢复。')) return;
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(sid), { method: 'DELETE' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    if (state.sessionId === sid) {
      state.sessionId = null;
      document.getElementById('chat-messages').innerHTML = '';
      appendMessage('system', '会话已删除');
    }
    showToast('会话已删除');
    loadSessions();
  } catch (e) {
    showToast('删除失败: ' + e.message, 'error');
  }
}

async function applyCapabilityManifest() {
  try {
    let manifest = null;
    const res = await fetch('/api/capabilities');
    if (res.ok) {
      manifest = await res.json();
      state.capabilities = manifest;
    }
    const appshellRes = await fetch('/api/appshell/capabilities');
    if (appshellRes.ok) {
      state.appShellCapabilities = await appshellRes.json();
      state.activeProduct = state.appShellCapabilities.active_mode === 'work'
        ? 'js-work'
        : 'js-agent';
    } else if (manifest && manifest.product_id) {
      // Standalone compatibility only; this value never selects a parent child.
      state.activeProduct = manifest.product_id;
    }
    updateProductSwitcherUI();
    applyProductMode(state.activeProduct);
    if (!manifest) return;
    const enabled = new Set(manifest.enabled_tabs || []);
    document.querySelectorAll('nav button[id^="nav-"]').forEach((btn) => {
      const tabId = btn.id.slice(4);
      if (!tabId || tabId === 'chat') return;
      const allowed = enabled.has(tabId);
      btn.classList.toggle('hidden', !allowed);
      btn.setAttribute('aria-disabled', allowed ? 'false' : 'true');
      btn.dataset.capabilityEnabled = allowed ? '1' : '0';
    });
  } catch (err) {
    console.error('[capabilities] failed to apply manifest', err);
  }
}

function _availableAppShellModes(appshell = state.appShellCapabilities) {
  const modes = new Set();
  if (appshell && Array.isArray(appshell.available_modes)) {
    appshell.available_modes.forEach((mode) => {
      if (mode === 'personal' || mode === 'work') modes.add(mode);
    });
  }
  if (appshell && appshell.mode_roles && typeof appshell.mode_roles === 'object') {
    Object.keys(appshell.mode_roles).forEach((mode) => {
      if (mode === 'personal' || mode === 'work') modes.add(mode);
    });
  }
  return modes;
}

let _workPrewarmArmed = false;

function _productModeLabel(product) {
  return product === 'js-work' ? 'Work' : 'Personal';
}

function _setSwitcherBusy(busy, targetProduct) {
  const group = document.getElementById('product-switcher');
  const personalBtn = document.getElementById('product-personal-btn');
  const workBtn = document.getElementById('product-work-btn');
  if (group) group.setAttribute('aria-busy', busy ? 'true' : 'false');
  [personalBtn, workBtn].forEach((btn) => {
    if (!btn) return;
    const isTarget = (targetProduct === 'js-work' && btn.id === 'product-work-btn')
      || (targetProduct === 'js-agent' && btn.id === 'product-personal-btn');
    btn.classList.toggle('seg-loading', Boolean(busy && isTarget));
    if (busy) {
      btn.disabled = true;
    }
  });
}

function _beginSwitchChrome(toProduct) {
  _setSwitcherBusy(true, toProduct);
  showModeSwitchOverlay(_productModeLabel(toProduct));
}

function _restoreSwitchChrome() {
  _setSwitcherBusy(false);
  hideModeSwitchOverlay({ immediate: true });
  updateProductSwitcherUI();
}

async function prewarmWorkRuntime() {
  try {
    await fetch('/api/appshell/prewarm', { method: 'POST' });
  } catch (_) { /* hover hint; switch still boots inline */ }
}

function armWorkPrewarm() {
  if (_workPrewarmArmed) return;
  const workBtn = document.getElementById('product-work-btn');
  if (!workBtn || workBtn.hidden) return;
  _workPrewarmArmed = true;
  const fire = () => { prewarmWorkRuntime(); };
  workBtn.addEventListener('pointerenter', fire, { once: true });
  workBtn.addEventListener('focus', fire, { once: true });
}

function updateProductSwitcherUI() {
  const personalBtn = document.getElementById('product-personal-btn');
  const workBtn = document.getElementById('product-work-btn');
  const botsBtn = document.getElementById('product-bots-btn');
  if (!personalBtn || !workBtn) return;
  const active = state.activeProduct || (state.capabilities && state.capabilities.product_id) || 'js-agent';
  const mark = (btn, on) => {
    btn.classList.toggle('seg-active', on);
  };
  const workAllowed = _availableAppShellModes().has('work');
  workBtn.hidden = !workAllowed;
  workBtn.disabled = !workAllowed;
  workBtn.setAttribute('aria-hidden', workAllowed ? 'false' : 'true');
  const botsAllowed = active !== 'js-work' && !(state.capabilities && state.capabilities.tabs && state.capabilities.tabs.bots && state.capabilities.tabs.bots.enabled === false);
  if (botsBtn) {
    botsBtn.hidden = !botsAllowed;
    botsBtn.setAttribute('aria-hidden', botsAllowed ? 'false' : 'true');
    if (!botsAllowed && isBotsSurface()) exitBotsSurface();
  }
  const botsOn = isBotsSurface();
  mark(personalBtn, active === 'js-agent' && !botsOn);
  mark(workBtn, active === 'js-work');
  if (botsBtn) mark(botsBtn, botsOn);
  if (workAllowed) armWorkPrewarm();
}

const APP_SHELL_SWITCH_ERRORS = Object.freeze({
  work_role_required: '当前账号没有工作模式权限',
  active_mode_conflict: '模式状态已变化，请刷新后重试',
  mode_already_active: '当前已经处于该模式',
  invalid_work_workspace_handle: '工作区绑定已变化，请刷新后重试',
  personal_workspace_must_be_null: 'Personal 模式工作区状态异常，请刷新后重试',
  session_binding_mismatch: '当前会话不属于此模式，请新建会话后重试',
  session_owner_mismatch: '当前会话身份已变化，请重新登录',
  old_websocket_close_timeout: '旧模式仍在清理，请稍后重试',
  old_websocket_close_failed: '旧模式连接未能安全关闭，请重新打开 JS Agent',
  old_epoch_drain_timeout: '旧模式任务仍在退出，请稍后重试',
  departing_resources_not_cleared: '旧模式资源未能安全清理，请重新打开 JS Agent',
});

function _switchErrorCode(payload) {
  if (!payload || typeof payload !== 'object') return '';
  if (typeof payload.code === 'string') return payload.code;
  if (payload.detail && typeof payload.detail === 'object'
      && typeof payload.detail.code === 'string') return payload.detail.code;
  if (payload.error && typeof payload.error === 'object'
      && typeof payload.error.code === 'string') return payload.error.code;
  if (typeof payload.error === 'string' && APP_SHELL_SWITCH_ERRORS[payload.error]) {
    return payload.error;
  }
  return '';
}

function _safeSwitchError(payload, status) {
  const code = _switchErrorCode(payload);
  if (code && APP_SHELL_SWITCH_ERRORS[code]) return APP_SHELL_SWITCH_ERRORS[code];
  if (status === 401) return '登录状态已失效，请重新登录';
  if (status === 403) return '当前账号无权切换模式';
  if (status === 409) return '模式状态已变化，请刷新后重试';
  if (status >= 500) return '本地服务暂时无法完成切换，请稍后重试';
  return '无法切换模式，请检查当前状态后重试';
}

function clearAppShellUiCache(keys) {
  const list = Array.isArray(keys) ? keys : [];
  // Drop in-memory transient state for the departing product.
  state.sessionId = null;
  state.streamBuffer = '';
  state.pendingAttachments = [];
  state.currentBubble = null;
  state.currentFleetSessionId = null;
  state.fleetAgents = {};
  if (state.ws) {
    try { state.ws.onclose = null; state.ws.close(); } catch (e) { /* ignore */ }
    state.ws = null;
  }
  if (state.fleetWS) {
    try { state.fleetWS.onclose = null; state.fleetWS.close(); } catch (e) { /* ignore */ }
    state.fleetWS = null;
  }
  const messages = document.getElementById('chat-messages');
  if (messages) messages.innerHTML = '';
  list.forEach((key) => {
    if (typeof key === 'string' && key.startsWith('product:')) {
      /* departing product marker — already cleared above */
    }
  });
}

function switchBotsSurface() {
  if (state.activeProduct === 'js-work' || (state.capabilities && state.capabilities.product_id === 'js-work')) {
    showToast('Work 模式不提供 Bots 表面', 'error');
    return;
  }
  if (isBotsSurface()) return;
  enterBotsSurface();
  updateProductSwitcherUI();
}

async function switchProductWorkspace(toProduct) {
  if (toProduct === 'js-agent' && isBotsSurface()) {
    exitBotsSurface();
    updateProductSwitcherUI();
    return;
  }
  const appshell = state.appShellCapabilities;
  const currentMode = appshell && appshell.active_mode;
  const current = currentMode === 'work' ? 'js-work' : 'js-agent';
  if (toProduct === current && !isBotsSurface()) return;
  if (toProduct !== 'js-agent' && toProduct !== 'js-work') {
    showToast('不支持的 JS Agent 模式', 'error');
    return;
  }
  if (toProduct === 'js-work' && !_availableAppShellModes(appshell).has('work')) {
    showToast('当前账号没有工作模式权限', 'error');
    updateProductSwitcherUI();
    return;
  }
  if (!appshell || !appshell.workspace_handles) {
    showToast('当前服务未启用 AppShell 模式切换', 'error');
    return;
  }
  const toMode = toProduct === 'js-work' ? 'work' : 'personal';
  const workspaceHandle = toMode === 'work'
    ? appshell.workspace_handles.work
    : null;
  _beginSwitchChrome(toProduct);
  let switchBody;
  try {
    const res = await fetch('/api/appshell/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        expected_from_mode: currentMode,
        to_mode: toMode,
        session_id: state.sessionId || null,
        workspace_handle: workspaceHandle,
      }),
    });
    const responseText = await res.text();
    try {
      switchBody = responseText ? JSON.parse(responseText) : null;
    } catch (_) {
      switchBody = null;
    }
    if (!res.ok) {
      showToast('工作区切换失败：' + _safeSwitchError(switchBody, res.status), 'error');
      _restoreSwitchChrome();
      return;
    }
  } catch (err) {
    showToast('工作区切换请求失败，请登录当前模式后重试', 'error');
    _restoreSwitchChrome();
    return;
  }

  if (!switchBody || switchBody.ok !== true) {
    showToast('工作区切换失败: 服务器未确认切换', 'error');
    _restoreSwitchChrome();
    return;
  }
  const rawTarget = switchBody.target_path;
  let targetUrl;
  try {
    if (typeof rawTarget !== 'string' || !rawTarget.startsWith('/') || rawTarget.startsWith('//')) {
      throw new Error('missing same-origin target path');
    }
    targetUrl = new URL(rawTarget, window.location.origin);
    if (targetUrl.origin !== window.location.origin) {
      throw new Error('cross-origin target rejected');
    }
  } catch (err) {
    showToast('工作区切换失败: 服务器目标地址无效', 'error');
    _restoreSwitchChrome();
    return;
  }

  clearAppShellUiCache(switchBody.clear_ui_cache_keys || []);
  state.activeProduct = toProduct;
  state.appShellCapabilities = {
    ...appshell,
    active_mode: toMode,
    workspace: workspaceHandle,
  };
  writeSwitchHandoff(toProduct);
  // Re-enter the same root; the parent principal selects the child runtime.
  window.location.href = targetUrl.toString();
}

function switchTab(tab) {
  const caps = state.capabilities;
  if (caps && Array.isArray(caps.enabled_tabs) && !caps.enabled_tabs.includes(tab)) {
    showToast(`当前产品未启用「${tab}」能力`, 'error');
    return;
  }
  // Hide all tabs, remove flex from chat
  document.querySelectorAll('.tab-content').forEach(el => {
    el.classList.add('hidden');
    el.classList.remove('flex');
  });
  // Show target tab
  const target = document.getElementById(`tab-${tab}`);
  if (target) {
    target.classList.remove('hidden');
    if (tab === 'chat' || tab === 'bots') {
      target.classList.add('flex');
    }
  }
  // Update nav highlighting (rail + more menu)
  document.querySelectorAll('#nav-rail button.rail-item').forEach((btn) => {
    btn.classList.toggle('shell-active', btn.getAttribute('data-tab') === tab);
  });
  document.querySelectorAll('#more-menu button').forEach((btn) => {
    btn.classList.toggle('shell-active', btn.id === `nav-${tab}`);
  });
  state.currentTab = tab;

  if (tab === 'files') loadFiles();
  if (tab === 'memory') loadMemory();
  if (tab === 'audit') loadAudit();
  if (tab === 'approvals') loadApprovals();
  if (tab === 'status') loadStatus();
  if (tab === 'dashboard') loadDashboard();
  if (tab === 'skills') loadSkills();
  if (tab === 'agents') loadAgents();
  if (tab === 'evolution') loadEvolution();
  if (tab === 'models') { loadModels(); loadCloudPresets().catch(e => console.error('[switchTab] loadCloudPresets failed:', e)); }
  if (tab === 'tasks') loadTasks();
  if (tab === 'scenarios') loadScenarios();
  if (tab === 'friends') loadFriends();
  if (tab === 'search') loadSearch();
  if (tab === 'stats') loadStats();
}

// Dashboard state
let dashboardTimer = null;

state.currentSkillId = null;


// ═══════════════════════════════════════════════════════════════
//  Simplified Fleet Collaboration
// ═══════════════════════════════════════════════════════════════
let fleetReconnectDelay = 3000;

const ROLE_META = {
  worker:   { label: '执行', icon: 'fa-hammer', color: '#3b82f6', bg: 'bg-blue-500' },
  reviewer: { label: '审查', icon: 'fa-eye', color: '#eab308', bg: 'bg-yellow-500' },
};

function getRoleMeta(role) { return ROLE_META[role] || ROLE_META.worker; }

function connectFleetWS() {
  if (state.fleetWS && state.fleetWS.readyState === WebSocket.OPEN) return;
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  // Cookie is sent automatically by the browser — no query param needed.
  const socket = new WebSocket(`${protocol}//${window.location.host}/ws/fleet`);
  state.fleetWS = socket;

  socket.onopen = () => {
    if (state.fleetWS !== socket) return;
    fleetReconnectDelay = 3000;
    const el = document.getElementById('fleet-conn-status');
    if (el) el.innerHTML = '<span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> <span class="text-green-400">已连接</span>';
  };

  socket.onclose = () => {
    if (state.fleetWS !== socket) return;
    state.fleetGeneration += 1;
    state.activeFleetRun = null;
    state.fleetWS = null;
    setStreaming(false);
    const el = document.getElementById('fleet-conn-status');
    if (el) el.innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500"></span> <span class="text-red-400">断开</span>';
    setTimeout(connectFleetWS, fleetReconnectDelay);
    fleetReconnectDelay = Math.min(fleetReconnectDelay * 1.5, 30000);
  };

  socket.onerror = () => {
    if (state.fleetWS !== socket) return;
    const el = document.getElementById('fleet-conn-status');
    if (el) el.innerHTML = '<span class="w-2 h-2 rounded-full bg-yellow-500"></span> <span class="text-yellow-400">错误</span>';
  };

  socket.onmessage = (e) => {
    if (state.fleetWS !== socket) return;
    let data;
    try { data = JSON.parse(e.data); } catch (err) { return; }
    handleFleetEvent(data);
  };
}

// ===== Fleet WeChat-style Group Chat =====

const FLEET_ROLE_COLORS = {
  worker:   { bg: 'bg-blue-500',    text: 'text-blue-400',    hex: '#3b82f6', label: '执行' },
  reviewer: { bg: 'bg-yellow-500',  text: 'text-yellow-400',  hex: '#eab308', label: '审查' },
};

function getFleetRoleColor(role) {
  if (FLEET_ROLE_COLORS[role]) return FLEET_ROLE_COLORS[role];
  // Generate consistent color from role name
  const colors = [
    { bg: 'bg-green-500',   text: 'text-green-400',   hex: '#22c55e' },
    { bg: 'bg-purple-500',  text: 'text-purple-400',  hex: '#a855f7' },
    { bg: 'bg-pink-500',    text: 'text-pink-400',    hex: '#ec4899' },
    { bg: 'bg-orange-500',  text: 'text-orange-400',  hex: '#f97316' },
    { bg: 'bg-cyan-500',    text: 'text-cyan-400',    hex: '#06b6d4' },
    { bg: 'bg-red-500',     text: 'text-red-400',     hex: '#ef4444' },
    { bg: 'bg-indigo-500',  text: 'text-indigo-400',  hex: '#6366f1' },
    { bg: 'bg-teal-500',    text: 'text-teal-400',    hex: '#14b8a6' },
  ];
  let hash = 0;
  for (let i = 0; i < role.length; i++) hash = role.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

function getFleetRoleInitial(role) {
  return (role.charAt(0).toUpperCase() || 'A');
}
// ===== Fleet / Multi-Agent Collaboration =====

state.currentFleetSessionId = null;

const FLEET_RUN_EVENT_TYPES = new Set([
  'agent_start', 'agent_done', 'collaborate_progress', 'agent_thinking',
  'agent_token', 'agent_tool_call', 'agent_tool_result', 'agent_usage',
  'agent_error', 'review_done', 'collaborate_result', 'cancelled', 'error',
]);

function acceptActiveFleetFrame(data) {
  if (!data || !FLEET_RUN_EVENT_TYPES.has(data.type)) return true;
  const active = state.activeFleetRun;
  if (!active || active.generation !== state.fleetGeneration) return false;
  if (typeof data.request_id !== 'string' || data.request_id !== active.request_id
      || typeof data.turn_id !== 'string' || data.turn_id !== active.turn_id
      || typeof data.session_id !== 'string' || data.session_id !== active.session_id) {
    return false;
  }
  return true;
}

function finishActiveFleetRun() {
  state.activeFleetRun = null;
  setStreaming(false);
}

function handleFleetEvent(data) {
  if (!state.fleetMode) return;
  if (data.type === 'status') {
    if (data.data && data.data.agents) {
      data.data.agents.forEach(a => { state.fleetAgents[a.id] = a; });
    }
    renderFleetRoleStatuses();
    return;
  }
  if (!acceptActiveFleetFrame(data)) return;
  if (data.type === 'agent_start') {
    updateFleetMemberStatus(data.agent_id, data.agent_name, data.agent_role, 'busy', data.task_description);
    if (!state.fleetMode) return;
    return;
  }
  if (data.type === 'agent_done') {
    updateFleetMemberStatus(data.agent_id, data.agent_name, data.agent_role, 'idle', '');
    if (!state.fleetMode) return;
    const statusText = data.status === 'done' ? '完成' : '失败';
    const statusColor = data.status === 'done' ? 'text-green-400' : 'text-red-400';
    appendFleetAgentMessage(data.agent_id, data.agent_name, data.agent_role, data.result, statusText, statusColor);
    return;
  }
  // Only render remaining chat messages when in fleet mode
  if (!state.fleetMode) return;
  if (data.type === 'collaborate_progress') {
    appendFleetSystemMessage(data.message);
    return;
  }
  if (data.type === 'agent_thinking') {
    appendFleetThinkingMessage(data.agent_name, data.agent_role, data.content);
    return;
  }
  if (data.type === 'agent_token') {
    // PR-4.4: live final-response text deltas. Re-use the system-message
    // append path with the agent's role tag so the dashboard shows tokens
    // streaming in. The aggregated final result still arrives via
    // agent_done -> appendFleetAgentMessage.
    const agentName = data.agent_name || data.agent_role || 'Agent';
    appendFleetSystemMessage(
      `[${agentName}] ${data.content}`,
      'assistant',
      `JS Agent 协作成员 ${agentName}`,
    );
    return;
  }
  if (data.type === 'agent_tool_call') {
    appendFleetToolCallMessage(data.agent_name, data.agent_role, data.tool_name, data.arguments);
    return;
  }
  if (data.type === 'agent_tool_result') {
    appendFleetToolResultMessage(data.agent_name, data.agent_role, data.tool_name, data.preview, data.success);
    return;
  }
  if (data.type === 'agent_usage') {
    // PR-4.4: structured usage from the in-stream usage event. Stashed for
    // diagnostics — UI display is intentionally deferred to avoid churn.
    state.fleetLastUsage = state.fleetLastUsage || {};
    if (data.agent_id) state.fleetLastUsage[data.agent_id] = data.usage || {};
    return;
  }
  if (data.type === 'agent_error') {
    // PR-4.4: streaming error from the provider. Surface as a system line
    // so operators see the failure before the agent_done frame arrives.
    const agentName = data.agent_name || 'Agent';
    appendFleetSystemMessage(
      `[${agentName}] 流式错误: ${data.content || ''}`,
      'assistant',
      `JS Agent 协作成员 ${agentName}`,
    );
    return;
  }
  if (data.type === 'review_done') {
    if (data.review) appendFleetReviewerMessage(data.review);
    return;
  }
  if (data.type === 'collaborate_result') {
    showCollaborateResult(data);
    finishActiveFleetRun();
    return;
  }
  if (data.type === 'cancelled') {
    appendFleetSystemMessage('协作任务已取消');
    finishActiveFleetRun();
    return;
  }
  if (data.type === 'error') {
    appendFleetSystemMessage('协作任务失败，请稍后重试');
    finishActiveFleetRun();
    return;
  }
}

// sendFleetChatMessage / sendFleetChatMessageFromMain removed — Fleet uses unified #chat-input via sendMessage()

function showCollaborateResult(data) {
  state.currentFleetSessionId = data.session_id || null;
  const container = document.getElementById('chat-messages');
  if (!container) return;

  const subtaskCount = data.subtasks ? Object.keys(data.subtasks).length : 0;
  const subtaskItems = data.subtasks ? Object.entries(data.subtasks).map(([desc, result], i) => `
    <details class="group">
      <summary class="cursor-pointer flex items-center gap-2 text-xs text-gray-400 hover:text-gray-300 py-1">
        <i class="fas fa-chevron-right text-[10px] group-open:rotate-90 transition-transform"></i>
        <span>子任务 ${i + 1}</span>
      </summary>
      <div class="pl-4 text-xs text-gray-300 mt-1 border-l-2 border-gray-700">${escapeHtml(result.substring(0, 300))}${result.length > 300 ? '...' : ''}</div>
    </details>
  `).join('') : '';

  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', 'JS Agent 协作结果');
  div.innerHTML = `
    <div class="w-8 h-8 rounded-full bg-green-500 flex-shrink-0 flex items-center justify-center text-white text-xs font-bold">结</div>
    <div class="max-w-[80%]">
      <div class="flex items-baseline gap-2 mb-0.5">
        <span class="text-xs font-medium text-gray-300">协作结果</span>
        <span class="text-[10px] text-green-400">${subtaskCount} 个子任务</span>
      </div>
      <div class="bg-gray-800 border border-green-800/30 text-gray-200 px-4 py-2.5 rounded-2xl rounded-tl-md text-sm markdown">${renderMarkdown(data.final || '无结果')}</div>
      ${data.review ? `<div class="mt-1 text-[10px] text-yellow-500"><i class="fas fa-eye mr-1"></i>已审查</div>` : ''}
      ${subtaskItems ? `<div class="mt-2 pt-2 border-t border-gray-700 space-y-1">${subtaskItems}</div>` : ''}
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();

  showToast('协作完成', 'success');
}

async function loadFleetSessionToChat(sessionId) {
  const sessionIdSafe = sanitizeRuntimeId(sessionId);
  if (!sessionIdSafe) {
    showToast('会话标识无效，无法加载', 'error');
    return;
  }
  try {
    const res = await fetch('/api/fleet/sessions/' + encodeURIComponent(sessionIdSafe));
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const session = data.session;
    if (!session || sanitizeRuntimeId(session.session_id) !== sessionIdSafe) {
      throw new Error('invalid session response');
    }

    const container = document.getElementById('chat-messages');
    if (!container) return;
    container.innerHTML = '';
    state.currentFleetSessionId = sessionIdSafe;
    state.fleetMode = true;
    restoreFleetMode();

    appendFleetSystemMessage('─── 历史会话 ───');
    appendFleetUserMessage(session.main_task);

    const subtaskResults = session.subtask_results || {};
    (session.subtasks || []).forEach((sub, idx) => {
      const result = subtaskResults[sub] || '';
      if (result) {
        appendFleetAgentMessage('sub-' + idx, 'Agent', 'worker', result, '完成', 'text-green-400');
      }
    });

    if (session.review) appendFleetReviewerMessage(session.review);

    if (session.final) {
      const div = document.createElement('div');
      div.className = 'flex justify-start gap-2';
      div.dataset.messageRole = 'assistant';
      div.setAttribute('role', 'article');
      div.setAttribute('aria-label', 'JS Agent 协作历史结果');
      div.innerHTML = `
        <div class="w-8 h-8 rounded-full bg-green-500 flex-shrink-0 flex items-center justify-center text-white text-xs font-bold">结</div>
        <div class="max-w-[80%]">
          <div class="bg-gray-800 border border-green-800/30 text-gray-200 px-4 py-2.5 rounded-2xl rounded-tl-md text-sm markdown">${renderMarkdown(session.final)}</div>
        </div>
      `;
      container.appendChild(div);
    }

    appendFleetSystemMessage('─── 输入消息继续对话 ───');
    scrollFleetChatToBottom();
    showToast('已加载历史会话', 'success');
  } catch (e) {
    showToast('加载会话失败', 'error');
  }
}

async function refreshFleetHistory() {
  const container = document.getElementById('fleet-history-list');
  if (!container) return;
  container.setAttribute('role', 'list');
  container.setAttribute('aria-label', '协作历史');
  try {
    const res = await fetch('/api/fleet/history');
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const items = data.history || [];
    if (items.length === 0) {
      container.innerHTML = '<div class="text-gray-600 text-xs p-2">暂无记录</div>';
      return;
    }
    container.innerHTML = items.map(item => {
      const sessionId = sanitizeRuntimeId(item.session_id);
      if (!sessionId) return '';
      const taskLabel = String(item.main_task || '未命名协作');
      return `
      <div class="fleet-conv-item group rounded-lg hover:bg-gray-800/50 transition relative"
           role="listitem" data-session-id="${escapeHtml(sessionId)}">
        <button class="fleet-open-btn block w-full rounded-lg px-2 py-1.5 pr-8 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-500"
                type="button" aria-label="打开协作历史：${escapeHtml(taskLabel)}">
          <div class="text-xs text-gray-300 truncate">${escapeHtml(taskLabel)}</div>
          <div class="flex items-center gap-1 mt-0.5">
            <span class="text-[10px] text-gray-500">${item.subtask_count} 子任务</span>
            ${item.has_review ? '<span class="text-[10px] text-yellow-500">已审查</span>' : ''}
            <span class="text-[10px] text-gray-600 ml-auto">${new Date(item.created_at * 1000).toLocaleDateString()}</span>
          </div>
        </button>
        <button class="fleet-delete-btn absolute top-1.5 right-1.5 min-w-6 min-h-6 text-[10px] text-gray-500 hover:text-red-400 opacity-70 hover:opacity-100 transition-opacity px-1 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-400"
                type="button" aria-label="删除协作历史：${escapeHtml(taskLabel)}">
          <i class="fas fa-trash"></i>
        </button>
      </div>
    `;
    }).join('');
    if (!container.querySelector('.fleet-conv-item')) {
      container.innerHTML = '<div class="text-gray-600 text-xs p-2">暂无有效记录</div>';
      return;
    }
    // 事件委托：点击列表项加载会话，点击删除按钮删除会话
    container.onclick = function(e) {
      const target = e.target instanceof Element ? e.target : null;
      const action = target?.closest('.fleet-open-btn, .fleet-delete-btn');
      const item = action?.closest('.fleet-conv-item');
      if (!action || !item) return;
      const sessionId = item.dataset.sessionId;
      if (!sessionId) return;
      if (action.classList.contains('fleet-delete-btn')) {
        e.stopPropagation();
        deleteFleetSession(sessionId);
      } else {
        loadFleetSessionToChat(sessionId);
      }
    };
  } catch (e) {
    container.innerHTML = '<div class="text-gray-600 text-xs p-2">加载失败</div>';
  }
}

async function deleteFleetSession(sessionId) {
  const sessionIdSafe = sanitizeRuntimeId(sessionId);
  if (!sessionIdSafe) {
    showToast('会话标识无效，无法删除', 'error');
    return;
  }
  if (!confirm('确定删除这条记录吗？')) return;
  try {
    const res = await fetch('/api/fleet/sessions/' + encodeURIComponent(sessionIdSafe), { method: 'DELETE' });
    if (!res.ok) throw new Error('API error');
    showToast('已删除', 'success');
    refreshFleetHistory();
    if (state.currentFleetSessionId === sessionIdSafe) {
      state.currentFleetSessionId = null;
      const container = document.getElementById('chat-messages');
      if (container) {
        container.innerHTML = '';
      }
    }
  } catch (e) {
    showToast('删除失败，请稍后重试', 'error');
  }
}

async function loadFleetSessionDetail(sessionId) {
  const sessionIdSafe = sanitizeRuntimeId(sessionId);
  if (!sessionIdSafe) {
    showToast('会话标识无效，无法加载详情', 'error');
    return;
  }
  try {
    const res = await fetch('/api/fleet/sessions/' + encodeURIComponent(sessionIdSafe));
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const session = data.session;
    if (!session || sanitizeRuntimeId(session.session_id) !== sessionIdSafe) {
      throw new Error('invalid session response');
    }

    const detail = document.getElementById('fleet-session-detail');
    const content = document.getElementById('fleet-session-detail-content');
    if (!detail || !content) return;

    let html = `<div class="text-gray-300 font-medium mb-1">${escapeHtml(session.main_task)}</div>`;
    html += '<div class="space-y-2">';
    const subtaskResults = session.subtask_results || {};
    (session.subtasks || []).forEach((sub, idx) => {
      const result = subtaskResults[sub] || '无结果';
      html += `
        <div class="bg-gray-800 rounded-lg p-2">
          <div class="text-xs text-blue-400 font-medium mb-1">子任务 ${idx + 1}</div>
          <div class="text-xs text-gray-400 mb-1">${escapeHtml(sub)}</div>
          <div class="text-xs text-gray-300">${escapeHtml(result.substring(0, 300))}${result.length > 300 ? '...' : ''}</div>
        </div>
      `;
    });
    html += '</div>';
    if (session.review) {
      html += `<div class="mt-2 bg-yellow-900/20 border border-yellow-800 rounded-lg p-2">
        <div class="text-xs text-yellow-500 font-medium mb-1">审查意见</div>
        <div class="text-xs text-gray-300">${escapeHtml(session.review.substring(0, 300))}${session.review.length > 300 ? '...' : ''}</div>
      </div>`;
    }
    if (session.final) {
      html += `<article class="mt-2 bg-green-900/20 border border-green-800 rounded-lg p-2"
          data-message-role="assistant" aria-label="JS Agent 协作历史结果">
        <div class="text-xs text-green-400 font-medium mb-1">最终结果</div>
        <div class="text-xs text-gray-300">${escapeHtml(session.final)}</div>
      </article>`;
    }

    content.innerHTML = html;
    const actions = el('div', { className: 'mt-3 flex gap-2' });
    const sessionIdSafe = sanitizeRuntimeId(session.session_id);
    if (sessionIdSafe) {
      const continueBtn = el('button', {
        className: 'text-xs bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded transition',
        attrs: { type: 'button' },
        dataset: { sessionId: sessionIdSafe },
      });
      continueBtn.appendChild(el('i', { className: 'fas fa-reply mr-1' }));
      continueBtn.appendChild(document.createTextNode('继续对话'));
      onDataClick(continueBtn, 'sessionId', (id) => {
        loadFleetSessionToChat(id);
        detail.classList.add('hidden');
      });
      const deleteBtn = el('button', {
        className: 'text-xs bg-red-900/40 hover:bg-red-900/60 text-red-300 px-3 py-1.5 rounded transition',
        attrs: { type: 'button' },
        dataset: { sessionId: sessionIdSafe },
      });
      deleteBtn.appendChild(el('i', { className: 'fas fa-trash mr-1' }));
      deleteBtn.appendChild(document.createTextNode('删除'));
      onDataClick(deleteBtn, 'sessionId', (id) => {
        deleteFleetSession(id);
        detail.classList.add('hidden');
      });
      actions.appendChild(continueBtn);
      actions.appendChild(deleteBtn);
    }
    content.appendChild(actions);
    detail.classList.remove('hidden');
  } catch (e) {
    showToast('加载详情失败', 'error');
  }
}

// ===== Fleet UI Helpers =====

function appendFleetSystemMessage(text, role = 'system', sender = '系统消息') {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'flex justify-center';
  div.dataset.messageRole = role;
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', sender);
  div.innerHTML = `<div class="bg-gray-800/50 rounded-lg px-3 py-1.5 text-xs text-gray-500">${escapeHtml(text)}</div>`;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function appendFleetUserMessage(text) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'flex justify-end';
  div.dataset.messageRole = 'user';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', '你');
  div.innerHTML = `
    <div class="max-w-[75%]">
      <div class="bg-blue-600 text-white px-4 py-2.5 rounded-2xl rounded-br-md text-sm">${escapeHtml(text)}</div>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function appendFleetAgentMessage(agentId, agentName, agentRole, result, statusText, statusColor) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', `JS Agent 协作成员 ${agentName || 'Agent'}`);
  div.innerHTML = `
    <div class="w-8 h-8 rounded-full ${color.bg} flex-shrink-0 flex items-center justify-center text-white text-xs font-bold">${getFleetRoleInitial(agentRole)}</div>
    <div class="max-w-[75%]">
      <div class="flex items-baseline gap-2 mb-0.5">
        <span class="text-xs font-medium text-gray-300">${escapeHtml(agentName)}</span>
        <span class="text-[10px] ${statusColor}">${statusText}</span>
      </div>
      <div class="bg-gray-800 border border-gray-700 text-gray-200 px-4 py-2.5 rounded-2xl rounded-tl-md text-sm markdown">${renderMarkdown(result)}</div>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function appendFleetReviewerMessage(review) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', 'JS Agent 审查员');
  div.innerHTML = `
    <div class="w-8 h-8 rounded-full bg-yellow-500 flex-shrink-0 flex items-center justify-center text-white text-xs font-bold">审</div>
    <div class="max-w-[75%]">
      <div class="flex items-baseline gap-2 mb-0.5">
        <span class="text-xs font-medium text-gray-300">审查员</span>
        <span class="text-[10px] text-yellow-400">已审查</span>
      </div>
      <div class="bg-yellow-900/20 border border-yellow-800 text-yellow-200 px-4 py-2.5 rounded-2xl rounded-tl-md text-sm">${escapeHtml(review)}</div>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function appendFleetThinkingMessage(agentName, agentRole, content) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2 my-1';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', `JS Agent 协作成员 ${agentName || 'Agent'} 思考`);
  div.innerHTML = `
    <div class="w-7 h-7 rounded-full ${color.bg} flex-shrink-0 flex items-center justify-center text-white text-[10px] font-bold">${getFleetRoleInitial(agentRole)}</div>
    <div class="max-w-[75%]">
      <div class="flex items-baseline gap-2 mb-0.5">
        <span class="text-xs font-medium text-gray-300">${escapeHtml(agentName)}</span>
        <span class="text-[10px] text-blue-400">思考中</span>
      </div>
      <details class="group">
        <summary class="cursor-pointer text-[10px] text-gray-500 hover:text-gray-400 flex items-center gap-1">
          <i class="fas fa-brain text-blue-400 mr-1"></i>查看推理过程
        </summary>
        <div class="bg-gray-900/50 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-400 mt-1 font-mono whitespace-pre-wrap">${escapeHtml(content)}</div>
      </details>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function appendFleetToolCallMessage(agentName, agentRole, toolName, args) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2 my-0.5';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', `JS Agent 协作成员 ${agentName || 'Agent'} 工具调用`);
  div.innerHTML = `
    <div class="w-7 h-7 rounded-full ${color.bg} flex-shrink-0 flex items-center justify-center text-white text-[10px] font-bold">${getFleetRoleInitial(agentRole)}</div>
    <div class="max-w-[75%]">
      <div class="flex items-center gap-1.5 text-[10px] text-gray-500">
        <i class="fas fa-wrench text-orange-400"></i>
        <span>${escapeHtml(agentName)} 调用 <span class="text-orange-300 font-mono">${escapeHtml(toolName)}</span></span>
      </div>
      <div class="text-[10px] text-gray-600 font-mono truncate">${escapeHtml(args)}</div>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function appendFleetToolResultMessage(agentName, agentRole, toolName, preview, success) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const statusIcon = success ? '<i class="fas fa-check text-green-400 text-[8px]"></i>' : '<i class="fas fa-times text-red-400 text-[8px]"></i>';
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2 my-0.5';
  div.dataset.messageRole = 'assistant';
  div.setAttribute('role', 'article');
  div.setAttribute('aria-label', `JS Agent 协作成员 ${agentName || 'Agent'} 工具结果`);
  div.innerHTML = `
    <div class="w-7 h-7 rounded-full ${color.bg} flex-shrink-0 flex items-center justify-center text-white text-[10px] font-bold">${getFleetRoleInitial(agentRole)}</div>
    <div class="max-w-[75%]">
      <div class="flex items-center gap-1.5 text-[10px]">
        ${statusIcon}
        <span class="text-gray-500">${escapeHtml(toolName)} 结果</span>
      </div>
      <div class="text-[10px] text-gray-600 truncate">${escapeHtml(preview)}</div>
    </div>
  `;
  container.appendChild(div);
  document.dispatchEvent(new CustomEvent('js:chat-content-changed'));
  scrollFleetChatToBottom();
}

function scrollFleetChatToBottom() {
  const container = document.getElementById('chat-messages');
  if (container) container.scrollTop = container.scrollHeight;
}

function renderFleetRoleStatuses() {
  // Update status indicators on each role card based on runtime state.fleetAgents
  const agents = Object.values(state.fleetAgents);
  if (agents.length === 0) {
    // No runtime agents yet — reset all status dots to gray
    document.querySelectorAll('.fleet-status-dot').forEach(el => {
      el.className = 'fleet-status-dot absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-gray-600 border-2 border-gray-900';
    });
    document.querySelectorAll('.fleet-status-text').forEach(el => {
      el.textContent = '未运行';
      el.className = 'fleet-status-text text-[10px] text-gray-600';
    });
    document.querySelectorAll('.fleet-task-text').forEach(el => el.textContent = '');
    return;
  }
  agents.forEach(a => {
    const card = document.querySelector(`.fleet-role-card[data-role="${CSS.escape(a.role)}"]`);
    if (!card) return;
    const dot = card.querySelector('.fleet-status-dot');
    const statusText = card.querySelector('.fleet-status-text');
    const taskText = card.querySelector('.fleet-task-text');
    if (dot) {
      const color = a.status === 'idle' ? 'bg-green-400' : a.status === 'busy' ? 'bg-blue-400' : 'bg-red-400';
      dot.className = `fleet-status-dot absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ${color} border-2 border-gray-900`;
    }
    if (statusText) {
      const text = a.status === 'idle' ? '空闲' : a.status === 'busy' ? '运行中' : '错误';
      const cls = a.status === 'idle' ? 'text-green-400' : a.status === 'busy' ? 'text-blue-400' : 'text-red-400';
      statusText.textContent = text;
      statusText.className = `fleet-status-text text-[10px] ${cls}`;
    }
    if (taskText) {
      taskText.textContent = a.task || '';
    }
  });
}

function updateFleetMemberStatus(agentId, agentName, agentRole, status, task) {
  state.fleetAgents[agentId] = { id: agentId, name: agentName, role: agentRole, status, task };
  renderFleetRoleStatuses();
}

function addFleetRoleCard(roleName, modelId, label, colorClass) {
  const container = document.getElementById('fleet-model-config');
  if (!container) return;
  const id = 'fleet-role-' + (roleName || 'custom-' + Date.now());
  const div = document.createElement('div');
  div.className = 'fleet-role-card border border-gray-700 rounded-lg p-3';
  div.dataset.role = roleName || '';
  div.id = id;
  const safeLabel = escapeHtml(label || roleName || '自定义角色');
  const bg = colorClass || 'bg-gray-500';
  const initial = getFleetRoleInitial(roleName || 'A');
  div.innerHTML = `
    <div class="flex items-center gap-3">
      <div class="relative flex-shrink-0">
        <div class="w-8 h-8 rounded-full ${bg} flex items-center justify-center text-white text-xs font-bold">${initial}</div>
        <div class="fleet-status-dot absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-gray-600 border-2 border-gray-900"></div>
      </div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2">
          <input type="text" value="${safeLabel}" class="fleet-role-label bg-transparent border-none text-xs text-gray-300 font-medium focus:outline-none px-0 w-24" placeholder="角色名">
          <span class="fleet-status-text text-[10px] text-gray-600">未运行</span>
        </div>
        <div class="fleet-task-text text-[10px] text-gray-600 truncate"></div>
      </div>
      <select class="fleet-role-model bg-gray-800 border border-gray-700 rounded text-xs text-gray-200 px-2 py-1 focus:outline-none focus:border-blue-500">
        <option value="">默认模型</option>
      </select>
      <button type="button" data-remove-fleet-role class="text-red-400 hover:text-red-300 text-xs flex-shrink-0"><i class="fas fa-times"></i></button>
    </div>
  `;
  const labelInput = div.querySelector('.fleet-role-label');
  if (labelInput) {
    labelInput.addEventListener('change', () => renameFleetRole(id, labelInput.value));
  }
  const modelSelect = div.querySelector('.fleet-role-model');
  if (modelSelect) {
    modelSelect.addEventListener('change', () => saveFleetModelConfig());
  }
  const removeBtn = div.querySelector('[data-remove-fleet-role]');
  if (removeBtn) {
    removeBtn.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      removeFleetRoleCard(id);
    });
  }
  container.appendChild(div);
  populateFleetRoleSelect(div.querySelector('.fleet-role-model'), modelId);
  refreshFleetSubtaskRoles();
  renderFleetRoleStatuses();
}

function removeFleetRoleCard(id) {
  const card = document.getElementById(id);
  if (card) card.remove();
  saveFleetModelConfig();
  refreshFleetSubtaskRoles();
}

function renameFleetRole(id, newLabel) {
  const card = document.getElementById(id);
  if (!card) return;
  // 支持中文及 Unicode 角色名
  let roleValue = newLabel.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^\p{L}\p{N}_-]/gu, '');
  if (!roleValue) {
    // 如果清理后为空（纯特殊字符），保留原始输入作为后备
    roleValue = newLabel.trim().replace(/\s+/g, '-');
  }
  if (!roleValue) {
    showToast('角色名不能为空', 'error');
    return;
  }
  card.dataset.role = roleValue;
  saveFleetModelConfig();
  refreshFleetSubtaskRoles();
}

function refreshFleetSubtaskRoles() {
  const options = buildFleetRoleOptions();
  document.querySelectorAll('.fleet-subtask-role').forEach(sel => {
    const current = sel.value;
    sel.innerHTML = options;
    if (current) {
      for (let i = 0; i < sel.options.length; i++) {
        if (sel.options[i].value === current) { sel.value = current; break; }
      }
    }
  });
}

let _fleetAvailableModels = [];

function populateFleetRoleSelect(selectEl, selectedModel) {
  if (!selectEl) return;
  selectEl.innerHTML = '<option value="">默认模型</option>' +
    _fleetAvailableModels.map(m => `<option value="${escapeHtml(m.id)}" ${m.id === selectedModel ? 'selected' : ''}>${escapeHtml(m.model_name || m.id)}</option>`).join('');
}

async function loadFleetModelOptions() {
  try {
    const res = await fetch('/api/agents/config');
    if (!res.ok) return;
    const data = await res.json();
    _fleetAvailableModels = data.available_models || [];
    const cfg = data.config || {};

    const container = document.getElementById('fleet-model-config');
    if (container) container.innerHTML = '';

    addFleetRoleCard('worker', cfg.worker || '', '执行 Agent', 'bg-blue-500');
    addFleetRoleCard('reviewer', cfg.reviewer || '', '审查 Agent', 'bg-yellow-500');

    const known = new Set(['worker', 'reviewer']);
    Object.entries(cfg).forEach(([role, model]) => {
      if (!known.has(role) && role) {
        addFleetRoleCard(role, model || '', role.charAt(0).toUpperCase() + role.slice(1), 'bg-gray-500');
      }
    });
  } catch (e) {
    console.error('Failed to load fleet model options:', e);
  }
}

async function saveFleetModelConfig() {
  const cards = document.querySelectorAll('#fleet-model-config .fleet-role-card');
  const config = {};
  cards.forEach(card => {
    const role = card.dataset.role;
    const model = card.querySelector('.fleet-role-model')?.value || '';
    if (role) config[role] = model;
  });
  try {
    const res = await fetch('/api/agents/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config }),
    });
    if (!res.ok) throw new Error('API error');
    showToast('模型分配已保存');
  } catch (e) {
    showToast('保存失败', 'error');
  }
}

// ---- Window mounts for HTML onclick/onchange compatibility ----
function openCommandPalette() {
  openPalette();
}

const _windowFuncs = {
  showToast, escapeHtml, toggleSidebar, renderMarkdown,
  switchTab, sendMessage, toggleFleetMode, newSession, toggleSessionList,
  loadDashboard, loadFiles, loadMemory, loadSkills, loadEvolution, loadStats, loadSearch, doSearch, runEvolutionNow,
  refreshSessionCapsule, clearSessionCapsule,
  discoverModels, saveProvider, testCloudProvider, toggleAddProvider,
  addCloudProvider, onCloudPresetChange, switchModel, deleteProvider,
  addFleetRoleCard, removeFleetRoleCard, renameFleetRole, saveFleetModelConfig,
  loadAgents, populateFleetRoleSelect, refreshFleetSubtaskRoles,
  showAddSemanticModal, submitSemanticMemory, searchSemantic, editSemanticMemory,
  deleteSemanticMemory, saveSemanticMemory, recoverEmbedder, showMemoryAudit,
  openMemoryFileEditor, closeMemoryFileEditor, saveMemoryFile,
  loadBlockTree, loadBlockMemories, verifyMemory, toggleSearchScope,
  toggleBlockExpand, openBlockDelete, openBlockMove, openBlockMerge,
  onBlockTargetChange, submitBlockModal, closeBlockModal,
  loadProposals, approveProposal, rejectProposal, approveAllProposals,
  organizeNow, openProposalEdit, closeProposalEdit, saveProposalEdit,
  confirmModalYes, closeConfirmModal,
  showSkillDetail, closeSkillModal, uninstallSkill, updateTrust,
  showWizard, hideWizard, wizardNext, wizardPrev, wizardComplete, wizardSkip, wizardSelectModel,
  loadWizardModels, checkFirstStart, resetWizard, testWizardModel,
  renderWizardNoModels, renderWizardCloudHint,
  loadWizardCloudPresets, onWizardCloudChange, testWizardCloud, addWizardCloud,
  showCronCreateModal, hideCronCreateModal, submitCronJob, refreshCronJobs,
  runCronJob, deleteCronJob, toggleCronJob, parseCronNatural, onCronTemplateChange,
  loadCronTemplates, renderCronJobs, triggerFileSelect, handleFileSelect,
  loadSessions, switchSession, deleteSession, setCurrentModel,
  refreshFleetHistory, loadFleetSessionToChat, loadFleetSessionDetail, deleteFleetSession,
  loadCloudPresets, loadAudit, loadStatus, loadModels,
  loadApprovals, startApprovalsPolling, stopApprovalsPolling,
  loadTasks,
  loadScenarios, startScenario, fillScenarioPrompt,
  loadFriends, createFriendInvite, acceptFriendInvite, completeFriendInvite, blockFriend, revokeFriend,
  sendFriendMessage, sendFriendTask,
  decideEvolutionProposal,
  saveApiKey,
  openCommandPalette: openPalette,
  updateProviderKey, hideProviderKeyModal, submitProviderKeyUpdate,
  switchProductWorkspace, updateProductSwitcherUI, clearAppShellUiCache,
  switchBotsSurface,
};
Object.entries(_windowFuncs).forEach(([k, v]) => { if (typeof v === 'function') window[k] = v; });

// Hook: refresh cron jobs when tab is shown
const _origSwitchTab = window.switchTab;
window.switchTab = function(tab) {
  if (_origSwitchTab) _origSwitchTab(tab);
  if (tab === 'cron') {
    refreshCronJobs();
  }
  if (tab === 'bots' && !isBotsSurface()) {
    enterBotsSurface();
    updateProductSwitcherUI();
  }
};

// ---- Bootstrap: initialize on page load ----
restoreApiKey();
// Headless/e2e Hosts may place the local bootstrap key in #bootstrap-api-key=.
// The desktop app uses #bootstrap= via the Tauri sidecar. Fragments never enter
// HTTP request or proxy logs; remove them immediately after use.
const bootstrapParams = new URLSearchParams(window.location.hash.slice(1));
const bootstrapKey = bootstrapParams.get('bootstrap-api-key');
const desktopBootstrapToken = bootstrapParams.get('bootstrap');
const DESKTOP_BOOTSTRAP_FAILURE_KEY = 'js-desktop-bootstrap-failed';

function hasDesktopBootstrapFailure() {
  try {
    return sessionStorage.getItem(DESKTOP_BOOTSTRAP_FAILURE_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function setDesktopBootstrapFailure(failed) {
  try {
    if (failed) sessionStorage.setItem(DESKTOP_BOOTSTRAP_FAILURE_KEY, '1');
    else sessionStorage.removeItem(DESKTOP_BOOTSTRAP_FAILURE_KEY);
  } catch (_) { /* sessionStorage may be unavailable in hardened webviews */ }
}

function clearBootstrapFragment(name) {
  bootstrapParams.delete(name);
  const remainingHash = bootstrapParams.toString();
  history.replaceState(
    null,
    '',
    window.location.pathname + window.location.search + (remainingHash ? '#' + remainingHash : '')
  );
}

function renderDesktopBootstrapFailure(kind) {
  const shell = document.getElementById('app-shell');
  const failure = document.getElementById('bootstrap-failure');
  if (shell) {
    shell.inert = true;
    shell.setAttribute('aria-hidden', 'true');
  }
  if (!failure) return;
  const isKey = kind === 'key';
  const desktopDesc = document.getElementById('bootstrap-failure-description-desktop');
  const keyDesc = document.getElementById('bootstrap-failure-description-key');
  const desktopGuide = document.getElementById('bootstrap-recovery-guidance-desktop');
  const keyGuide = document.getElementById('bootstrap-recovery-guidance-key');
  if (desktopDesc) desktopDesc.classList.toggle('hidden', isKey);
  if (keyDesc) keyDesc.classList.toggle('hidden', !isKey);
  if (desktopGuide) desktopGuide.classList.toggle('hidden', isKey);
  if (keyGuide) keyGuide.classList.toggle('hidden', !isKey);
  failure.setAttribute(
    'aria-describedby',
    isKey ? 'bootstrap-failure-description-key' : 'bootstrap-failure-description-desktop'
  );
  failure.classList.remove('hidden');
  failure.focus();
}

async function initApp() {
  if (desktopBootstrapToken) {
    // The native parent supplied this 256-bit, 60-second, single-use token via
    // sidecar stdin. Exchange it only with the same-origin parent Host, then
    // clear the fragment before any WebSocket or other application request.
    try {
      const response = await fetch('/api/appshell/desktop-bootstrap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: desktopBootstrapToken }),
      });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      setDesktopBootstrapFailure(false);
    } catch (error) {
      // A native bootstrap token is single-use. Persist only a boolean failure
      // marker for this WebView session so reload cannot silently fall back to
      // a different identity path or retry the consumed secret.
      setDesktopBootstrapFailure(true);
      throw error;
    } finally {
      clearBootstrapFragment('bootstrap');
    }
  } else if (bootstrapKey) {
    // Exchange the target bootstrap key for an HttpOnly session cookie
    // BEFORE opening the WebSocket, which authenticates via that cookie.
    // On failure keep the fragment so reload can retry this reusable key.
    const exchanged = await saveApiKey(bootstrapKey);
    if (!exchanged) throw new Error('bootstrap key exchange failed');
    clearBootstrapFragment('bootstrap-api-key');
  } else if (hasDesktopBootstrapFailure()) {
    throw new Error('native desktop bootstrap requires a fresh app launch');
  } else {
    // A fresh direct-loopback AppShell has no child login to fall back to.
    // The parent either reuses the existing HttpOnly session, creates the one
    // shared recovery identity, or rejects because an explicit login exists.
    try {
      await fetch('/api/appshell/bootstrap', { method: 'POST' });
    } catch (e) { /* standalone / existing-login compatibility */ }
  }
  connectWS();
  initDragDrop();
  checkFirstStart();
  await applyCapabilityManifest();
  initShell();
  initWorkContext();
  initBotsSurface();
  refreshModelHint();
  loadSessions();
  loadApprovals();
  startApprovalsPolling();
  // Load model list eagerly so the top-bar dropdown is usable immediately
  // without requiring the user to visit the Models tab first.
  loadModels();
  finishSwitchHandoff();
}
initApp().catch(() => {
  // Never surface the token, filesystem paths, response body or raw exception.
  console.error('[bootstrap] local identity exchange failed');
  const kind = (desktopBootstrapToken || hasDesktopBootstrapFailure()) ? 'desktop' : 'key';
  renderDesktopBootstrapFailure(kind);
});

// Bind Enter key on chat input
const chatInput = document.getElementById('chat-input');
if (chatInput) {
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
}

const chatStopButton = document.getElementById('chat-stop-button');
if (chatStopButton) {
  chatStopButton.addEventListener('click', async (e) => {
    e.preventDefault();
    await cancelActiveStream({ reportFailure: true });
  });
}

const chatSendButton = document.getElementById('chat-send-button');
if (chatSendButton) {
  const submitFromButton = (e) => {
    e.preventDefault();
    sendMessage();
  };
  chatSendButton.addEventListener('click', submitFromButton);
}
