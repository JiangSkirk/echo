import { state } from './state/store.js';
import { escapeHtml, showToast, toggleSidebar, showLoading, showError } from './utils/dom.js';
import { renderMarkdown } from './utils/markdown.js';
import { loadStats } from './tabs/stats.js';
import { loadSearch, doSearch } from './tabs/search.js';
import { loadDashboard } from './tabs/dashboard.js';
import { loadEvolution, runEvolutionNow } from './tabs/evolution.js';
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
import { loadTasks, pauseTask, resumeTask, deleteTask, startTasksPolling } from './tabs/tasks.js';
import { loadScenarios, startScenario, fillScenarioPrompt } from './tabs/scenarios.js';
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

let wizardStep = state.wizardStep;
let wizardSelectedModel = state.wizardSelectedModel;

// ═══════════════════════════════════════════════════════════════
//  Global fetch wrapper — injects X-API-Key for all API calls
// ═══════════════════════════════════════════════════════════════
const _origFetch = window.fetch;
window.fetch = async function(url, options = {}) {
  if (typeof url === 'string' && url.startsWith('/api/')) {
    options = structuredClone ? structuredClone(options) : JSON.parse(JSON.stringify(options));
    options.headers = options.headers || {};
    if (!options.headers['X-API-Key'] && state.apiKey) {
      options.headers['X-API-Key'] = state.apiKey;
    }
  }
  return _origFetch(url, options);
};

function saveApiKey(key) {
  state.apiKey = key.trim();
  localStorage.setItem('js-api-key', state.apiKey);
  // Mirror to cookie so WebSocket can authenticate without
  // leaking the key in the URL (browser history, server logs, referrers).
  if (state.apiKey) {
    document.cookie = 'x-api-key=' + encodeURIComponent(state.apiKey) + '; path=/; SameSite=Strict';
  } else {
    document.cookie = 'x-api-key=; path=/; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  }
  const input = document.getElementById('api-key-input');
  if (input) input.value = state.apiKey;
  showToast(state.apiKey ? 'API Key 已保存' : 'API Key 已清除');
}

function restoreApiKey() {
  // Prefer localStorage, fall back to cookie (e.g. after hard refresh)
  if (!state.apiKey) {
    const m = document.cookie.match(/(?:^|; )x-api-key=([^;]*)/);
    if (m) {
      try {
        state.apiKey = decodeURIComponent(m[1]);
      } catch (e) {
        state.apiKey = m[1];
      }
    }
  }
  const input = document.getElementById('api-key-input');
  if (input && state.apiKey) input.value = state.apiKey;
}

async function checkFirstStart() {
  // Skip if already completed locally
  if (localStorage.getItem('js-wizard-completed') === 'true') return;
  try {
    const res = await fetch('/api/setup/first-start');
    if (!res.ok) return;
    const data = await res.json();
    if (!data.first_run_completed) {
      showWizard();
    } else {
      localStorage.setItem('js-wizard-completed', 'true');
    }
  } catch (e) {
    console.error('Failed to check first-start status:', e);
  }
}

async function resetWizard() {
  localStorage.removeItem('js-wizard-completed');
  try {
    await fetch('/api/setup/reset', { method: 'POST' });
    showWizard();
    showToast('设置向导已重置');
  } catch (e) {
    showToast('重置失败: ' + e.message, 'error');
  }
}

function showWizard() {
  wizardStep = 1;
  wizardSelectedModel = '';
  document.getElementById('setup-wizard').classList.remove('hidden');
  document.getElementById('wizard-step-1').classList.remove('hidden');
  document.getElementById('wizard-step-2').classList.add('hidden');
  document.getElementById('wizard-step-3').classList.add('hidden');
}

function hideWizard() {
  document.getElementById('setup-wizard').classList.add('hidden');
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
      loadWizardModels();
      wizardStep = 2;
    } else if (step2 && !step2.classList.contains('hidden')) {
      if (!wizardSelectedModel) {
        showToast('请先选择一个模型', 'warning');
        return;
      }
      step2.classList.add('hidden');
      step3.classList.remove('hidden');
      const model = state.availableModels.find(m => m.id === wizardSelectedModel);
      document.getElementById('wizard-selected-model').textContent = model ? (model.name || model.id) : wizardSelectedModel;
      wizardStep = 3;
    }
  } catch (e) {
    console.error('wizardNext error:', e);
    showToast('向导出错: ' + e.message, 'error');
  }
}

function wizardPrev() {
  if (wizardStep === 2) {
    document.getElementById('wizard-step-2').classList.add('hidden');
    document.getElementById('wizard-step-1').classList.remove('hidden');
    wizardStep = 1;
  }
}

async function wizardComplete() {
  try {
    if (wizardSelectedModel) {
      await switchModel(wizardSelectedModel);
    }
    const res = await fetch('/api/setup/complete', { method: 'POST' });
    try {
      const data = await res.json();
      // If the server minted an admin key on completion (and we don't already
      // have one), persist it so the now-closed bootstrap window stays usable.
      if (data && data.admin_key && !state.apiKey) {
        saveApiKey(data.admin_key);
      }
    } catch (_) {}
    localStorage.setItem('js-wizard-completed', 'true');
    hideWizard();
    showToast('设置完成，欢迎使用！');
  } catch (e) {
    showToast('完成设置失败: ' + e.message, 'error');
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
    // Configured providers
    if (data.providers) {
      data.providers.forEach(p => {
        const statusIcon = p.healthy ? '🟢' : (p.has_key ? '🔴' : '🟡');
        if (p.healthy) hasHealthyConfigured = true;
        p.models.forEach(m => {
          flatModels.push({
            id: `${p.name}/${m.id}`,
            rawId: m.id,
            name: `${p.name}/${m.name || m.id}`,
            provider: p.name,
            contextWindow: m.context_window,
            statusIcon,
            healthy: p.healthy,
            hasKey: p.has_key,
            isPreset: false,
          });
        });
      });
    }
    // Presets (not configured)
    if (data.presets) {
      data.presets.forEach(preset => {
        preset.models.forEach(m => {
          flatModels.push({
            id: `${preset.id}/${m.id}`,
            rawId: m.id,
            name: `${preset.id}/${m.name || m.id}`,
            provider: preset.id,
            contextWindow: m.context_window,
            statusIcon: '⚪',
            healthy: false,
            hasKey: false,
            isPreset: true,
          });
        });
      });
    }
    if (flatModels.length === 0) {
      container.innerHTML = renderWizardNoModels();
      document.getElementById('wizard-next-2').disabled = false;
      loadWizardCloudPresets();
      return;
    }
    container.innerHTML = flatModels.map(m => `
      <div class="flex items-center gap-2 bg-gray-800 rounded-lg px-3 py-2 border border-transparent ${wizardSelectedModel === m.id ? 'border-blue-500' : ''}" data-model-id="${escapeHtml(m.id)}">
        <label class="flex items-center gap-3 flex-1 cursor-pointer hover:bg-gray-700 transition rounded px-1 py-1">
          <input type="radio" name="wizard-model" value="${escapeHtml(m.id)}" ${wizardSelectedModel === m.id ? 'checked' : ''} onchange="wizardSelectModel('${escapeHtml(m.id)}')" class="accent-blue-500">
          <div class="flex-1 min-w-0">
            <div class="text-sm font-medium">${m.statusIcon} ${escapeHtml(m.name)}</div>
            <div class="text-xs text-gray-500">Provider: ${escapeHtml(m.provider)} · 上下文: ${m.contextWindow || '--'} tokens ${m.isPreset ? '· 未配置' : ''}</div>
          </div>
        </label>
        ${!m.isPreset ? `<button onclick="testWizardModel('${escapeHtml(m.id)}', this)" class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition whitespace-nowrap" title="测试连接">
          <i class="fas fa-bolt"></i> 测试
        </button>` : ''}
        <span id="test-result-${escapeHtml(m.id.replace(/[^a-zA-Z0-9]/g, '-'))}" class="text-xs hidden whitespace-nowrap"></span>
      </div>
    `).join('');
    document.getElementById('wizard-next-2').disabled = !wizardSelectedModel;
    loadWizardCloudPresets();
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-sm">加载模型失败: ' + escapeHtml(e.message) + '</div>';
    document.getElementById('wizard-next-2').disabled = false;
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
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>测试中...';

  try {
    const res = await fetch('/api/providers/test-cloud', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset_id: presetId, api_key: apiKey })
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || '连接失败: HTTP ' + res.status);
    }
    const data = await res.json();
    sucEl.textContent = '✅ 连接成功！发现 ' + (data.models?.length || 0) + ' 个模型';
    sucEl.classList.remove('hidden');
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-bolt mr-1"></i>测试连接';
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
    <div class="mt-4 text-center">
      <button onclick="hideWizard(); switchTab('models');" class="text-sm text-blue-400 hover:text-blue-300 underline">前往模型设置手动添加</button>
    </div>
  `;
}

function renderWizardCloudHint() {
  return `
    <div class="bg-blue-900/30 border border-blue-700/50 rounded-lg p-3 mt-2">
      <div class="text-sm font-medium text-blue-300 mb-2"><i class="fas fa-cloud mr-1"></i> 没有本地模型？快速添加云模型：</div>
      <div class="flex flex-wrap gap-2">
        <button onclick="hideWizard(); switchTab('models'); setTimeout(() => document.getElementById('cloud-preset-select').value='deepseek', 100);" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700 transition">DeepSeek</button>
        <button onclick="hideWizard(); switchTab('models'); setTimeout(() => document.getElementById('cloud-preset-select').value='openai', 100);" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700 transition">OpenAI</button>
        <button onclick="hideWizard(); switchTab('models'); setTimeout(() => document.getElementById('cloud-preset-select').value='kimi-cn', 100);" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700 transition">Kimi</button>
      </div>
    </div>
  `;
}

async function testWizardModel(modelId, btnEl) {
  const resultId = 'test-result-' + modelId.replace(/[^a-zA-Z0-9]/g, '-');
  const resultEl = document.getElementById(resultId);
  if (!resultEl) return;

  btnEl.disabled = true;
  btnEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
  resultEl.classList.remove('hidden');
  resultEl.textContent = '测试中...';
  resultEl.className = 'text-xs text-gray-400 whitespace-nowrap';

  try {
    const res = await fetch('/api/setup/test-model', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_id: modelId }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.ok) {
      resultEl.innerHTML = `<span class="text-green-400">🟢 可用 (${data.latency_ms}ms)</span>`;
      // Auto-select this model after successful test
      wizardSelectModel(modelId);
      const safeId = modelId.replace(/"/g, '\\"');
      const radio = document.querySelector('input[name="wizard-model"][value="' + safeId + '"]');
      if (radio) radio.checked = true;
    } else {
      resultEl.innerHTML = `<span class="text-red-400">🔴 ${escapeHtml(data.error || '连接失败')}</span>`;
    }
  } catch (e) {
    resultEl.innerHTML = `<span class="text-red-400">🔴 ${escapeHtml(e.message)}</span>`;
  } finally {
    btnEl.disabled = false;
    btnEl.innerHTML = '<i class="fas fa-bolt"></i> 测试';
  }
}

function wizardSelectModel(modelId) {
  wizardSelectedModel = modelId;
  document.getElementById('wizard-next-2').disabled = false;
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
  state.ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
  state.ws.onopen = () => {
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> <span class="text-green-400">已连接</span>';
  };
  state.ws.onclose = () => {
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500"></span> <span class="text-red-400">断开 - 重连中...</span>';
    setTimeout(connectWS, 3000);
  };
  state.ws.onerror = () => {
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-yellow-500"></span> <span class="text-yellow-400">连接错误</span>';
  };
  state.ws.onmessage = (e) => {
    let data;
    try {
      data = JSON.parse(e.data);
    } catch (err) {
      console.error('WebSocket JSON parse error:', err);
      return;
    }
    if (data.type === 'token') {
      appendToken(data.content);
    } else if (data.type === 'response') {
      state.sessionId = data.session_id;
      finishResponse(data.content, data.model);
    } else if (data.type === 'done') {
      if (data.session_id) state.sessionId = data.session_id;
      finishStream();
    } else if (data.type === 'status') {
      showTyping();
    } else if (data.type === 'progress') {
      showProgress(data.tool, data.preview);
    } else if (data.type === 'error') {
      appendMessage('system', '错误: ' + data.content);
    }
  };
}

function appendMessage(role, content, model) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = `flex ${role === 'user' ? 'justify-end' : 'justify-start'}`;
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
  div.innerHTML = `<div class="msg-assistant px-4 py-3 rounded-2xl rounded-bl-md flex gap-1"><span class="typing-dot w-2 h-2 bg-gray-400 rounded-full"></span><span class="typing-dot w-2 h-2 bg-gray-400 rounded-full"></span><span class="typing-dot w-2 h-2 bg-gray-400 rounded-full"></span></div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function showProgress(tool, preview) {
  const container = document.getElementById('chat-messages');
  let indicator = document.getElementById('typing-indicator');
  if (!indicator) {
    indicator = document.createElement('div');
    indicator.id = 'typing-indicator';
    indicator.className = 'flex justify-start';
    container.appendChild(indicator);
  }
  const toolLabels = {
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
  };
  const label = toolLabels[tool] || ('正在执行: ' + tool);
  const previewText = preview ? preview.substring(0, 60) : '';
  indicator.innerHTML = `<div class="msg-assistant px-4 py-2 rounded-2xl rounded-bl-md text-sm text-gray-300">${escapeHtml(label)}${previewText ? ' — ' + escapeHtml(previewText) : ''}</div>`;
  container.scrollTop = container.scrollHeight;
}

state.currentBubble = null;
state.streamBuffer = '';
state.inThinking = false;
state.thinkingBuffer = '';
state.responseBuffer = '';
state.thinkingBlock = null;
state.responseSpan = null;
state.tokenRAF = null;

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
        if (state.thinkingBlock) {
          const tc = state.thinkingBlock.querySelector('.thinking-content');
          if (tc) tc.textContent = state.thinkingBuffer;
        }
      } else {
        state.responseBuffer += remaining;
        if (!state.responseSpan) {
          state.responseSpan = document.createElement('span');
          state.responseSpan.className = 'response-span';
          state.currentBubble.appendChild(state.responseSpan);
        }
        state.responseSpan.textContent = state.responseBuffer;
      }
      break;
    }

    const before = remaining.slice(0, trans.index);
    if (state.inThinking) {
      state.thinkingBuffer += before;
      if (state.thinkingBlock) {
        const tc = state.thinkingBlock.querySelector('.thinking-content');
        if (tc) tc.textContent = state.thinkingBuffer;
      }
    } else {
      state.responseBuffer += before;
      if (!state.responseSpan) {
        state.responseSpan = document.createElement('span');
        state.responseSpan.className = 'response-span';
        state.currentBubble.appendChild(state.responseSpan);
      }
      state.responseSpan.textContent = state.responseBuffer;
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

function _finalizeStreamBubble(model) {
  if (!state.currentBubble) return;
  state.currentBubble.classList.remove('typing-cursor');
  state.currentBubble.id = '';

  // Combine thinking + response and render as markdown
  let fullText = '';
  if (state.thinkingBlock) {
    const tc = state.thinkingBlock.querySelector('.thinking-content');
    if (tc) {
      const thinkText = tc.textContent;
      if (thinkText) fullText += '<think>\n' + thinkText + '\n</think>\n\n';
    }
  }
  fullText += state.responseBuffer;

  state.currentBubble.innerHTML = renderMarkdown(fullText);

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
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  if (state.tokenRAF) {
    cancelAnimationFrame(state.tokenRAF);
    state.tokenRAF = null;
  }
  if (!state.currentBubble) {
    appendMessage('assistant', content, model);
  } else {
    _finalizeStreamBubble(model);
  }
  const container = document.getElementById('chat-messages');
  container.scrollTop = container.scrollHeight;
}

function finishStream() {
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  if (state.tokenRAF) {
    cancelAnimationFrame(state.tokenRAF);
    state.tokenRAF = null;
  }
  if (state.currentBubble) {
    _finalizeStreamBubble();
  }
}

function toggleFleetMode() {
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

function sendMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text && state.pendingAttachments.length === 0) return;

  // Build display text with attachment names
  let displayText = text || '';
  if (state.pendingAttachments.length > 0) {
    const attNames = state.pendingAttachments.map(a => `[${a.name}]`).join(' ');
    displayText = (text ? text + ' ' : '') + attNames;
  }

  // Fleet mode: multi-agent collaboration
  if (state.fleetMode) {
    if (!state.fleetWS || state.fleetWS.readyState !== WebSocket.OPEN) {
      connectFleetWS();
      appendMessage('system', '正在建立协作连接，请稍候再试...');
      return;
    }
    input.value = '';
    appendMessage('user', displayText);

    const modeSelect = document.getElementById('fleet-mode-select');
    const mode = modeSelect ? modeSelect.value : 'auto';

    if (state.currentFleetSessionId) {
      state.fleetWS.send(JSON.stringify({
        type: 'continue',
        task: text,
        session_id: state.currentFleetSessionId,
      }));
    } else {
      state.fleetWS.send(JSON.stringify({
        type: 'collaborate',
        task: text,
        subtasks: [],
        mode: mode,
      }));
    }
    clearAttachments();
    return;
  }

  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    appendMessage('system', '连接已断开，请等待重连或刷新页面');
    return;
  }

  input.value = '';
  appendMessage('user', displayText);
  showTyping();

  state.ws.send(JSON.stringify({
    type: 'message',
    content: text,
    session_id: state.sessionId,
    model: state.selectedModel || null,
    attachments: state.pendingAttachments.map(a => a.path),
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
  const formData = new FormData();
  formData.append('file', file);

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
  div.innerHTML = `
    <div class="msg-assistant px-4 py-2 rounded-2xl rounded-bl-md text-sm text-gray-400 flex items-center gap-2">
      <i class="fas fa-circle-notch fa-spin text-blue-400"></i>
      <span>正在上传 ${count} 个文件...</span>
    </div>
  `;
  container.appendChild(div);
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

  card.innerHTML = `${iconHtml}${nameHtml}<button onclick="removeAttachment('${escapeHtml(att.id)}')" class="ml-1 text-gray-500 hover:text-red-400 transition flex-shrink-0" title="移除"><i class="fas fa-times"></i></button>`;
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
  state.sessionId = null;
  document.getElementById('chat-messages').innerHTML = '';
  appendMessage('system', '新会话已开始');
}

// ===== Session History =====
let sessionListOpen = false;

function toggleSessionList() {
  const list = document.getElementById('session-list');
  const chevron = document.getElementById('session-chevron');
  if (!list || !chevron) return;
  // Always switch to chat tab first
  switchTab('chat');
  sessionListOpen = !sessionListOpen;
  if (sessionListOpen) {
    list.style.maxHeight = '200px';
    list.style.opacity = '1';
    chevron.classList.add('rotate-180');
    loadSessions();
  } else {
    list.style.maxHeight = '0px';
    list.style.opacity = '0';
    chevron.classList.remove('rotate-180');
  }
}

async function loadSessions() {
  const container = document.getElementById('session-list');
  if (!container) return;
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const sessions = data.sessions || [];
    if (sessions.length === 0) {
      container.innerHTML = '<div class="px-6 py-1 text-xs text-gray-600">暂无历史会话</div>';
      return;
    }
    container.innerHTML = sessions.map(s => {
      const summary = (s.summary || '无摘要').replace(/\n/g, ' ').slice(0, 40);
      const isActive = s.session_id === state.sessionId;
      const msgCount = s.message_count || 0;
      const countBadge = msgCount > 0 ? `<span class="text-[10px] text-gray-600 ml-1">(${msgCount})</span>` : '';
      return `<div class="session-item mx-2 px-3 py-1.5 rounded text-xs flex items-center justify-between gap-1 ${isActive ? 'bg-blue-900/40 text-blue-300' : 'text-gray-400'}" title="${escapeHtml(summary)}">
        <span class="truncate flex-1 cursor-pointer" onclick='switchSession(${JSON.stringify(s.session_id)})'>${escapeHtml(summary)}${summary.length >= 40 ? '...' : ''}${countBadge}</span>
        <button onclick='event.stopPropagation(); deleteSession(${JSON.stringify(s.session_id)})' class="text-gray-600 hover:text-red-400 px-1 rounded transition" title="删除会话">
          <i class="fas fa-times text-[10px]"></i>
        </button>
      </div>`;
    }).join('');
  } catch (e) {
    container.innerHTML = '<div class="px-6 py-1 text-xs text-gray-600">加载失败</div>';
  }
}

async function switchSession(sid) {
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

function switchTab(tab) {
  // Hide all tabs, remove flex from chat
  document.querySelectorAll('.tab-content').forEach(el => {
    el.classList.add('hidden');
    el.classList.remove('flex');
  });
  // Show target tab
  const target = document.getElementById(`tab-${tab}`);
  if (target) {
    target.classList.remove('hidden');
    if (tab === 'chat') {
      target.classList.add('flex');
    }
  }
  // Update nav highlighting
  document.querySelectorAll('nav button').forEach(el => {
    el.classList.remove('text-blue-400', 'bg-gray-800/50');
  });
  const navBtn = document.getElementById(`nav-${tab}`);
  if (navBtn) navBtn.classList.add('text-blue-400', 'bg-gray-800/50');
  state.currentTab = tab;

  if (tab === 'files') loadFiles();
  if (tab === 'memory') loadMemory();
  if (tab === 'audit') loadAudit();
  if (tab === 'status') loadStatus();
  if (tab === 'dashboard') loadDashboard();
  if (tab === 'skills') loadSkills();
  if (tab === 'agents') loadAgents();
  if (tab === 'evolution') loadEvolution();
  if (tab === 'models') { loadModels(); loadCloudPresets().catch(e => console.error('[switchTab] loadCloudPresets failed:', e)); }
  if (tab === 'tasks') loadTasks();
  if (tab === 'scenarios') loadScenarios();
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
  state.fleetWS = new WebSocket(`${protocol}//${window.location.host}/ws/fleet`);

  state.fleetWS.onopen = () => {
    fleetReconnectDelay = 3000;
    const el = document.getElementById('fleet-conn-status');
    if (el) el.innerHTML = '<span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> <span class="text-green-400">已连接</span>';
  };

  state.fleetWS.onclose = () => {
    const el = document.getElementById('fleet-conn-status');
    if (el) el.innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500"></span> <span class="text-red-400">断开</span>';
    setTimeout(connectFleetWS, fleetReconnectDelay);
    fleetReconnectDelay = Math.min(fleetReconnectDelay * 1.5, 30000);
  };

  state.fleetWS.onerror = () => {
    const el = document.getElementById('fleet-conn-status');
    if (el) el.innerHTML = '<span class="w-2 h-2 rounded-full bg-yellow-500"></span> <span class="text-yellow-400">错误</span>';
  };

  state.fleetWS.onmessage = (e) => {
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

function handleFleetEvent(data) {
  if (data.type === 'status') {
    if (data.data && data.data.agents) {
      data.data.agents.forEach(a => { state.fleetAgents[a.id] = a; });
    }
    renderFleetRoleStatuses();
    return;
  }
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
  if (data.type === 'agent_tool_call') {
    appendFleetToolCallMessage(data.agent_name, data.agent_role, data.tool_name, data.arguments);
    return;
  }
  if (data.type === 'agent_tool_result') {
    appendFleetToolResultMessage(data.agent_name, data.agent_role, data.tool_name, data.preview, data.success);
    return;
  }
  if (data.type === 'review_done') {
    if (data.review) appendFleetReviewerMessage(data.review);
    return;
  }
  if (data.type === 'collaborate_result') {
    showCollaborateResult(data);
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
  scrollFleetChatToBottom();

  showToast('协作完成', 'success');
}

async function loadFleetSessionToChat(sessionId) {
  try {
    const res = await fetch('/api/fleet/sessions/' + encodeURIComponent(state.sessionId));
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const session = data.session;
    if (!session) return;

    const container = document.getElementById('chat-messages');
    if (!container) return;
    container.innerHTML = '';
    state.currentFleetSessionId = state.sessionId;
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
  try {
    const res = await fetch('/api/fleet/history');
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const items = data.history || [];
    if (items.length === 0) {
      container.innerHTML = '<div class="text-gray-600 text-xs p-2">暂无记录</div>';
      return;
    }
    container.innerHTML = items.map(item => `
      <div class="fleet-conv-item group rounded-lg px-2 py-1.5 hover:bg-gray-800/50 transition cursor-pointer relative"
           data-session-id="${escapeHtml(item.session_id)}">
        <div class="text-xs text-gray-300 truncate pr-5">${escapeHtml(item.main_task)}</div>
        <div class="flex items-center gap-1 mt-0.5">
          <span class="text-[10px] text-gray-500">${item.subtask_count} 子任务</span>
          ${item.has_review ? '<span class="text-[10px] text-yellow-500">已审查</span>' : ''}
          <span class="text-[10px] text-gray-600 ml-auto">${new Date(item.created_at * 1000).toLocaleDateString()}</span>
        </div>
        <button class="fleet-delete-btn absolute top-1.5 right-1.5 text-[10px] text-gray-500 hover:text-red-400 opacity-70 hover:opacity-100 transition-opacity px-1">
          <i class="fas fa-trash"></i>
        </button>
      </div>
    `).join('');
    // 事件委托：点击列表项加载会话，点击删除按钮删除会话
    container.onclick = function(e) {
      const item = e.target.closest('.fleet-conv-item');
      if (!item) return;
      const sessionId = item.dataset.sessionId;
      if (e.target.closest('.fleet-delete-btn')) {
        e.stopPropagation();
        deleteFleetSession(state.sessionId);
      } else {
        loadFleetSessionToChat(state.sessionId);
      }
    };
  } catch (e) {
    container.innerHTML = '<div class="text-gray-600 text-xs p-2">加载失败</div>';
  }
}

async function deleteFleetSession(sessionId) {
  if (!confirm('确定删除这条记录吗？')) return;
  try {
    const res = await fetch('/api/fleet/sessions/' + encodeURIComponent(state.sessionId), { method: 'DELETE' });
    if (!res.ok) throw new Error('API error');
    showToast('已删除', 'success');
    refreshFleetHistory();
    if (state.currentFleetSessionId === state.sessionId) {
      state.currentFleetSessionId = null;
      const container = document.getElementById('chat-messages');
      if (container) {
        container.innerHTML = '';
      }
    }
  } catch (e) {
    showToast('删除失败: ' + (e.message || ''), 'error');
  }
}

async function loadFleetSessionDetail(sessionId) {
  try {
    const res = await fetch('/api/fleet/sessions/' + encodeURIComponent(state.sessionId));
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const session = data.session;
    if (!session) return;

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
    html += `<div class="mt-3 flex gap-2">
      <button onclick="loadFleetSessionToChat('${escapeHtml(session.session_id)}'); document.getElementById('fleet-session-detail').classList.add('hidden');" class="text-xs bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded transition">
        <i class="fas fa-reply mr-1"></i>继续对话
      </button>
      <button onclick="deleteFleetSession('${escapeHtml(session.session_id)}'); document.getElementById('fleet-session-detail').classList.add('hidden');" class="text-xs bg-red-900/40 hover:bg-red-900/60 text-red-300 px-3 py-1.5 rounded transition">
        <i class="fas fa-trash mr-1"></i>删除
      </button>
    </div>`;

    content.innerHTML = html;
    detail.classList.remove('hidden');
  } catch (e) {
    showToast('加载详情失败', 'error');
  }
}

// ===== Fleet UI Helpers =====

function appendFleetSystemMessage(text) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'flex justify-center';
  div.innerHTML = `<div class="bg-gray-800/50 rounded-lg px-3 py-1.5 text-xs text-gray-500">${escapeHtml(text)}</div>`;
  container.appendChild(div);
  scrollFleetChatToBottom();
}

function appendFleetUserMessage(text) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'flex justify-end';
  div.innerHTML = `
    <div class="max-w-[75%]">
      <div class="bg-blue-600 text-white px-4 py-2.5 rounded-2xl rounded-br-md text-sm">${escapeHtml(text)}</div>
    </div>
  `;
  container.appendChild(div);
  scrollFleetChatToBottom();
}

function appendFleetAgentMessage(agentId, agentName, agentRole, result, statusText, statusColor) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2';
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
  scrollFleetChatToBottom();
}

function appendFleetReviewerMessage(review) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2';
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
  scrollFleetChatToBottom();
}

function appendFleetThinkingMessage(agentName, agentRole, content) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2 my-1';
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
  scrollFleetChatToBottom();
}

function appendFleetToolCallMessage(agentName, agentRole, toolName, args) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2 my-0.5';
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
  scrollFleetChatToBottom();
}

function appendFleetToolResultMessage(agentName, agentRole, toolName, preview, success) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const color = getFleetRoleColor(agentRole);
  const statusIcon = success ? '<i class="fas fa-check text-green-400 text-[8px]"></i>' : '<i class="fas fa-times text-red-400 text-[8px]"></i>';
  const div = document.createElement('div');
  div.className = 'flex justify-start gap-2 my-0.5';
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
          <input type="text" value="${safeLabel}" class="fleet-role-label bg-transparent border-none text-xs text-gray-300 font-medium focus:outline-none px-0 w-24" placeholder="角色名" onchange="renameFleetRole('${id}', this.value)">
          <span class="fleet-status-text text-[10px] text-gray-600">未运行</span>
        </div>
        <div class="fleet-task-text text-[10px] text-gray-600 truncate"></div>
      </div>
      <select class="fleet-role-model bg-gray-800 border border-gray-700 rounded text-xs text-gray-200 px-2 py-1 focus:outline-none focus:border-blue-500" onchange="saveFleetModelConfig()">
        <option value="">默认模型</option>
      </select>
      <button onclick="removeFleetRoleCard('${id}')" class="text-red-400 hover:text-red-300 text-xs flex-shrink-0"><i class="fas fa-times"></i></button>
    </div>
  `;
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
  showWizard, hideWizard, wizardNext, wizardPrev, wizardComplete, wizardSelectModel,
  loadWizardModels, checkFirstStart, resetWizard, testWizardModel,
  renderWizardNoModels, renderWizardCloudHint,
  loadWizardCloudPresets, onWizardCloudChange, testWizardCloud, addWizardCloud,
  showCronCreateModal, hideCronCreateModal, submitCronJob, refreshCronJobs,
  runCronJob, deleteCronJob, toggleCronJob, parseCronNatural, onCronTemplateChange,
  loadCronTemplates, renderCronJobs, triggerFileSelect, handleFileSelect,
  loadSessions, switchSession, deleteSession, setCurrentModel,
  loadCloudPresets, loadAudit, loadStatus, loadModels,
  loadTasks, pauseTask, resumeTask, deleteTask,
  loadScenarios, startScenario, fillScenarioPrompt,
  saveApiKey,
  updateProviderKey, hideProviderKeyModal, submitProviderKeyUpdate,
};
Object.entries(_windowFuncs).forEach(([k, v]) => { if (typeof v === 'function') window[k] = v; });

// Hook: refresh cron jobs when tab is shown
const _origSwitchTab = window.switchTab;
window.switchTab = function(tab) {
  if (_origSwitchTab) _origSwitchTab(tab);
  if (tab === 'cron') {
    refreshCronJobs();
  }
};

// ---- Bootstrap: initialize on page load ----
restoreApiKey();
// First run: adopt the server-injected bootstrap admin key so a fresh install
// is usable immediately without manual key entry. Only when we have none yet.
if (!state.apiKey && typeof window.__BOOTSTRAP_API_KEY__ === 'string' && window.__BOOTSTRAP_API_KEY__) {
  state.apiKey = window.__BOOTSTRAP_API_KEY__;
  localStorage.setItem('js-api-key', state.apiKey);
  document.cookie = 'x-api-key=' + encodeURIComponent(state.apiKey) + '; path=/; SameSite=Strict';
  const keyInput = document.getElementById('api-key-input');
  if (keyInput) keyInput.value = state.apiKey;
}
connectWS();
initDragDrop();
checkFirstStart();
// Load model list eagerly so the top-bar dropdown is usable immediately
// without requiring the user to visit the Models tab first.
loadModels();

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
