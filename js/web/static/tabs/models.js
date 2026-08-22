import { state } from '../state/store.js';
import { escapeHtml, showToast, showLoading, showError, el, onDataClick, sanitizeRuntimeId } from '../utils/dom.js';

function modelSwitchErrorMessage(payload, status) {
  const detail = payload && payload.detail;
  if (typeof detail === 'string' && detail) return detail;
  if (detail && typeof detail === 'object') {
    if (typeof detail.error === 'string' && detail.error) return detail.error;
    if (typeof detail.message === 'string' && detail.message) return detail.message;
  }
  if (payload && typeof payload.error === 'string' && payload.error) return payload.error;
  return `HTTP ${status}`;
}

export function setCurrentModel(modelId) {
  applyServerActiveModel(modelId);
}

/**
 * Apply the server-authoritative active model to all UI surfaces.
 *
 * Accepts only a model_id that exists in ``state.availableModels`` as a
 * non-preset (i.e. actually configured) model.  When valid, updates
 * state.selectedModel, localStorage, the #current-model select, the active
 * summary (#active-model-name / #active-model-meta), the badge visibility,
 * and the chat bar (#chat-model-name), then dispatches ``js:models-updated``.
 *
 * When invalid (not found or isPreset), clears state.selectedModel, removes
 * localStorage, resets the select to empty, hides the badge, and shows
 * "未配置模型" in the chat bar.
 */
export function applyServerActiveModel(modelId) {
  const availableModels = Array.isArray(state.availableModels) ? state.availableModels : [];
  const model = modelId ? availableModels.find(m => m.id === modelId && !m.isPreset) : null;

  if (model) {
    state.selectedModel = modelId;
    localStorage.setItem('js-selected-model', modelId);
  } else {
    state.selectedModel = '';
    localStorage.removeItem('js-selected-model');
  }

  const select = document.getElementById('current-model');
  if (select) {
    select.value = state.selectedModel || '';
  }

  const activeModelName = document.getElementById('active-model-name');
  const activeModelMeta = document.getElementById('active-model-meta');
  const activeModelBadge = document.getElementById('active-model-badge');
  const chatNameEl = document.getElementById('chat-model-name');

  if (model) {
    if (activeModelName) activeModelName.textContent = model.name || model.id;
    if (activeModelMeta) {
      const statusLabel = model.healthy ? '在线' : (model.hasKey ? '离线' : '待配置');
      activeModelMeta.textContent = `Provider: ${model.provider} · 上下文: ${model.context_window || '--'} tokens · 状态: ${statusLabel}`;
    }
    if (activeModelBadge) activeModelBadge.style.display = '';
    if (chatNameEl) chatNameEl.textContent = String(model.name || model.id).split('/').pop();
  } else {
    if (activeModelName) activeModelName.textContent = '未配置模型';
    if (activeModelMeta) activeModelMeta.textContent = '请先添加 Provider 并选择模型';
    if (activeModelBadge) activeModelBadge.style.display = 'none';
    if (chatNameEl) chatNameEl.textContent = '未配置模型';
  }

  document.dispatchEvent(new CustomEvent('js:models-updated'));
}

export function toggleAddProvider() {
  const form = document.getElementById('add-provider-form');
  const chevron = document.getElementById('add-provider-chevron');
  const isHidden = form.classList.contains('hidden');
  form.classList.toggle('hidden');
  chevron.classList.toggle('rotate-180');
  if (isHidden) {
    document.getElementById('provider-error').classList.add('hidden');
    document.getElementById('discover-results').classList.add('hidden');
    document.getElementById('btn-save-provider').classList.add('hidden');
    state.discoveredModels = [];
  }
}

export async function discoverModels() {
  const url = document.getElementById('provider-url').value.trim();
  const key = document.getElementById('provider-key').value.trim();
  const errEl = document.getElementById('provider-error');
  const btn = document.getElementById('btn-discover');
  const resultsEl = document.getElementById('discover-results');
  const listEl = document.getElementById('discover-list');

  if (!url) {
    errEl.textContent = '请输入 Base URL';
    errEl.classList.remove('hidden');
    return;
  }
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new Error('invalid protocol');
    }
  } catch {
    errEl.textContent = '请输入有效的 URL（以 http:// 或 https:// 开头）';
    errEl.classList.remove('hidden');
    return;
  }
  errEl.classList.add('hidden');
  document.getElementById('btn-save-provider').classList.add('hidden');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>发现中...';

  try {
    const res = await fetch('/api/providers/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ base_url: url, api_key: key || null })
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || '发现失败: HTTP ' + res.status);
    }
    const data = await res.json();

    state.discoveredModels = data.models || [];
    if (state.discoveredModels.length === 0) {
      errEl.textContent = '未发现任何模型，请检查 URL 是否正确';
      errEl.classList.remove('hidden');
      resultsEl.classList.add('hidden');
      document.getElementById('btn-save-provider').classList.add('hidden');
      return;
    }

    listEl.innerHTML = state.discoveredModels.map(m => `
      <label class="flex items-center gap-2 bg-gray-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-gray-700">
        <input type="checkbox" class="discover-model-check accent-blue-500" value="${escapeHtml(m.id)}" checked>
        <span class="text-sm">${escapeHtml(m.name || m.id)}</span>
        <span class="text-xs text-gray-500 font-mono">${escapeHtml(m.id)}</span>
      </label>
    `).join('');
    resultsEl.classList.remove('hidden');
    document.getElementById('btn-save-provider').classList.remove('hidden');
  } catch (e) {
    errEl.textContent = '发现失败: ' + e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-search mr-1"></i>自动发现模型';
  }
}

export async function loadCloudPresets() {
  const select = document.getElementById('cloud-preset-select');
  if (!select) { console.warn('[loadCloudPresets] select element not found'); return; }
  select.innerHTML = '<option value="">加载中...</option>';
  try {
    const res = await fetch('/api/providers/cloud-presets');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    state.cloudPresets = data.presets || [];
    console.log('[loadCloudPresets] loaded', state.cloudPresets.length, 'presets');
    if (state.cloudPresets.length === 0) {
      select.innerHTML = '<option value="">暂无预设</option>';
      return;
    }
    select.innerHTML = '<option value="">请选择云模型...</option>' +
      state.cloudPresets.map(p => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');
  } catch (e) {
    console.error('[loadCloudPresets] failed:', e);
    select.innerHTML = '<option value="">加载失败: ' + escapeHtml(e.message) + '</option>';
  }
}

export function onCloudPresetChange() {
  const select = document.getElementById('cloud-preset-select');
  const detailsEl = document.getElementById('cloud-preset-details');
  const descEl = document.getElementById('cloud-preset-desc');
  const modelsEl = document.getElementById('cloud-preset-models');
  const errEl = document.getElementById('cloud-preset-error');
  const sucEl = document.getElementById('cloud-preset-success');

  errEl.classList.add('hidden');
  sucEl.classList.add('hidden');

  const presetId = select.value;
  if (!presetId) {
    detailsEl.classList.add('hidden');
    return;
  }

  const preset = state.cloudPresets.find(p => p.id === presetId);
  if (!preset) {
    detailsEl.classList.add('hidden');
    return;
  }

  descEl.textContent = preset.description || '';
  modelsEl.innerHTML = (preset.models || []).map(m =>
    `<span class="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-[10px]">${escapeHtml(m.name || m.id)}</span>`
  ).join('');
  detailsEl.classList.remove('hidden');
}

export async function testCloudProvider() {
  const select = document.getElementById('cloud-preset-select');
  const keyInput = document.getElementById('cloud-preset-key');
  const errEl = document.getElementById('cloud-preset-error');
  const sucEl = document.getElementById('cloud-preset-success');
  const btn = document.getElementById('btn-test-cloud');

  const presetId = select.value;
  const apiKey = keyInput.value.trim();

  if (!presetId) { errEl.textContent = '请选择云模型'; errEl.classList.remove('hidden'); sucEl.classList.add('hidden'); return; }
  if (!apiKey) { errEl.textContent = '请输入 API Key'; errEl.classList.remove('hidden'); sucEl.classList.add('hidden'); return; }

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
    errEl.textContent = '❌ ' + e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-plug mr-1"></i>测试连接';
  }
}

export async function addCloudProvider() {
  const select = document.getElementById('cloud-preset-select');
  const keyInput = document.getElementById('cloud-preset-key');
  const errEl = document.getElementById('cloud-preset-error');
  const btn = document.getElementById('btn-add-cloud');

  const presetId = select.value;
  const apiKey = keyInput.value.trim();

  if (!presetId) { errEl.textContent = '请选择云模型'; errEl.classList.remove('hidden'); return; }
  if (!apiKey) { errEl.textContent = '请输入 API Key'; errEl.classList.remove('hidden'); return; }

  const preset = state.cloudPresets.find(p => p.id === presetId);
  if (!preset) { errEl.textContent = '预设不存在'; errEl.classList.remove('hidden'); return; }

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

    keyInput.value = '';
    select.value = '';
    showToast('云模型添加成功: ' + (data.name || presetId));
    loadModels();
  } catch (e) {
    errEl.textContent = '添加失败: ' + e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-plus mr-1"></i>添加云模型';
  }
}

export async function saveProvider() {
  const name = document.getElementById('provider-name').value.trim();
  const url = document.getElementById('provider-url').value.trim();
  const key = document.getElementById('provider-key').value.trim();
  const errEl = document.getElementById('provider-error');
  const btn = document.getElementById('btn-save-provider');

  if (!name) { errEl.textContent = '请输入 Provider 名称'; errEl.classList.remove('hidden'); return; }
  if (!url) { errEl.textContent = '请输入 Base URL'; errEl.classList.remove('hidden'); return; }

  const checks = document.querySelectorAll('.discover-model-check:checked');
  const selectedIds = new Set(Array.from(checks).map(c => c.value));
  const selectedModels = state.discoveredModels.filter(m => selectedIds.has(m.id));
  if (selectedModels.length === 0) { errEl.textContent = '请至少选择一个模型'; errEl.classList.remove('hidden'); return; }

  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>保存中...';

  try {
    const res = await fetch('/api/providers/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, base_url: url, api_key: key || null, models: selectedModels })
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || '保存失败: HTTP ' + res.status);
    }
    const data = await res.json();

    document.getElementById('provider-name').value = '';
    document.getElementById('provider-url').value = '';
    document.getElementById('provider-key').value = '';
    document.getElementById('discover-results').classList.add('hidden');
    document.getElementById('btn-save-provider').classList.add('hidden');
    state.discoveredModels = [];

    showToast('Provider 添加成功: ' + data.provider);
    toggleAddProvider();
    loadModels();
  } catch (e) {
    errEl.textContent = '保存失败: ' + e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-check mr-1"></i>保存 Provider';
  }
}

export async function deleteProvider(name) {
  const display = name.length > 50 ? name.slice(0, 50) + '...' : name;
  if (!confirm('确定删除 Provider "' + display.replace(/[\r\n]/g, '') + '" 吗？')) return;
  try {
    const res = await fetch('/api/providers/' + encodeURIComponent(name), { method: 'DELETE' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    showToast('Provider 已删除');
    loadModels();
  } catch (e) {
    showToast('删除失败: ' + e.message, 'error');
  }
}

export function updateProviderKey(name) {
  document.getElementById('provider-key-target-name').textContent = name;
  document.getElementById('provider-key-input').value = '';
  document.getElementById('provider-key-error').classList.add('hidden');
  document.getElementById('provider-key-modal').classList.remove('hidden');
}

export function hideProviderKeyModal() {
  document.getElementById('provider-key-modal').classList.add('hidden');
}

export async function submitProviderKeyUpdate() {
  const name = document.getElementById('provider-key-target-name').textContent;
  const key = document.getElementById('provider-key-input').value.trim();
  const errEl = document.getElementById('provider-key-error');
  errEl.classList.add('hidden');
  try {
    const res = await fetch('/api/providers/' + encodeURIComponent(name), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key || null }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'HTTP ' + res.status);
    }
    hideProviderKeyModal();
    showToast('API Key 已更新');
    loadModels();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
  }
}

export async function switchModel(modelId) {
  if (!modelId) {
    applyServerActiveModel(state.selectedModel || '');
    return;
  }
  const model = state.availableModels.find(m => m.id === modelId);
  if (model && model.isPreset) {
    const presetId = model.provider;
    showToast(`Provider '${presetId}' 尚未配置，请先添加 API Key`, 'warning');
    switchTab('models');
    return;
  }
  const select = document.getElementById('current-model');
  // Save the previous active model so we can roll back on failure.
  const previousModel = state.selectedModel || '';
  if (select) {
    select.disabled = true;
    select.classList.add('opacity-50', 'cursor-wait');
  }
  try {
    const res = await fetch('/api/models/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_id: modelId }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(modelSwitchErrorMessage(data, res.status));
    }
    const result = await res.json();
    // Use the server-confirmed model_id to apply the new active model.
    applyServerActiveModel(result.model_id);
    if (result.warning) {
      showToast(result.warning, 'warning');
    } else {
      showToast('已切换到模型: ' + (model?.name || modelId));
    }
  } catch (e) {
    // Roll back to the previous active model on failure.
    applyServerActiveModel(previousModel);
    showToast('切换模型失败: ' + e.message, 'error');
  } finally {
    if (select) {
      select.disabled = false;
      select.classList.remove('opacity-50', 'cursor-wait');
    }
  }
}

let modelCatalogGeneration = 0;
let modelCatalogController = null;
let modelCatalogFingerprint = null;

function _plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function _hasOnlyKeys(value, allowed) {
  return Object.keys(value).every(key => allowed.has(key));
}

function _hasExactRuntimeId(value) {
  return typeof value === 'string' && sanitizeRuntimeId(value) === value;
}

function _optionalString(value, key, { nullable = false } = {}) {
  if (!Object.hasOwn(value, key)) return true;
  return typeof value[key] === 'string' || (nullable && value[key] === null);
}

function _optionalBoolean(value, key) {
  return !Object.hasOwn(value, key) || typeof value[key] === 'boolean';
}

function _optionalPositiveInteger(value, key) {
  if (!Object.hasOwn(value, key)) return true;
  const candidate = value[key];
  return typeof candidate === 'number' && Number.isInteger(candidate)
    && Number.isFinite(candidate) && candidate > 0;
}

function _optionalNonnegativeNumber(value, key) {
  if (!Object.hasOwn(value, key)) return true;
  const candidate = value[key];
  return typeof candidate === 'number' && Number.isFinite(candidate) && candidate >= 0;
}

function _normalizeModelCatalog(data) {
  const topKeys = new Set(['active_model', 'providers', 'presets']);
  const providerKeys = new Set([
    'name', 'base_url', 'healthy', 'health_error', 'has_key',
    'user_configured', 'models',
  ]);
  const providerModelKeys = new Set([
    'id', 'name', 'provider', 'context_window', 'max_tokens',
    'cost_input', 'cost_output',
  ]);
  const presetKeys = new Set([
    'id', 'name', 'description', 'base_url', 'api_key_env', 'models',
  ]);
  const presetModelKeys = new Set(['id', 'name', 'context_window']);
  if (!_plainObject(data) || !_hasOnlyKeys(data, topKeys)
      || !Array.isArray(data.providers) || !Array.isArray(data.presets)
      || !(data.active_model == null || typeof data.active_model === 'string')) {
    throw new Error('invalid model catalog');
  }

  const availableModels = [];
  const configuredModelIds = new Set();
  const allModelIds = new Set();
  for (const provider of data.providers) {
    if (!_plainObject(provider) || !_hasOnlyKeys(provider, providerKeys)
        || !_hasExactRuntimeId(provider.name) || !Array.isArray(provider.models)
        || !_optionalString(provider, 'base_url')
        || !_optionalString(provider, 'health_error', { nullable: true })
        || !_optionalBoolean(provider, 'healthy')
        || !_optionalBoolean(provider, 'has_key')
        || !_optionalBoolean(provider, 'user_configured')) {
      throw new Error('invalid provider catalog');
    }
    for (const model of provider.models) {
      if (!_plainObject(model) || !_hasOnlyKeys(model, providerModelKeys)
          || !_hasExactRuntimeId(model.id)
          || !_hasExactRuntimeId(model.provider)
          || model.provider !== provider.name
          || !_optionalString(model, 'name')
          || !_optionalPositiveInteger(model, 'context_window')
          || !_optionalPositiveInteger(model, 'max_tokens')
          || !_optionalNonnegativeNumber(model, 'cost_input')
          || !_optionalNonnegativeNumber(model, 'cost_output')) {
        throw new Error('invalid configured model');
      }
      const fullId = sanitizeRuntimeId(`${provider.name}/${model.id}`);
      if (!fullId || allModelIds.has(fullId)) {
        throw new Error('invalid configured model binding');
      }
      configuredModelIds.add(fullId);
      allModelIds.add(fullId);
      availableModels.push({
        ...model,
        id: fullId,
        name: `${provider.name}/${model.name || model.id}`,
        provider: provider.name,
        healthy: provider.healthy,
        hasKey: provider.has_key,
        isPreset: false,
      });
    }
  }
  for (const preset of data.presets) {
    if (!_plainObject(preset) || !_hasOnlyKeys(preset, presetKeys)
        || !_hasExactRuntimeId(preset.id) || !Array.isArray(preset.models)
        || !_optionalString(preset, 'name')
        || !_optionalString(preset, 'description')
        || !_optionalString(preset, 'base_url')
        || !_optionalString(preset, 'api_key_env')) {
      throw new Error('invalid preset catalog');
    }
    for (const model of preset.models) {
      if (!_plainObject(model) || !_hasOnlyKeys(model, presetModelKeys)
          || !_hasExactRuntimeId(model.id)
          || !_optionalString(model, 'name')
          || !_optionalPositiveInteger(model, 'context_window')) {
        throw new Error('invalid preset model');
      }
      const fullId = sanitizeRuntimeId(`${preset.id}/${model.id}`);
      if (!fullId || allModelIds.has(fullId)) {
        throw new Error('invalid preset model binding');
      }
      allModelIds.add(fullId);
      availableModels.push({
        ...model,
        id: fullId,
        name: `${preset.name}/${model.name || model.id}`,
        provider: preset.id,
        healthy: false,
        hasKey: false,
        isPreset: true,
      });
    }
  }
  if (data.active_model !== null) {
    if (!_hasExactRuntimeId(data.active_model)) {
      throw new Error('invalid active model binding');
    }
    // A safe id which is absent from the entire response is a stale server
    // pointer left behind after a provider was removed.  The catalog itself is
    // still authoritative and usable; callers clear that ghost active value.
    // An id which resolves to a preset is different: the response is claiming
    // an unconfigured model is active, so reject the response fail-closed.
    if (allModelIds.has(data.active_model)
        && !configuredModelIds.has(data.active_model)) {
      throw new Error('invalid active model binding');
    }
  }
  return availableModels;
}

function _captureModelCatalogCommit(container, select) {
  const activeModelName = document.getElementById('active-model-name');
  const activeModelMeta = document.getElementById('active-model-meta');
  const activeModelBadge = document.getElementById('active-model-badge');
  const chatName = document.getElementById('chat-model-name');
  return {
    availableModels: state.availableModels,
    selectedModel: state.selectedModel,
    hasSnapshot: state.modelCatalogHasSnapshot,
    fingerprint: modelCatalogFingerprint,
    storedModel: localStorage.getItem('js-selected-model'),
    container,
    containerNodes: container ? Array.from(container.childNodes) : [],
    select,
    selectNodes: select ? Array.from(select.childNodes) : [],
    selectValue: select ? select.value : '',
    activeModelName,
    activeModelNameText: activeModelName ? activeModelName.textContent : null,
    activeModelMeta,
    activeModelMetaText: activeModelMeta ? activeModelMeta.textContent : null,
    activeModelBadge,
    activeModelBadgeDisplay: activeModelBadge ? activeModelBadge.style.display : null,
    chatName,
    chatNameText: chatName ? chatName.textContent : null,
  };
}

function _bestEffortRollback(action) {
  try {
    action();
  } catch {
    // Rollback must continue across independent state, storage, and DOM
    // surfaces.  A persistently broken browser primitive cannot be repaired
    // here, but it must not prevent the remaining surfaces from being restored.
  }
}

function _rollbackModelCatalogCommit(snapshot) {
  state.availableModels = snapshot.availableModels;
  state.selectedModel = snapshot.selectedModel;
  state.modelCatalogHasSnapshot = snapshot.hasSnapshot;
  modelCatalogFingerprint = snapshot.fingerprint;

  _bestEffortRollback(() => {
    if (snapshot.storedModel === null) {
      localStorage.removeItem('js-selected-model');
    } else {
      localStorage.setItem('js-selected-model', snapshot.storedModel);
    }
  });
  _bestEffortRollback(() => {
    if (!snapshot.select) return;
    snapshot.select.replaceChildren(...snapshot.selectNodes);
    snapshot.select.value = snapshot.selectValue;
  });
  _bestEffortRollback(() => {
    if (snapshot.container) {
      snapshot.container.replaceChildren(...snapshot.containerNodes);
    }
  });
  _bestEffortRollback(() => {
    if (snapshot.activeModelName) {
      snapshot.activeModelName.textContent = snapshot.activeModelNameText;
    }
    if (snapshot.activeModelMeta) {
      snapshot.activeModelMeta.textContent = snapshot.activeModelMetaText;
    }
    if (snapshot.activeModelBadge) {
      snapshot.activeModelBadge.style.display = snapshot.activeModelBadgeDisplay;
    }
    if (snapshot.chatName) snapshot.chatName.textContent = snapshot.chatNameText;
  });
}

export async function loadModels() {
  const generation = ++modelCatalogGeneration;
  if (modelCatalogController) modelCatalogController.abort();
  const controller = new AbortController();
  modelCatalogController = controller;
  state.modelCatalogStatus = 'loading';
  state.modelCatalogError = null;
  document.body.dataset.modelCatalogStatus = 'loading';
  document.body.dataset.modelCatalogSnapshot = state.modelCatalogHasSnapshot ? 'true' : 'false';
  document.dispatchEvent(new CustomEvent('js:model-catalog-state'));
  if (!state.modelCatalogHasSnapshot) showLoading('models-content', '加载模型...');
  try {
    const res = await fetch('/api/models', { signal: controller.signal });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (generation !== modelCatalogGeneration) return;
    const nextAvailableModels = _normalizeModelCatalog(data);
    const nextFingerprint = JSON.stringify(data);
    const container = document.getElementById('models-content');
    const select = document.getElementById('current-model');

    if (state.modelCatalogHasSnapshot && modelCatalogFingerprint === nextFingerprint) {
      state.modelCatalogStatus = 'ready';
      state.modelCatalogError = null;
      document.body.dataset.modelCatalogStatus = 'ready';
      document.body.dataset.modelCatalogSnapshot = 'true';
      document.dispatchEvent(new CustomEvent('js:model-catalog-state'));
      return;
    }

    const activeModelId = nextAvailableModels.some(
      model => !model.isPreset && model.id === data.active_model,
    ) ? data.active_model : '';
    const activeModel = nextAvailableModels.find(
      model => !model.isPreset && model.id === activeModelId,
    ) || null;
    const nextView = document.createDocumentFragment();
    const nextSelectView = document.createDocumentFragment();
    nextSelectView.appendChild(el('option', {
      attrs: { value: '' },
      text: '默认模型',
    }));
    for (const model of nextAvailableModels.filter(item => !item.isPreset)) {
      nextSelectView.appendChild(el('option', {
        attrs: { value: model.id },
        text: model.name,
      }));
    }
    let rendered = false;

    if (data.providers && data.providers.length > 0) {
      for (const p of data.providers) {
        const providerName = sanitizeRuntimeId(p.name);
        if (!providerName) continue;
        rendered = true;
        const card = el('section', { className: 'model-provider-group' });
        const header = el('div', { className: 'flex items-center justify-between mb-3' });
        header.appendChild(el('h3', { className: 'font-bold text-lg', text: providerName }));
        const actions = el('div', { className: 'flex items-center gap-2' });
        const statusColor = p.healthy ? 'bg-green-900 text-green-400' : (p.has_key ? 'bg-red-900 text-red-400' : 'bg-yellow-900 text-yellow-400');
        const statusLabel = p.healthy ? '在线' : (p.has_key ? '离线' : '缺Key');
        actions.appendChild(el('span', { className: `text-xs px-2 py-1 rounded ${statusColor}`, text: statusLabel }));
        const keyBtn = el('button', {
          className: 'model-icon-action',
          attrs: { type: 'button', title: '设置 API Key' },
          dataset: { providerName },
        });
        keyBtn.appendChild(el('i', { className: 'fas fa-key' }));
        onDataClick(keyBtn, 'providerName', (name) => updateProviderKey(name));
        const delBtn = el('button', {
          className: 'text-xs bg-red-900/50 hover:bg-red-900 text-red-400 px-2 py-1 rounded transition',
          attrs: { type: 'button', title: '删除' },
          dataset: { providerName },
        });
        delBtn.appendChild(el('i', { className: 'fas fa-trash' }));
        onDataClick(delBtn, 'providerName', (name) => deleteProvider(name));
        actions.appendChild(keyBtn);
        actions.appendChild(delBtn);
        header.appendChild(actions);
        card.appendChild(header);

        const urlLine = el('p', { className: 'text-sm text-gray-400 mb-3', text: String(p.base_url || '') });
        if (p.health_error) {
          urlLine.appendChild(document.createTextNode(' '));
          urlLine.appendChild(el('span', {
            className: 'text-red-400 text-xs ml-2',
            text: String(p.health_error),
          }));
        }
        card.appendChild(urlLine);

        const modelList = el('div', { className: 'model-list' });
        for (const m of (p.models || [])) {
          const modelId = sanitizeRuntimeId(m.id);
          if (!modelId) continue;
          const fullId = sanitizeRuntimeId(`${providerName}/${modelId}`);
          if (!fullId) continue;
          const isActive = activeModelId === fullId;
          const row = el('div', {
            className: `model-list-row ${isActive ? 'is-active' : ''}`,
          });
          const info = el('div');
          info.appendChild(el('span', { className: 'text-sm', text: m.name || modelId }));
          info.appendChild(el('span', { className: 'text-xs text-gray-500 font-mono ml-2', text: modelId }));
          if (m.context_window) {
            info.appendChild(el('span', {
              className: 'text-xs text-gray-500 ml-2',
              text: `${m.context_window} tokens`,
            }));
          }
          if (isActive) {
            info.appendChild(el('span', {
              className: 'model-inline-current',
              text: '当前',
            }));
          }
          row.appendChild(info);
          const switchBtn = el('button', {
            className: `model-switch-action ${isActive ? 'is-current' : 'is-primary'}`,
            attrs: { type: 'button', disabled: isActive || null },
            dataset: { modelId: fullId },
            text: isActive ? '使用中' : '切换',
          });
          if (!isActive) {
            onDataClick(switchBtn, 'modelId', (id) => switchModel(id));
          }
          row.appendChild(switchBtn);
          modelList.appendChild(row);
        }
        card.appendChild(modelList);
        nextView.appendChild(card);
      }
    }

    if (data.presets && data.presets.length > 0) {
      rendered = true;
      const presetCard = el('section', { className: 'model-provider-group model-preset-group' });
      const title = el('h3', { className: 'font-bold text-lg mb-3' });
      title.appendChild(el('i', { className: 'fas fa-cloud text-blue-400 mr-2' }));
      title.appendChild(document.createTextNode('可添加的云模型'));
      presetCard.appendChild(title);
      presetCard.appendChild(el('p', {
        className: 'text-sm text-gray-400 mb-3',
        text: '以下云模型尚未配置，选择后会提示您添加 API Key。',
      }));
      const list = el('div', { className: 'space-y-4' });
      for (const preset of data.presets) {
        const presetId = sanitizeRuntimeId(preset.id);
        if (!presetId) continue;
        const block = el('div', { className: 'model-preset-block' });
        const head = el('div', { className: 'flex items-center justify-between mb-2' });
        head.appendChild(el('span', { className: 'font-medium', text: preset.name || presetId }));
        head.appendChild(el('span', {
          className: 'text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded',
          text: preset.api_key_env || 'API Key',
        }));
        block.appendChild(head);
        block.appendChild(el('p', {
          className: 'text-xs text-gray-500 mb-2',
          text: preset.description || '',
        }));
        const rows = el('div', { className: 'space-y-1' });
        for (const m of (preset.models || [])) {
          const modelId = sanitizeRuntimeId(m.id);
          if (!modelId) continue;
          const fullId = sanitizeRuntimeId(`${presetId}/${modelId}`);
          if (!fullId) continue;
          const row = el('div', {
            className: 'preset-model-row model-list-row',
          });
          const meta = el('div', { className: 'flex-1 min-w-0' });
          meta.appendChild(el('div', { className: 'text-sm', text: m.name || modelId }));
          meta.appendChild(el('div', {
            className: 'text-xs text-gray-500 font-mono truncate',
            text: `${modelId}${m.context_window ? ' · 上下文 ' + m.context_window : ''}`,
          }));
          row.appendChild(meta);
          const addBtn = el('button', {
            className: 'text-xs bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 px-3 py-1 rounded transition whitespace-nowrap',
            attrs: { type: 'button' },
            dataset: { modelId: fullId },
            text: '配置并添加',
          });
          onDataClick(addBtn, 'modelId', (id) => switchModel(id));
          row.appendChild(addBtn);
          rows.appendChild(row);
        }
        block.appendChild(rows);
        list.appendChild(block);
      }
      presetCard.appendChild(list);
      nextView.appendChild(presetCard);
    }

    if (!rendered) {
      nextView.appendChild(el('div', { className: 'text-gray-400', text: '未配置模型 Provider' }));
    }

    // All fallible validation and rendering happens off-DOM.  The remaining
    // synchronous commit is transactional across state, storage, the model
    // select, active-model surfaces, rendered content, and the fingerprint.
    const commitSnapshot = _captureModelCatalogCommit(container, select);
    try {
      if (activeModel) {
        localStorage.setItem('js-selected-model', activeModelId);
      } else {
        localStorage.removeItem('js-selected-model');
      }
      state.availableModels = nextAvailableModels;
      state.selectedModel = activeModelId;
      if (select) {
        select.replaceChildren(nextSelectView);
        select.value = activeModelId;
      }

      const activeModelName = document.getElementById('active-model-name');
      const activeModelMeta = document.getElementById('active-model-meta');
      const activeModelBadge = document.getElementById('active-model-badge');
      const chatName = document.getElementById('chat-model-name');
      if (activeModel) {
        if (activeModelName) activeModelName.textContent = activeModel.name || activeModel.id;
        if (activeModelMeta) {
          const statusLabel = activeModel.healthy
            ? '在线'
            : (activeModel.hasKey ? '离线' : '待配置');
          activeModelMeta.textContent = `Provider: ${activeModel.provider} · 上下文: ${activeModel.context_window || '--'} tokens · 状态: ${statusLabel}`;
        }
        if (activeModelBadge) activeModelBadge.style.display = '';
        if (chatName) chatName.textContent = String(activeModel.name || activeModel.id).split('/').pop();
      } else {
        if (activeModelName) activeModelName.textContent = '未配置模型';
        if (activeModelMeta) activeModelMeta.textContent = '请先添加 Provider 并选择模型';
        if (activeModelBadge) activeModelBadge.style.display = 'none';
        if (chatName) chatName.textContent = '未配置模型';
      }

      if (!container) throw new Error('missing model catalog container');
      container.replaceChildren(nextView);
      state.modelCatalogStatus = 'ready';
      state.modelCatalogError = null;
      state.modelCatalogHasSnapshot = true;
      modelCatalogFingerprint = nextFingerprint;
      document.body.dataset.modelCatalogStatus = 'ready';
      document.body.dataset.modelCatalogSnapshot = 'true';
    } catch (commitError) {
      _rollbackModelCatalogCommit(commitSnapshot);
      throw commitError;
    }
    document.dispatchEvent(new CustomEvent('js:models-updated'));
    document.dispatchEvent(new CustomEvent('js:model-catalog-state'));
  } catch (e) {
    if (generation !== modelCatalogGeneration || e?.name === 'AbortError') return;
    state.modelCatalogStatus = 'error';
    state.modelCatalogError = '模型目录暂时无法加载';
    document.body.dataset.modelCatalogStatus = 'error';
    document.body.dataset.modelCatalogSnapshot = state.modelCatalogHasSnapshot ? 'true' : 'false';
    document.dispatchEvent(new CustomEvent('js:model-catalog-state'));
    if (state.modelCatalogHasSnapshot) {
      showToast('模型列表刷新失败，继续使用上次成功结果', 'warning');
    } else {
      showError('models-content', '模型列表暂时无法加载，请稍后重试');
    }
  } finally {
    if (generation === modelCatalogGeneration && modelCatalogController === controller) {
      modelCatalogController = null;
    }
  }
}
