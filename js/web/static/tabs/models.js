import { state } from '../state/store.js';
import { escapeHtml, showToast, showLoading, showError, el, onDataClick, sanitizeRuntimeId } from '../utils/dom.js';

export function setCurrentModel(modelId) {
  state.selectedModel = modelId;
  localStorage.setItem('js-selected-model', modelId);
  const select = document.getElementById('current-model');
  if (select) select.value = modelId;
  const label = state.availableModels.find(m => m.id === modelId);
  const display = label ? (label.name || label.id) : '默认模型';
  const badge = document.getElementById('model-badge');
  if (badge) {
    const icon = label ? (label.isPreset ? '⚪' : (label.healthy ? '🟢' : (label.hasKey ? '🔴' : '🟡'))) : '';
    badge.textContent = `${icon} ${display}`;
  }
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
  if (!modelId) return;
  const model = state.availableModels.find(m => m.id === modelId);
  if (model && model.isPreset) {
    const presetId = model.provider;
    showToast(`Provider '${presetId}' 尚未配置，请先添加 API Key`, 'warning');
    switchTab('models');
    return;
  }
  const select = document.getElementById('current-model');
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
      throw new Error(data.detail || 'HTTP ' + res.status);
    }
    const result = await res.json();
    setCurrentModel(modelId);
    if (result.warning) {
      showToast(result.warning, 'warning');
    } else {
      showToast('已切换到模型: ' + (model?.name || modelId));
    }
    // Do not reload the full model list immediately; the dropdown already
    // reflects the new selection. loadModels() is expensive and causes UI lag.
  } catch (e) {
    showToast('切换模型失败: ' + e.message, 'error');
  } finally {
    if (select) {
      select.disabled = false;
      select.classList.remove('opacity-50', 'cursor-wait');
    }
  }
}

export async function loadModels() {
  showLoading('models-content', '加载模型...');
  try {
    const res = await fetch('/api/models');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const container = document.getElementById('models-content');
    const select = document.getElementById('current-model');

    if (data.active_model) {
      state.selectedModel = data.active_model;
      localStorage.setItem('js-selected-model', state.selectedModel);
    }

    state.availableModels = [];
    if (data.providers) {
      data.providers.forEach(p => {
        p.models.forEach(m => {
          state.availableModels.push({
            id: `${p.name}/${m.id}`,
            name: `${p.name}/${m.name || m.id}`,
            provider: p.name,
            healthy: p.healthy,
            hasKey: p.has_key,
            isPreset: false,
            ...m
          });
        });
      });
    }
    if (data.presets) {
      data.presets.forEach(preset => {
        preset.models.forEach(m => {
          state.availableModels.push({
            id: `${preset.id}/${m.id}`,
            name: `${preset.name}/${m.name || m.id}`,
            provider: preset.id,
            healthy: false,
            hasKey: false,
            isPreset: true,
            ...m
          });
        });
      });
    }

    if (select) {
      const currentVal = select.value;
      // Dropdown only shows configured providers, not unconfigured presets
      const usableModels = state.availableModels.filter(m => !m.isPreset);
      select.innerHTML = '<option value="">默认模型</option>' +
        usableModels.map(m => {
          const icon = m.healthy ? '🟢' : (m.hasKey ? '🔴' : '🟡');
          return `<option value="${escapeHtml(m.id)}">${icon} ${escapeHtml(m.name)}</option>`;
        }).join('');
      select.value = state.selectedModel || '';
    }

    const activeModelName = document.getElementById('active-model-name');
    const activeModelMeta = document.getElementById('active-model-meta');
    const activeModel = state.availableModels.find(m => m.id === state.selectedModel);
    if (activeModelName && activeModelMeta) {
      if (activeModel) {
        const icon = activeModel.isPreset ? '⚪' : (activeModel.healthy ? '🟢' : (activeModel.hasKey ? '🔴' : '🟡'));
        activeModelName.textContent = `${icon} ${activeModel.name || activeModel.id}`;
        activeModelMeta.textContent = `Provider: ${activeModel.provider} · 上下文: ${activeModel.context_window || '--'} tokens ${activeModel.isPreset ? '· 未配置' : ''}`;
      } else {
        activeModelName.textContent = '未选择';
        activeModelMeta.textContent = '使用系统默认模型';
      }
    }

    container.replaceChildren();
    let rendered = false;

    if (data.providers && data.providers.length > 0) {
      for (const p of data.providers) {
        const providerName = sanitizeRuntimeId(p.name);
        if (!providerName) continue;
        rendered = true;
        const card = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4' });
        const header = el('div', { className: 'flex items-center justify-between mb-3' });
        header.appendChild(el('h3', { className: 'font-bold text-lg', text: providerName }));
        const actions = el('div', { className: 'flex items-center gap-2' });
        const statusColor = p.healthy ? 'bg-green-900 text-green-400' : (p.has_key ? 'bg-red-900 text-red-400' : 'bg-yellow-900 text-yellow-400');
        const statusLabel = p.healthy ? '在线' : (p.has_key ? '离线' : '缺Key');
        actions.appendChild(el('span', { className: `text-xs px-2 py-1 rounded ${statusColor}`, text: statusLabel }));
        const keyBtn = el('button', {
          className: 'text-xs bg-blue-900/50 hover:bg-blue-900 text-blue-400 px-2 py-1 rounded transition',
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

        const modelList = el('div', { className: 'space-y-2' });
        for (const m of (p.models || [])) {
          const modelId = sanitizeRuntimeId(m.id);
          if (!modelId) continue;
          const fullId = sanitizeRuntimeId(`${providerName}/${modelId}`);
          if (!fullId) continue;
          const isActive = state.selectedModel === fullId;
          const row = el('div', {
            className: `flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2 ${isActive ? 'ring-1 ring-blue-500' : ''}`,
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
              className: 'text-xs bg-blue-900 text-blue-400 px-1.5 py-0.5 rounded ml-2',
              text: '当前',
            }));
          }
          row.appendChild(info);
          const switchBtn = el('button', {
            className: `text-xs ${isActive ? 'bg-gray-700 text-gray-400 cursor-default' : 'bg-blue-600 hover:bg-blue-700 text-white'} px-2 py-1 rounded transition`,
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
        container.appendChild(card);
      }
    }

    if (data.presets && data.presets.length > 0) {
      rendered = true;
      const presetCard = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 mt-4' });
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
        const block = el('div', { className: 'border border-gray-700/50 rounded-lg p-3' });
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
        const buttons = el('div', { className: 'flex flex-wrap gap-2' });
        for (const m of (preset.models || [])) {
          const modelId = sanitizeRuntimeId(m.id);
          if (!modelId) continue;
          const fullId = sanitizeRuntimeId(`${presetId}/${modelId}`);
          if (!fullId) continue;
          const btn = el('button', {
            className: 'text-xs bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 px-2 py-1 rounded transition',
            attrs: { type: 'button' },
            dataset: { modelId: fullId },
            text: m.name || modelId,
          });
          onDataClick(btn, 'modelId', (id) => switchModel(id));
          buttons.appendChild(btn);
        }
        block.appendChild(buttons);
        list.appendChild(block);
      }
      presetCard.appendChild(list);
      container.appendChild(presetCard);
    }

    if (!rendered) {
      container.appendChild(el('div', { className: 'text-gray-400', text: '未配置模型 Provider' }));
    }
  } catch (e) {
    showError('models-content', '加载模型失败: ' + e.message);
  }
}
