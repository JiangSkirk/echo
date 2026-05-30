import { escapeHtml, showToast, showLoading, showError } from '../utils/dom.js';

export async function loadMemory() {
  // Set loading states for all sections
  showLoading('memory-context', '加载记忆中...');
  showLoading('memory-working', '加载工作记忆...');
  showLoading('memory-semantic', '加载长期知识...');
  showLoading('memory-episodes', '加载情景记忆...');
  showLoading('memory-dreams', '加载梦境日志...');
  showLoading('memory-files', '加载记忆文件...');

  try {
    // Fetch embedder status in parallel
    let embedderStatus = null;
    try {
      const diagRes = await fetch('/api/diag');
      if (diagRes.ok) {
        const diag = await diagRes.json();
        embedderStatus = diag.embedder || null;
      }
    } catch (_) {}

    const res = await fetch('/api/memory/enhanced');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    // Show embedder status
    const statusEl = document.getElementById('memory-embedder-status');
    const recoverBtn = document.getElementById('memory-embedder-recover');
    if (statusEl && embedderStatus) {
      statusEl.classList.remove('hidden');
      if (embedderStatus.active) {
        statusEl.className = 'text-xs px-2 py-1 rounded bg-green-900/40 text-green-400';
        statusEl.innerHTML = '<i class="fas fa-microchip mr-1"></i>' + escapeHtml(embedderStatus.provider);
        if (recoverBtn) recoverBtn.classList.add('hidden');
      } else if (embedderStatus.fallback) {
        statusEl.className = 'text-xs px-2 py-1 rounded bg-yellow-900/40 text-yellow-400';
        statusEl.innerHTML = '<i class="fas fa-exclamation-triangle mr-1"></i>降级: ' + escapeHtml(embedderStatus.fallback);
        if (recoverBtn) recoverBtn.classList.remove('hidden');
      } else {
        statusEl.className = 'text-xs px-2 py-1 rounded bg-gray-800 text-gray-400';
        statusEl.textContent = escapeHtml(embedderStatus.provider);
        if (recoverBtn) recoverBtn.classList.add('hidden');
      }
    }

    // Active context
    const ctxEl = document.getElementById('memory-context');
    if (ctxEl) ctxEl.textContent = data.context || '暂无上下文';

    // Working memories
    const workEl = document.getElementById('memory-working');
    if (workEl) {
      const items = data.working_memories || [];
      if (items.length === 0) {
        workEl.innerHTML = '<div class="text-gray-400 text-sm">暂无工作记忆</div>';
      } else {
        workEl.innerHTML = items.map(w => `
          <div class="bg-gray-800 rounded-lg px-3 py-2">
            <div class="flex items-center justify-between">
              <span class="text-xs font-mono text-cyan-400">${escapeHtml(w.key || 'unknown')}</span>
              <span class="text-[10px] text-gray-500">${w.category || 'general'} · 重要性 ${w.importance || 0}</span>
            </div>
            <div class="text-sm text-gray-300 mt-0.5">${escapeHtml(w.value || '')}</div>
          </div>
        `).join('');
      }
    }

    // Semantic memories
    const semEl = document.getElementById('memory-semantic');
    if (semEl) {
      const items = data.semantic_memories || [];
      if (items.length === 0) {
        semEl.innerHTML = '<div class="text-gray-400 text-sm">暂无长期知识</div>';
      } else {
        semEl.innerHTML = items.map(s => renderSemanticMemoryItem(s)).join('');
      }
    }

    // Episodes
    const epEl = document.getElementById('memory-episodes');
    if (epEl) {
      if (!data.episodes || data.episodes.length === 0) {
        epEl.innerHTML = '<div class="text-gray-400 text-sm">暂无情景记忆</div>';
      } else {
        epEl.innerHTML = data.episodes.map(e => `
          <div class="bg-gray-800 rounded-lg px-3 py-2">
            <div class="text-sm">${escapeHtml(e.summary)}</div>
            <div class="text-xs text-gray-500 mt-1">
              <span class="mr-2"><i class="fas fa-calendar mr-1"></i>${new Date(e.created_at * 1000).toLocaleDateString()}</span>
              <span class="mr-2"><i class="fas fa-comment mr-1"></i>${e.turn_count} 轮</span>
              <span class="mr-2"><i class="fas fa-coins mr-1"></i>${e.tokens_used} tokens</span>
              ${e.topics && e.topics.length > 0 ? `<span class="text-blue-400">${e.topics.map(t => '#' + escapeHtml(t)).join(' ')}</span>` : ''}
            </div>
          </div>
        `).join('');
      }
    }

    // Dream logs
    const dreamEl = document.getElementById('memory-dreams');
    if (dreamEl) {
      if (!data.dream_logs || data.dream_logs.length === 0) {
        dreamEl.innerHTML = '<div class="text-gray-400 text-sm">暂无梦境日志</div>';
      } else {
        dreamEl.innerHTML = data.dream_logs.map(d => `
          <div class="bg-gray-800 rounded-lg px-3 py-2">
            <div class="flex items-center gap-2">
              <span class="text-xs px-2 py-0.5 rounded ${d.phase === 'deep' ? 'bg-purple-900 text-purple-400' : d.phase === 'rem' ? 'bg-blue-900 text-blue-400' : 'bg-gray-700 text-gray-400'}">${escapeHtml(d.phase)}</span>
              <span class="text-xs text-gray-500">${new Date(d.created_at * 1000).toLocaleString()}</span>
            </div>
            <div class="text-sm mt-1">${escapeHtml(d.summary)}</div>
          </div>
        `).join('');
      }
    }

    // Memory files (dynamic)
    const filesEl = document.getElementById('memory-files');
    if (filesEl) {
      const files = data.memory_files || [];
      if (files.length === 0) {
        filesEl.innerHTML = '<div class="text-gray-400 text-sm col-span-3">暂无记忆文件</div>';
      } else {
        filesEl.innerHTML = files.map(f => `
          <div onclick="openMemoryFileEditor('${escapeHtml(f)}')" class="cursor-pointer bg-gray-800 rounded-lg p-3 hover:bg-gray-700 transition">
            <div class="text-sm font-medium">${escapeHtml(f.toUpperCase())}.md</div>
            <div class="text-xs text-gray-500">点击编辑</div>
          </div>
        `).join('');
      }
    }
  } catch (e) {
    showError('memory-context', '加载记忆失败: ' + e.message);
    ['memory-working','memory-semantic','memory-episodes','memory-dreams','memory-files'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<div class="text-gray-500 text-sm">加载失败</div>';
    });
  }
}

export function renderSemanticMemoryItem(s) {
  const catColor = {
    fact: 'bg-blue-900/40 text-blue-400',
    preference: 'bg-pink-900/40 text-pink-400',
    insight: 'bg-purple-900/40 text-purple-400',
  }[s.category] || 'bg-gray-700 text-gray-400';
  return `
    <div class="bg-gray-800 rounded-lg px-3 py-2" data-memory-id="${s.id}">
      <div class="flex items-center justify-between flex-wrap gap-1">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-xs font-mono text-pink-400">${escapeHtml(s.key || 'unknown')}</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded ${catColor}">${escapeHtml(s.category || 'fact')}</span>
          <span class="text-[10px] text-gray-500">置信度 ${((s.confidence || 0.5) * 100).toFixed(0)}%</span>
        </div>
        <div class="flex items-center gap-1">
          <button onclick="editSemanticMemory(${s.id})" class="text-[10px] bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition" title="编辑">
            <i class="fas fa-pen"></i>
          </button>
          <button onclick="deleteSemanticMemory(${s.id})" class="text-[10px] bg-red-900/40 hover:bg-red-900/60 text-red-400 px-2 py-1 rounded transition" title="删除">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
      <div class="text-sm text-gray-300 mt-1 memory-value">${escapeHtml(s.value || '')}</div>
      ${s.source ? `<div class="text-[10px] text-gray-500 mt-1"><i class="fas fa-source mr-1"></i>来源: ${escapeHtml(s.source)}</div>` : ''}
    </div>
  `;
}

export function editSemanticMemory(id) {
  const card = document.querySelector(`[data-memory-id="${id}"]`);
  if (!card) return;
  const valueEl = card.querySelector('.memory-value');
  const currentValue = valueEl.textContent;
  const currentCategory = card.querySelector('[class*="rounded"].text-blue-400, [class*="rounded"].text-pink-400, [class*="rounded"].text-purple-400, [class*="rounded"].text-gray-400')?.textContent || 'fact';

  valueEl.innerHTML = `
    <textarea id="sem-edit-${id}" rows="3" class="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-300 resize-none focus:outline-none focus:border-pink-500">${escapeHtml(currentValue)}</textarea>
    <div class="flex items-center gap-2 mt-2">
      <select id="sem-cat-${id}" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
        <option value="fact" ${currentCategory === 'fact' ? 'selected' : ''}>事实</option>
        <option value="preference" ${currentCategory === 'preference' ? 'selected' : ''}>偏好</option>
        <option value="insight" ${currentCategory === 'insight' ? 'selected' : ''}>洞察</option>
      </select>
      <button onclick="saveSemanticMemory(${id})" class="bg-pink-900/40 hover:bg-pink-900/60 text-pink-300 px-3 py-1 rounded text-xs">保存</button>
      <button onclick="loadMemory()" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-xs">取消</button>
    </div>
  `;
}

export async function saveSemanticMemory(id) {
  const value = document.getElementById(`sem-edit-${id}`)?.value.trim();
  const category = document.getElementById(`sem-cat-${id}`)?.value;
  if (!value) {
    showToast('内容不能为空', 'error');
    return;
  }
  try {
    const res = await fetch(`/api/memory/semantic/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value, category }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    loadMemory();
    showToast('知识已更新');
  } catch (e) {
    showToast('更新失败: ' + e.message, 'error');
  }
}

export async function deleteSemanticMemory(id) {
  if (!confirm('确定删除这条知识吗？此操作不可恢复。')) return;
  try {
    const res = await fetch(`/api/memory/semantic/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    loadMemory();
    showToast('知识已删除');
  } catch (e) {
    showToast('删除失败: ' + e.message, 'error');
  }
}

export async function recoverEmbedder() {
  const btn = document.getElementById('memory-embedder-recover');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>恢复中...';
  }
  try {
    const res = await fetch('/api/memory/embedder/recover', { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.success) {
      showToast('嵌入器已恢复: ' + (data.provider || 'OK'));
    } else {
      showToast('恢复失败: ' + (data.reason || '未知错误'), 'error');
    }
    loadMemory();
  } catch (e) {
    showToast('恢复失败: ' + e.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-undo mr-1"></i>恢复嵌入器';
    }
  }
}

export async function searchSemantic() {
  const input = document.getElementById('semantic-search');
  const query = input.value.trim();
  if (!query) {
    loadMemory();
    return;
  }
  const container = document.getElementById('memory-semantic');
  showLoading('memory-semantic', '搜索中...');
  try {
    const res = await fetch('/api/memory/enhanced');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const items = (data.semantic_memories || []).filter(s =>
      (s.key || '').toLowerCase().includes(query.toLowerCase()) ||
      (s.value || '').toLowerCase().includes(query.toLowerCase())
    );
    if (items.length === 0) {
      container.innerHTML = '<div class="text-gray-400 text-sm">未找到匹配的知识</div>';
    } else {
      container.innerHTML = items.map(s => renderSemanticMemoryItem(s)).join('');
    }
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-sm">搜索失败: ' + escapeHtml(e.message) + '</div>';
  }
}

export function showAddSemanticModal() {
  const container = document.getElementById('memory-semantic');
  const existing = document.getElementById('semantic-add-form');
  if (existing) {
    existing.remove();
    return;
  }
  const form = document.createElement('div');
  form.id = 'semantic-add-form';
  form.className = 'bg-gray-800 rounded-lg p-3 space-y-2';
  form.innerHTML = `
    <div class="flex gap-2">
      <input id="semantic-add-key" type="text" placeholder="键 (如: user_name)" class="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm">
      <select id="semantic-add-cat" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-300">
        <option value="fact">事实</option>
        <option value="preference">偏好</option>
        <option value="insight">洞察</option>
      </select>
    </div>
    <textarea id="semantic-add-value" rows="2" placeholder="值..." class="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm resize-none"></textarea>
    <div class="flex gap-2">
      <button onclick="submitSemanticMemory()" class="bg-pink-900/40 hover:bg-pink-900/60 text-pink-300 px-3 py-1 rounded text-sm">保存</button>
      <button onclick="document.getElementById('semantic-add-form').remove()" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm">取消</button>
    </div>
  `;
  container.insertBefore(form, container.firstChild);
}

export async function submitSemanticMemory() {
  const key = document.getElementById('semantic-add-key').value.trim();
  const value = document.getElementById('semantic-add-value').value.trim();
  const category = document.getElementById('semantic-add-cat').value;
  if (!key || !value) {
    showToast('键和值不能为空', 'error');
    return;
  }
  try {
    const res = await fetch('/api/memory/semantic', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, value, category }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    document.getElementById('semantic-add-form').remove();
    loadMemory();
    showToast('知识已保存');
  } catch (e) {
    showToast('保存失败: ' + e.message, 'error');
  }
}

export async function openMemoryFileEditor(name) {
  const modal = document.getElementById('memory-file-modal');
  const title = document.getElementById('memory-file-modal-title');
  const textarea = document.getElementById('memory-file-editor');
  const saveBtn = document.getElementById('memory-file-save-btn');

  title.textContent = name.toUpperCase() + '.md';
  textarea.value = '加载中...';
  saveBtn.onclick = () => saveMemoryFile(name);

  modal.classList.remove('hidden');
  modal.classList.add('flex');

  try {
    const res = await fetch(`/api/memory/files/${name}`);
    const data = await res.json();
    textarea.value = data.content || '';
  } catch (e) {
    textarea.value = '加载失败: ' + e.message;
  }
}

export async function saveMemoryFile(name) {
  const textarea = document.getElementById('memory-file-editor');
  try {
    const res = await fetch(`/api/memory/files/${name}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: textarea.value }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    closeMemoryFileEditor();
    loadMemory();
  } catch (e) {
    alert('保存失败: ' + e.message);
  }
}

export function closeMemoryFileEditor() {
  const modal = document.getElementById('memory-file-modal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}
