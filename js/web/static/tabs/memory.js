import { escapeHtml, showToast, showLoading, showError } from '../utils/dom.js';

// Current block filter for search
let currentBlockPath = '';
let searchScopeAll = true;
// Top-level block paths currently expanded to show their sub-blocks.
const expandedBlocks = new Set();
// Inbox / modal state.
let currentProposals = [];     // pending proposals currently rendered
let proposalEditId = null;     // proposal being edited in the modal
let pendingBlockOp = null;     // { mode: 'move'|'merge', src }
let pendingConfirm = null;     // callback for the generic confirm modal

function showModal(id) {
  const m = document.getElementById(id);
  if (!m) return;
  m.classList.remove('hidden');
  m.classList.add('flex');
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (!m) return;
  m.classList.add('hidden');
  m.classList.remove('flex');
}

function openConfirm(title, message, onYes) {
  pendingConfirm = onYes;
  const t = document.getElementById('memory-confirm-title');
  const msg = document.getElementById('memory-confirm-message');
  if (t) t.textContent = title;
  if (msg) msg.textContent = message;
  showModal('memory-confirm-modal');
}

export function confirmModalYes() {
  const fn = pendingConfirm;
  pendingConfirm = null;
  closeModal('memory-confirm-modal');
  if (fn) fn();
}

export function closeConfirmModal() {
  pendingConfirm = null;
  closeModal('memory-confirm-modal');
}

const ENTITY_COLORS = {
  family: 'bg-orange-900/40 text-orange-400',
  friend: 'bg-lime-900/40 text-lime-400',
  colleague: 'bg-indigo-900/40 text-indigo-400',
  project: 'bg-teal-900/40 text-teal-400',
  company: 'bg-sky-900/40 text-sky-400',
  preference: 'bg-green-900/40 text-green-400',
  personality: 'bg-fuchsia-900/40 text-fuchsia-400',
  body: 'bg-red-900/40 text-red-400',
  device: 'bg-amber-900/40 text-amber-400',
  identity: 'bg-rose-900/40 text-rose-400',
  event: 'bg-violet-900/40 text-violet-400',
  location: 'bg-emerald-900/40 text-emerald-400',
  plan: 'bg-cyan-900/40 text-cyan-400',
  chat: 'bg-slate-700 text-slate-300',
  general: 'bg-gray-700 text-gray-400',
};

const ENTITY_LABELS = {
  family: '家人',
  friend: '朋友',
  colleague: '同事',
  project: '项目',
  company: '公司',
  preference: '偏好',
  personality: '性格',
  body: '身体',
  device: '设备',
  identity: '身份',
  event: '事件',
  location: '地点',
  plan: '计划',
  chat: '会话',
  general: '通用',
};

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

    // Load block tree + pending proposals
    loadBlockTree();
    loadProposals();
  } catch (e) {
    showError('memory-context', '加载记忆失败: ' + e.message);
    ['memory-working','memory-semantic','memory-episodes','memory-dreams','memory-files'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<div class="text-gray-500 text-sm">加载失败</div>';
    });
  }
}

export async function loadBlockTree() {
  const treeEl = document.getElementById('memory-block-tree');
  if (!treeEl) return;
  try {
    const res = await fetch('/api/memory/blocks');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const blocks = data.blocks || [];
    let html = `
      <div onclick="loadBlockMemories('')" class="cursor-pointer px-2 py-1 rounded hover:bg-gray-800 transition ${currentBlockPath === '' ? 'bg-gray-800 text-pink-400' : 'text-gray-400'}">
        <i class="fas fa-database mr-1 text-xs"></i>全部
      </div>`;
    if (blocks.length === 0) {
      html += '<div class="text-gray-500 text-xs px-2 py-1">暂无区块</div>';
    }
    // Render each top-level block; if expanded, fetch + inline its sub-blocks.
    for (const b of blocks) {
      const path = b.block_path || b.path || '';
      html += renderBlockNode(b, 0, true);
      if (expandedBlocks.has(path)) {
        try {
          const subRes = await fetch('/api/memory/blocks?prefix=' + encodeURIComponent(path));
          const subData = await subRes.json();
          for (const sb of (subData.blocks || [])) {
            if ((sb.block_path || '') !== path) html += renderBlockNode(sb, 1, false);
          }
        } catch (_) {}
      }
    }
    html += blockToolbarHtml();
    treeEl.innerHTML = html;
  } catch (e) {
    treeEl.innerHTML = '<div class="text-red-400 text-xs">加载失败</div>';
  }
}

function renderBlockNode(block, depth, expandable) {
  const path = block.block_path || block.path || '';
  const name = path.split('/').pop() || path || '未知';
  const count = block.memory_count || block.count || 0;
  const isActive = currentBlockPath === path;
  const pad = depth > 0 ? 'ml-4' : '';
  const isOpen = expandedBlocks.has(path);
  const caret = expandable
    ? `<i onclick="event.stopPropagation(); toggleBlockExpand('${escapeHtml(path)}')" class="fas fa-chevron-${isOpen ? 'down' : 'right'} text-[9px] mr-1 text-gray-500 hover:text-pink-400 cursor-pointer"></i>`
    : '<span class="inline-block w-3"></span>';
  return `
    <div class="flex items-center justify-between group ${pad} px-2 py-1 rounded hover:bg-gray-800 transition ${isActive ? 'bg-gray-800 text-pink-400' : 'text-gray-400'}">
      <div onclick="loadBlockMemories('${escapeHtml(path)}')" class="cursor-pointer flex-1 truncate">
        ${caret}<i class="fas fa-folder mr-1 text-xs ${isActive ? 'text-pink-400' : 'text-gray-600'}"></i>
        <span class="${isActive ? 'font-medium' : ''}">${escapeHtml(name)}</span>
        <span class="text-[10px] text-gray-600 ml-1">(${count})</span>
      </div>
      <i onclick="event.stopPropagation(); openBlockDelete('${escapeHtml(path)}')" class="fas fa-trash text-[9px] text-gray-700 hover:text-red-400 cursor-pointer opacity-0 group-hover:opacity-100 ml-1" title="删除区块"></i>
    </div>
  `;
}

function blockToolbarHtml() {
  return `
    <div class="mt-3 pt-2 border-t border-gray-800 flex flex-col gap-1">
      <button onclick="openBlockMove()" class="text-[11px] text-gray-400 hover:text-pink-400 text-left px-2 py-1 rounded hover:bg-gray-800 transition"><i class="fas fa-arrows-up-down-left-right mr-1"></i>移动区块</button>
      <button onclick="openBlockMerge()" class="text-[11px] text-gray-400 hover:text-pink-400 text-left px-2 py-1 rounded hover:bg-gray-800 transition"><i class="fas fa-code-merge mr-1"></i>合并区块</button>
    </div>
  `;
}

export function toggleBlockExpand(path) {
  if (expandedBlocks.has(path)) expandedBlocks.delete(path);
  else expandedBlocks.add(path);
  loadBlockTree();
}

export function openBlockMove() {
  pendingBlockOp = { mode: 'move', src: currentBlockPath || '' };
  prepBlockModal('移动区块', '把源区块下的所有记忆改到目标路径。');
}

export function openBlockMerge() {
  pendingBlockOp = { mode: 'merge', src: currentBlockPath || '' };
  prepBlockModal('合并区块', '把源区块并入目标区块（记忆都归到目标路径下）。');
}

async function prepBlockModal(title, hint) {
  const t = document.getElementById('block-modal-title');
  const h = document.getElementById('block-modal-hint');
  const srcInput = document.getElementById('block-modal-src');
  const sel = document.getElementById('block-modal-target');
  const custom = document.getElementById('block-modal-custom');
  if (t) t.textContent = title;
  if (h) h.textContent = hint;
  if (srcInput) srcInput.value = pendingBlockOp ? pendingBlockOp.src : '';
  if (custom) { custom.classList.add('hidden'); custom.value = ''; }
  if (sel) {
    sel.innerHTML = '<option value="">— 选择目标区块 —</option>';
    try {
      const res = await fetch('/api/memory/blocks');
      const data = await res.json();
      for (const b of (data.blocks || [])) {
        const p = b.block_path || b.path || '';
        if (!p) continue;
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = `${p} (${b.memory_count || b.count || 0})`;
        sel.appendChild(opt);
      }
    } catch (_) {}
    const customOpt = document.createElement('option');
    customOpt.value = '__custom__';
    customOpt.textContent = '自定义新路径…';
    sel.appendChild(customOpt);
    sel.value = '';
  }
  showModal('block-op-modal');
}

export function onBlockTargetChange() {
  const sel = document.getElementById('block-modal-target');
  const custom = document.getElementById('block-modal-custom');
  if (!sel || !custom) return;
  if (sel.value === '__custom__') custom.classList.remove('hidden');
  else custom.classList.add('hidden');
}

export function closeBlockModal() {
  pendingBlockOp = null;
  closeModal('block-op-modal');
}

export async function submitBlockModal() {
  const src = (document.getElementById('block-modal-src')?.value || '').trim();
  const sel = document.getElementById('block-modal-target');
  let dst = sel ? sel.value : '';
  if (dst === '__custom__') dst = (document.getElementById('block-modal-custom')?.value || '').trim();
  if (!src || !dst) {
    showToast('请填写源区块和目标区块', 'error');
    return;
  }
  const mode = pendingBlockOp ? pendingBlockOp.mode : 'move';
  closeBlockModal();
  await blockOp(mode, src, dst);
}

async function blockOp(op, src, dst) {
  try {
    const res = await fetch(`/api/memory/blocks/${op}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src, dst }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    showToast(`已${op === 'move' ? '移动' : '合并'} ${data.moved ?? data.merged ?? 0} 条记忆`);
    currentBlockPath = '';
    loadMemory();
  } catch (e) {
    showToast('操作失败: ' + e.message, 'error');
  }
}

export async function openBlockDelete(path) {
  if (!path) return;
  let count = null;
  try {
    const res = await fetch(`/api/memory/block/${encodeURIComponent(path)}?limit=500`);
    const data = await res.json();
    count = (data.memories || []).length;
  } catch (_) {}
  const msg = count == null
    ? `将删除「${path}」下的所有记忆，且不可恢复。`
    : `将删除「${path}」下的 ${count} 条记忆，且不可恢复。`;
  openConfirm('删除区块', msg, () => doDeleteBlock(path));
}

async function doDeleteBlock(path) {
  try {
    const res = await fetch(`/api/memory/block/${encodeURIComponent(path)}?limit=500`);
    const data = await res.json();
    const items = data.memories || [];
    for (const m of items) {
      await fetch(`/api/memory/semantic/${m.id}`, { method: 'DELETE' });
    }
    showToast(`已删除区块 ${path} (${items.length} 条)`);
    if (currentBlockPath === path) currentBlockPath = '';
    loadMemory();
  } catch (e) {
    showToast('删除失败: ' + e.message, 'error');
  }
}

export async function loadBlockMemories(path) {
  currentBlockPath = path;
  loadBlockTree(); // refresh highlight
  const semEl = document.getElementById('memory-semantic');
  if (!semEl) return;

  if (!path) {
    // Show all memories
    loadMemory();
    return;
  }

  showLoading('memory-semantic', '加载区块中...');
  try {
    const res = await fetch(`/api/memory/block/${encodeURIComponent(path)}?limit=50`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const items = data.memories || [];
    if (items.length === 0) {
      semEl.innerHTML = '<div class="text-gray-400 text-sm">该区块暂无知识</div>';
    } else {
      semEl.innerHTML = items.map(s => renderSemanticMemoryItem(s)).join('');
    }
  } catch (e) {
    semEl.innerHTML = '<div class="text-red-400 text-sm">加载失败: ' + escapeHtml(e.message) + '</div>';
  }
}

function getConfidenceBadge(confidence) {
  const c = confidence || 0.5;
  if (c >= 0.8) return { icon: '🟢', label: '高可信', color: 'text-green-400' };
  if (c >= 0.5) return { icon: '🟡', label: '中可信', color: 'text-yellow-400' };
  return { icon: '🔴', label: '低可信', color: 'text-red-400' };
}

function getSourceLabel(source) {
  const map = {
    user: '用户',
    agent: 'AI',
    dream: '梦境',
    import: '导入',
    manual: '手动',
  };
  return map[source] || source || '未知';
}

export function renderSemanticMemoryItem(s) {
  const catColor = {
    fact: 'bg-blue-900/40 text-blue-400',
    preference: 'bg-pink-900/40 text-pink-400',
    insight: 'bg-purple-900/40 text-purple-400',
  }[s.category] || 'bg-gray-700 text-gray-400';
  const confBadge = getConfidenceBadge(s.confidence);
  const etype = s.entity_type || 'general';
  const entityColor = ENTITY_COLORS[etype] || ENTITY_COLORS.general;
  const entityLabel = ENTITY_LABELS[etype] || etype;
  const isVerified = (s.last_verified_at || 0) > 0;
  return `
    <div class="bg-gray-800 rounded-lg px-3 py-2" data-memory-id="${s.id}">
      <div class="flex items-center justify-between flex-wrap gap-1">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-xs font-mono text-pink-400">${escapeHtml(s.key || 'unknown')}</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded ${catColor}">${escapeHtml(s.category || 'fact')}</span>
          <span class="text-[10px] ${confBadge.color}" title="${confBadge.label}">${confBadge.icon} ${((s.confidence || 0.5) * 100).toFixed(0)}%</span>
          <span class="text-[10px] bg-gray-700/50 text-gray-400 px-1.5 py-0.5 rounded">${getSourceLabel(s.source)}</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded ${entityColor}">${entityLabel}</span>
          ${isVerified ? '<span class="text-[10px] text-green-400" title="已验证"><i class="fas fa-check-circle"></i></span>' : ''}
        </div>
        <div class="flex items-center gap-1">
          <button onclick="verifyMemory(${s.id})" class="text-[10px] bg-green-900/30 hover:bg-green-900/50 text-green-400 px-2 py-1 rounded transition" title="验证">
            <i class="fas fa-check"></i>
          </button>
          <button onclick="showMemoryAudit(${s.id})" class="text-[10px] bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition" title="历史版本">
            <i class="fas fa-history"></i>
          </button>
          <button onclick="editSemanticMemory(${s.id})" class="text-[10px] bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition" title="编辑">
            <i class="fas fa-pen"></i>
          </button>
          <button onclick="deleteSemanticMemory(${s.id})" class="text-[10px] bg-red-900/40 hover:bg-red-900/60 text-red-400 px-2 py-1 rounded transition" title="删除">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
      <div class="text-sm text-gray-300 mt-1 memory-value">${escapeHtml(s.value || '')}</div>
      ${s.memory_path ? `<div class="text-[10px] text-gray-600 mt-0.5"><i class="fas fa-folder-open mr-1"></i>${escapeHtml(s.memory_path)}</div>` : ''}
      <div class="memory-audit hidden mt-2 bg-gray-900/50 rounded p-2 text-xs text-gray-400" id="memory-audit-${s.id}"></div>
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
    <div class="flex flex-wrap items-center gap-2 mt-2">
      <select id="sem-cat-${id}" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
        <option value="fact" ${currentCategory === 'fact' ? 'selected' : ''}>事实</option>
        <option value="preference" ${currentCategory === 'preference' ? 'selected' : ''}>偏好</option>
        <option value="insight" ${currentCategory === 'insight' ? 'selected' : ''}>洞察</option>
      </select>
      <select id="sem-etype-${id}" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
        <option value="general">通用</option>
        <option value="family">家人</option>
        <option value="colleague">同事</option>
        <option value="project">项目</option>
        <option value="company">公司</option>
        <option value="preference">偏好</option>
        <option value="device">设备</option>
        <option value="identity">身份</option>
        <option value="event">事件</option>
        <option value="location">地点</option>
      </select>
      <input id="sem-path-${id}" type="text" placeholder="路径" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 w-32">
      <input id="sem-ename-${id}" type="text" placeholder="实体名" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 w-24">
      <button onclick="saveSemanticMemory(${id})" class="bg-pink-900/40 hover:bg-pink-900/60 text-pink-300 px-3 py-1 rounded text-xs">保存</button>
      <button onclick="loadMemory()" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-xs">取消</button>
    </div>
  `;
}

export async function showMemoryAudit(id) {
  const auditEl = document.getElementById(`memory-audit-${id}`);
  if (!auditEl) return;
  if (!auditEl.classList.contains('hidden')) {
    auditEl.classList.add('hidden');
    return;
  }
  auditEl.classList.remove('hidden');
  auditEl.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>加载历史...';
  try {
    const res = await fetch(`/api/memory/audit?memory_id=${id}&limit=20`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const entries = data.entries || [];
    if (entries.length === 0) {
      auditEl.innerHTML = '<span class="text-gray-500">暂无变更记录</span>';
      return;
    }
    auditEl.innerHTML = entries.map(e => {
      const actionMap = { create: '创建', update: '更新', delete: '删除', verify: '验证' };
      const time = new Date(e.created_at * 1000).toLocaleString();
      return `
        <div class="border-l-2 border-gray-600 pl-2 mb-1">
          <div class="flex items-center gap-2">
            <span class="text-gray-300">${actionMap[e.action] || e.action}</span>
            <span class="text-gray-500">${time}</span>
            <span class="text-gray-600">来源: ${getSourceLabel(e.source)}</span>
          </div>
          ${e.old_value ? `<div class="text-gray-500 line-through">${escapeHtml(e.old_value.substring(0, 100))}</div>` : ''}
          ${e.new_value ? `<div class="text-gray-300">${escapeHtml(e.new_value.substring(0, 100))}</div>` : ''}
        </div>
      `;
    }).join('');
  } catch (e) {
    auditEl.innerHTML = '<span class="text-red-400">加载失败</span>';
  }
}

export async function saveSemanticMemory(id) {
  const value = document.getElementById(`sem-edit-${id}`)?.value.trim();
  const category = document.getElementById(`sem-cat-${id}`)?.value;
  const entity_type = document.getElementById(`sem-etype-${id}`)?.value;
  const memory_path = document.getElementById(`sem-path-${id}`)?.value.trim();
  const entity_name = document.getElementById(`sem-ename-${id}`)?.value.trim();
  if (!value) {
    showToast('内容不能为空', 'error');
    return;
  }
  const body = { value, category };
  if (entity_type) body.entity_type = entity_type;
  if (memory_path) body.memory_path = memory_path;
  if (entity_name) body.entity_name = entity_name;
  try {
    const res = await fetch(`/api/memory/semantic/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
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

export async function verifyMemory(id) {
  try {
    const res = await fetch(`/api/memory/semantic/${id}/verify`, { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    showToast('知识已标记为验证');
    loadMemory();
  } catch (e) {
    showToast('验证失败: ' + e.message, 'error');
  }
}

// ── Memory inbox: proposed changes awaiting confirmation ──

export async function loadProposals() {
  const el = document.getElementById('memory-proposals');
  if (!el) return;
  try {
    const res = await fetch('/api/memory/proposals?status=pending&limit=50');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const items = data.proposals || [];
    currentProposals = items;
    const countEl = document.getElementById('memory-proposals-count');
    if (countEl) countEl.textContent = items.length ? `· ${items.length} 条待确认` : '· 已清空';
    const allBtn = document.getElementById('memory-approve-all-btn');
    if (allBtn) allBtn.classList.toggle('hidden', items.length === 0);
    if (items.length === 0) {
      el.innerHTML = '<div class="text-gray-500 text-sm">收件箱已清空，没有待确认的记忆。</div>';
      return;
    }
    el.innerHTML = items.map(renderProposal).join('');
  } catch (e) {
    el.innerHTML = '<div class="text-red-400 text-sm">加载收件箱失败</div>';
  }
}

function renderProposal(p) {
  const conf = Math.round((p.confidence || 0) * 100);
  const etype = p.entity_type || 'general';
  const entityColor = ENTITY_COLORS[etype] || ENTITY_COLORS.general;
  const entityLabel = ENTITY_LABELS[etype] || etype;
  const confInfo = getConfidenceBadge(p.confidence);
  const srcLabel = getSourceLabel(p.source);
  return `
    <div class="bg-gray-800 rounded-lg px-3 py-2 border-l-2 border-yellow-600/60">
      <div class="text-[11px] text-gray-500 mb-1"><i class="fas fa-lightbulb text-yellow-500 mr-1"></i>${escapeHtml(srcLabel)}想记住（<span class="${entityColor.split(' ').find(c => c.startsWith('text-')) || ''}">${entityLabel}</span>）</div>
      <div class="flex items-start justify-between gap-2">
        <div class="flex-1 min-w-0">
          <div class="text-sm text-gray-200">${p.key ? `<span class="text-gray-500">${escapeHtml(p.key)}：</span>` : ''}${escapeHtml(p.value || '')}</div>
          ${p.memory_path ? `<div class="text-[10px] text-gray-600 mt-0.5"><i class="fas fa-folder-open mr-1"></i>${escapeHtml(p.memory_path)}</div>` : ''}
          <div class="text-[10px] mt-0.5 ${confInfo.color}" title="${confInfo.label}">${confInfo.icon} ${confInfo.label} ${conf}%</div>
          ${p.evidence ? `<details class="mt-1"><summary class="text-[10px] text-gray-500 cursor-pointer hover:text-gray-300">查看证据</summary><div class="text-[10px] text-gray-400 italic mt-1">${escapeHtml(p.evidence)}</div></details>` : ''}
        </div>
        <div class="flex flex-col gap-1 shrink-0">
          <button onclick="approveProposal(${p.id})" class="text-[10px] bg-green-900/40 hover:bg-green-900/60 text-green-300 px-2 py-1 rounded" title="确认并写入"><i class="fas fa-check"></i></button>
          <button onclick="openProposalEdit(${p.id})" class="text-[10px] bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded" title="编辑后确认"><i class="fas fa-pen"></i></button>
          <button onclick="rejectProposal(${p.id})" class="text-[10px] bg-red-900/40 hover:bg-red-900/60 text-red-300 px-2 py-1 rounded" title="拒绝"><i class="fas fa-times"></i></button>
        </div>
      </div>
    </div>
  `;
}

export async function organizeNow() {
  const btn = document.getElementById('memory-organize-btn');
  const statusEl = document.getElementById('memory-organize-status');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>整理中...'; }
  if (statusEl) statusEl.textContent = '正在从最近的对话中提取要记住的信息…';
  try {
    const res = await fetch('/api/memory/organize', { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const d = await res.json();
    if ((d.turns || 0) === 0) {
      showToast('最近没有可整理的对话');
      if (statusEl) statusEl.textContent = '最近没有新的对话可整理，先去聊几句吧。';
    } else if (d.skipped) {
      showToast('暂时无法整理：' + d.skipped, 'warning');
      if (statusEl) statusEl.textContent = '暂时无法整理（' + d.skipped + '）。';
    } else {
      const pend = d.pending || 0;
      const auto = d.auto_applied || 0;
      showToast(`整理完成：新增 ${pend} 条待确认，自动收录 ${auto} 条`);
      const now = new Date().toLocaleTimeString();
      if (statusEl) statusEl.textContent = `上次整理：${now} · 分析 ${d.turns} 轮对话 · 待确认 ${pend} · 自动收录 ${auto}`;
    }
    loadMemory();
  } catch (e) {
    showToast('整理失败: ' + e.message, 'error');
    if (statusEl) statusEl.textContent = '整理失败：' + e.message;
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-wand-magic-sparkles mr-1"></i>立即整理'; }
  }
}

export async function approveProposal(id) {
  try {
    const res = await fetch(`/api/memory/proposals/${id}/approve`, { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    showToast('已确认并写入记忆');
    loadMemory();
  } catch (e) {
    showToast('确认失败: ' + e.message, 'error');
  }
}

export async function rejectProposal(id) {
  try {
    const res = await fetch(`/api/memory/proposals/${id}/reject`, { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    showToast('已拒绝该提案');
    loadProposals();
  } catch (e) {
    showToast('拒绝失败: ' + e.message, 'error');
  }
}

export function approveAllProposals() {
  if (!currentProposals.length) {
    showToast('没有待确认的提案');
    return;
  }
  openConfirm('全部确认', `确认全部 ${currentProposals.length} 条记忆提案并写入？`, doApproveAll);
}

async function doApproveAll() {
  const ids = currentProposals.map(p => p.id);
  let ok = 0;
  for (const id of ids) {
    try {
      const res = await fetch(`/api/memory/proposals/${id}/approve`, { method: 'POST' });
      if (res.ok) ok++;
    } catch (_) {}
  }
  showToast(`已确认 ${ok}/${ids.length} 条`);
  loadMemory();
}

export function openProposalEdit(id) {
  const p = currentProposals.find(x => x.id === id);
  if (!p) return;
  proposalEditId = id;
  const v = document.getElementById('proposal-edit-value');
  const path = document.getElementById('proposal-edit-path');
  const cat = document.getElementById('proposal-edit-cat');
  const etype = document.getElementById('proposal-edit-etype');
  if (v) v.value = p.value || '';
  if (path) path.value = p.memory_path || '';
  if (cat) cat.value = p.category || 'fact';
  if (etype) etype.value = p.entity_type || '';
  showModal('proposal-edit-modal');
}

export function closeProposalEdit() {
  proposalEditId = null;
  closeModal('proposal-edit-modal');
}

export async function saveProposalEdit() {
  if (proposalEditId == null) return;
  const value = (document.getElementById('proposal-edit-value')?.value || '').trim();
  if (!value) {
    showToast('内容不能为空', 'error');
    return;
  }
  const overrides = {
    value,
    category: document.getElementById('proposal-edit-cat')?.value || 'fact',
  };
  const path = (document.getElementById('proposal-edit-path')?.value || '').trim();
  const etype = document.getElementById('proposal-edit-etype')?.value || '';
  if (path) overrides.memory_path = path;
  if (etype) overrides.entity_type = etype;
  try {
    const res = await fetch(`/api/memory/proposals/${proposalEditId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(overrides),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    closeProposalEdit();
    showToast('已按修改后的内容确认并写入');
    loadMemory();
  } catch (e) {
    showToast('保存失败: ' + e.message, 'error');
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

export function toggleSearchScope() {
  searchScopeAll = !searchScopeAll;
  const btn = document.getElementById('semantic-search-scope');
  if (btn) {
    btn.textContent = searchScopeAll ? '全部' : '当前区块';
    btn.className = searchScopeAll
      ? 'bg-gray-800 border border-gray-700 px-2 py-1.5 rounded-lg text-xs text-gray-400 transition'
      : 'bg-pink-900/40 border border-pink-700 px-2 py-1.5 rounded-lg text-xs text-pink-300 transition';
  }
}

export async function searchSemantic() {
  const input = document.getElementById('semantic-search');
  const query = input.value.trim();
  const container = document.getElementById('memory-semantic');
  if (!query) {
    if (currentBlockPath) {
      loadBlockMemories(currentBlockPath);
    } else {
      loadMemory();
    }
    return;
  }
  showLoading('memory-semantic', '搜索中...');
  try {
    const pathPrefix = (!searchScopeAll && currentBlockPath) ? currentBlockPath : '';
    const params = new URLSearchParams({ q: query, limit: '20' });
    if (pathPrefix) params.append('path_prefix', pathPrefix);
    const res = await fetch(`/api/memory/search?${params.toString()}`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const items = data.results || [];
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
    <div class="flex gap-2 flex-wrap">
      <input id="semantic-add-key" type="text" placeholder="键 (如: user_name)" class="flex-1 min-w-[8rem] bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm">
      <select id="semantic-add-cat" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-300">
        <option value="fact">事实</option>
        <option value="preference">偏好</option>
        <option value="insight">洞察</option>
      </select>
      <select id="semantic-add-etype" class="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-300">
        <option value="">自动推断</option>
        <option value="family">家人</option>
        <option value="colleague">同事</option>
        <option value="project">项目</option>
        <option value="company">公司</option>
        <option value="preference">偏好</option>
        <option value="device">设备</option>
        <option value="identity">身份</option>
        <option value="event">事件</option>
        <option value="location">地点</option>
        <option value="general">通用</option>
      </select>
    </div>
    <input id="semantic-add-path" type="text" placeholder="路径 (可选, 如 /user/preferences)" class="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm">
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
  const entity_type = document.getElementById('semantic-add-etype').value;
  const memory_path = document.getElementById('semantic-add-path').value.trim();
  if (!key || !value) {
    showToast('键和值不能为空', 'error');
    return;
  }
  const body = { key, value, category };
  if (entity_type) body.entity_type = entity_type;
  if (memory_path) body.memory_path = memory_path;
  try {
    const res = await fetch('/api/memory/semantic', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
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
