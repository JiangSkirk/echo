import { escapeHtml, showToast, showLoading, showError, el, onDataClick, bindDataClicks, sanitizeRuntimeId } from '../utils/dom.js';

// Current block filter for search
let currentBlockPath = '';
let searchScopeAll = true;
let currentMemoryView = 'knowledge';
let memoryPageLimit = 20;
let memoryChromeBound = false;
let enhancedCache = null;
let enhancedIsAdmin = true;
const loadedViews = new Set();
// Top-level block paths currently expanded to show their sub-blocks.
const expandedBlocks = new Set();
// Inbox / modal state.
let currentProposals = [];     // pending proposals currently rendered
let proposalEditId = null;     // proposal being edited in the modal
let pendingBlockOp = null;     // { mode: 'move'|'merge', src }
let pendingConfirm = null;     // callback for the generic confirm modal

function parseMemoryId(raw) {
  if (typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= Number.MAX_SAFE_INTEGER) {
    return raw;
  }
  const text = String(raw ?? '').trim();
  if (!/^[0-9]{1,16}$/.test(text)) return null;
  return Number.parseInt(text, 10);
}

function bindMemoryActions(root) {
  if (!root) return;
  bindDataClicks(root, 'memId', (rawId, event) => {
    const id = parseMemoryId(rawId);
    if (id == null) return;
    const action = event.currentTarget.dataset.memAction;
    if (action === 'verify') verifyMemory(id);
    else if (action === 'audit') showMemoryAudit(id);
    else if (action === 'edit') editSemanticMemory(id);
    else if (action === 'delete') deleteSemanticMemory(id);
    else if (action === 'save') saveSemanticMemory(id);
    else if (action === 'cancel-edit') loadMemory();
    else if (action === 'approve') approveProposal(id);
    else if (action === 'edit-proposal') openProposalEdit(id);
    else if (action === 'reject') rejectProposal(id);
  });
}

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

const ENTITY_TONES = {
  family: 'mem-tone-warn',
  friend: 'mem-tone-ok',
  colleague: 'mem-tone-pine',
  project: 'mem-tone-celadon',
  company: 'mem-tone-pine',
  preference: 'mem-tone-ok',
  personality: 'mem-tone-cinnabar',
  body: 'mem-tone-cinnabar',
  device: 'mem-tone-warn',
  identity: 'mem-tone-cinnabar',
  event: 'mem-tone-pine',
  location: 'mem-tone-celadon',
  plan: 'mem-tone-celadon',
  chat: 'mem-tone-neutral',
  general: 'mem-tone-neutral',
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

const CATEGORY_LABELS = {
  fact: '事实',
  preference: '偏好',
  insight: '洞察',
};

const CATEGORY_TONES = {
  fact: 'mem-tone-pine',
  preference: 'mem-tone-cinnabar',
  insight: 'mem-tone-celadon',
};

function entityOptionsHtml(selected = '', includeAuto = false) {
  let html = includeAuto ? '<option value="">自动推断</option>' : '';
  for (const [val, label] of Object.entries(ENTITY_LABELS)) {
    html += `<option value="${val}"${val === selected ? ' selected' : ''}>${label}</option>`;
  }
  return html;
}

function categoryOptionsHtml(selected = 'fact') {
  return Object.entries(CATEGORY_LABELS)
    .map(([val, label]) => `<option value="${val}"${val === selected ? ' selected' : ''}>${label}</option>`)
    .join('');
}

function emptyState(title, hint, action = null) {
  const actionHtml = action
    ? `<button type="button" class="mem-btn mem-btn-primary" data-mem-empty-action="${escapeHtml(action.id)}">${escapeHtml(action.label)}</button>`
    : '';
  return `
    <div class="mem-empty">
      <div class="mem-empty-title">${escapeHtml(title)}</div>
      <div class="mem-empty-hint">${escapeHtml(hint)}</div>
      ${actionHtml}
    </div>
  `;
}

function bindEmptyActions(root) {
  if (!root) return;
  root.querySelectorAll('[data-mem-empty-action]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const action = btn.getAttribute('data-mem-empty-action');
      if (action === 'add') showAddSemanticModal();
      else if (action === 'organize') organizeNow();
    });
  });
}

function bindMemoryChrome() {
  if (memoryChromeBound) return;
  memoryChromeBound = true;
  document.querySelectorAll('#memory-subnav [data-mem-view]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const view = btn.getAttribute('data-mem-view');
      if (view) switchMemoryView(view);
    });
  });
  const more = document.getElementById('memory-load-more');
  if (more) more.addEventListener('click', loadMoreMemory);
}

export function switchMemoryView(view) {
  currentMemoryView = view || 'knowledge';
  document.querySelectorAll('#memory-subnav [data-mem-view]').forEach((btn) => {
    const on = btn.getAttribute('data-mem-view') === currentMemoryView;
    btn.classList.toggle('is-active', on);
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  document.querySelectorAll('#tab-memory [data-mem-panel]').forEach((panel) => {
    panel.classList.toggle('hidden', panel.getAttribute('data-mem-panel') !== currentMemoryView);
  });
  renderMemoryView(currentMemoryView);
}

function setLoadMoreVisible(show) {
  const btn = document.getElementById('memory-load-more');
  if (btn) btn.classList.toggle('hidden', !show);
}

function loadMoreMemory() {
  if (memoryPageLimit < 50) memoryPageLimit = 50;
  else memoryPageLimit = 100;
  loadMemory();
}

function setAdminHint(show) {
  const hint = document.getElementById('memory-admin-hint');
  if (hint) hint.classList.toggle('hidden', !show);
}

export async function loadMemory() {
  bindMemoryChrome();
  showLoading('memory-context', '加载记忆中...');
  showLoading('memory-working', '加载工作记忆...');
  showLoading('memory-semantic', '加载长期知识...');
  showLoading('memory-episodes', '加载情景记忆...');
  showLoading('memory-dreams', '加载梦境日志...');
  showLoading('memory-files', '加载记忆文件...');

  try {
    let embedderStatus = null;
    try {
      const diagRes = await fetch('/api/diag');
      if (diagRes.ok) {
        const diag = await diagRes.json();
        embedderStatus = diag.embedder || null;
      }
    } catch (_) {}

    const res = await fetch(`/api/memory/enhanced?limit=${memoryPageLimit}`);
    if (!res.ok) {
      if (res.status === 403) {
        enhancedIsAdmin = false;
        enhancedCache = null;
        setAdminHint(true);
        const basicRes = await fetch('/api/memory');
        const basicData = basicRes.ok ? await basicRes.json() : {};
        const ctxEl = document.getElementById('memory-context');
        if (ctxEl) ctxEl.textContent = basicData.context || '暂无上下文';
        ['memory-working', 'memory-episodes', 'memory-dreams', 'memory-files'].forEach((id) => {
          const node = document.getElementById(id);
          if (node) {
            node.innerHTML = emptyState('需要管理员权限', '此聚合视图仅管理员可打开。知识库搜索、区块和收件箱仍可使用。');
          }
        });
        const semEl = document.getElementById('memory-semantic');
        if (semEl) {
          semEl.innerHTML = emptyState('使用搜索或选择区块', '聚合列表需要管理员权限。你可以搜索知识，或从左侧打开一个区块。');
        }
        setLoadMoreVisible(false);
        loadedViews.clear();
        loadedViews.add('knowledge');
        loadedViews.add('context');
        loadBlockTree();
        loadProposals();
        switchMemoryView(currentMemoryView);
        return;
      }
      throw new Error('HTTP ' + res.status);
    }
    const data = await res.json();
    enhancedIsAdmin = true;
    enhancedCache = data;
    setAdminHint(false);

    const statusEl = document.getElementById('memory-embedder-status');
    const recoverBtn = document.getElementById('memory-embedder-recover');
    if (statusEl && embedderStatus) {
      statusEl.classList.remove('hidden');
      if (embedderStatus.active) {
        statusEl.className = 'mem-chip mem-chip-ok';
        statusEl.textContent = embedderStatus.provider || '就绪';
        if (recoverBtn) recoverBtn.classList.add('hidden');
      } else if (embedderStatus.fallback) {
        statusEl.className = 'mem-chip mem-chip-warn';
        statusEl.textContent = '降级: ' + embedderStatus.fallback;
        if (recoverBtn) recoverBtn.classList.remove('hidden');
      } else {
        statusEl.className = 'mem-chip';
        statusEl.textContent = embedderStatus.provider || '';
        if (recoverBtn) recoverBtn.classList.add('hidden');
      }
    }

    loadedViews.clear();
    renderKnowledgeFromCache(data);
    loadBlockTree();
    loadProposals();
    switchMemoryView(currentMemoryView);
  } catch (e) {
    showError('memory-context', '加载记忆失败: ' + e.message);
    ['memory-working', 'memory-semantic', 'memory-episodes', 'memory-dreams', 'memory-files'].forEach((id) => {
      const node = document.getElementById(id);
      if (node) node.innerHTML = '<div class="mem-muted">加载失败</div>';
    });
  }
}

function renderKnowledgeFromCache(data) {
  const ctxEl = document.getElementById('memory-context');
  if (ctxEl) ctxEl.textContent = data.context || '暂无上下文';

  const workEl = document.getElementById('memory-working');
  if (workEl) renderWorking(workEl, data.working_memories || []);

  const semEl = document.getElementById('memory-semantic');
  if (semEl) {
    const items = data.semantic_memories || [];
    if (items.length === 0) {
      semEl.innerHTML = emptyState('还没有长期知识', '对话里确认过的事实会出现在这里，也可以手动添加。', { id: 'add', label: '添加知识' });
      bindEmptyActions(semEl);
    } else {
      semEl.innerHTML = items.map((s) => renderSemanticMemoryItem(s)).join('');
      bindMemoryActions(semEl);
    }
    setLoadMoreVisible(items.length >= memoryPageLimit && memoryPageLimit < 100);
  }

  const epEl = document.getElementById('memory-episodes');
  if (epEl) renderEpisodes(epEl, data.episodes || []);

  const dreamEl = document.getElementById('memory-dreams');
  if (dreamEl) renderDreams(dreamEl, data.dream_logs || []);

  const filesEl = document.getElementById('memory-files');
  if (filesEl) renderFiles(filesEl, data.memory_files || []);

  loadedViews.add('knowledge');
  loadedViews.add('working');
  loadedViews.add('episodes');
  loadedViews.add('dreams');
  loadedViews.add('files');
  loadedViews.add('context');
}

function renderMemoryView(view) {
  if (view === 'knowledge' || loadedViews.has(view)) return;
  if (!enhancedIsAdmin && (view === 'working' || view === 'episodes' || view === 'dreams' || view === 'files')) {
    loadedViews.add(view);
    return;
  }
  if (!enhancedCache) return;
  renderKnowledgeFromCache(enhancedCache);
}

function renderWorking(root, items) {
  if (items.length === 0) {
    root.innerHTML = emptyState('暂无工作记忆', '当前会话里暂存的要点会显示在这里。');
    return;
  }
  root.innerHTML = items.map((w) => `
    <article class="mem-card">
      <div class="mem-card-head">
        <span class="mem-card-title">${escapeHtml(w.key || 'unknown')}</span>
        <span class="mem-muted">${escapeHtml(w.category || 'general')} · 重要性 ${w.importance || 0}</span>
      </div>
      <div class="mem-card-body">${escapeHtml(w.value || '')}</div>
    </article>
  `).join('');
}

function renderEpisodes(root, items) {
  if (!items.length) {
    root.innerHTML = emptyState('暂无情景记忆', '较长对话被整理后，会在这里留下摘要。');
    return;
  }
  root.innerHTML = items.map((e) => `
    <article class="mem-card">
      <div class="mem-card-body">${escapeHtml(e.summary)}</div>
      <div class="mem-card-meta">
        <span class="mem-muted">${new Date(e.created_at * 1000).toLocaleDateString()} · ${e.turn_count} 轮 · ${e.tokens_used} tokens</span>
        ${e.topics && e.topics.length > 0 ? `<span class="mem-chip">${e.topics.map((t) => '#' + escapeHtml(t)).join(' ')}</span>` : ''}
      </div>
    </article>
  `).join('');
}

function renderDreams(root, items) {
  if (!items.length) {
    root.innerHTML = emptyState('暂无梦境日志', '空闲整理周期完成后，会把巩固结果记在这里。');
    return;
  }
  root.innerHTML = items.map((d) => `
    <article class="mem-card">
      <div class="mem-card-head">
        <span class="mem-badge mem-tone-pine">${escapeHtml(d.phase)}</span>
        <span class="mem-muted">${new Date(d.created_at * 1000).toLocaleString()}</span>
      </div>
      <div class="mem-card-body">${escapeHtml(d.summary)}</div>
    </article>
  `).join('');
}

function renderFiles(root, files) {
  root.replaceChildren();
  if (files.length === 0) {
    root.innerHTML = emptyState('暂无记忆文件', '身份、偏好等 Markdown 档案会出现在这里。');
    return;
  }
  for (const rawName of files) {
    const name = sanitizeRuntimeId(rawName);
    if (!name) continue;
    const card = el('div', {
      className: 'mem-file-card',
      dataset: { memoryFile: name },
    });
    card.appendChild(el('div', { className: 'mem-card-title', text: `${name.toUpperCase()}.md` }));
    card.appendChild(el('div', { className: 'mem-muted', text: '点击编辑' }));
    onDataClick(card, 'memoryFile', (fileName) => {
      openMemoryFileEditor(fileName);
    });
    root.appendChild(card);
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
    treeEl.replaceChildren();
    const allBtn = el('div', {
      className: `mem-tree-row ${currentBlockPath === '' ? 'is-active' : ''}`,
    });
    allBtn.appendChild(el('span', { className: 'mem-tree-label', text: '全部' }));
    allBtn.addEventListener('click', (event) => {
      event.preventDefault();
      loadBlockMemories('');
    });
    treeEl.appendChild(allBtn);
    if (blocks.length === 0) {
      treeEl.appendChild(el('div', { className: 'mem-muted', text: '暂无区块' }));
    }
    for (const b of blocks) {
      const path = b.block_path || b.path || '';
      treeEl.appendChild(renderBlockNode(b, 0, true));
      if (expandedBlocks.has(path)) {
        try {
          const subRes = await fetch('/api/memory/blocks?prefix=' + encodeURIComponent(path));
          const subData = await subRes.json();
          for (const sb of (subData.blocks || [])) {
            if ((sb.block_path || '') !== path) treeEl.appendChild(renderBlockNode(sb, 1, false));
          }
        } catch (_) {}
      }
    }
    const toolbar = el('div', { className: 'mem-tree-tools' });
    const moveBtn = el('button', { className: 'mem-btn', text: '移动区块' });
    moveBtn.addEventListener('click', () => openBlockMove());
    const mergeBtn = el('button', { className: 'mem-btn', text: '合并区块' });
    mergeBtn.addEventListener('click', () => openBlockMerge());
    toolbar.appendChild(moveBtn);
    toolbar.appendChild(mergeBtn);
    treeEl.appendChild(toolbar);
  } catch (e) {
    treeEl.replaceChildren();
    treeEl.appendChild(el('div', { className: 'mem-muted', text: '加载失败' }));
  }
}

function renderBlockNode(block, depth, expandable) {
  const path = block.block_path || block.path || '';
  const name = path.split('/').pop() || path || '未知';
  const count = block.memory_count || block.count || 0;
  const isActive = currentBlockPath === path;
  const isOpen = expandedBlocks.has(path);
  const row = el('div', {
    className: `mem-tree-row ${isActive ? 'is-active' : ''}`,
  });
  if (depth > 0) row.style.marginLeft = '16px';
  const label = el('div', { className: 'mem-tree-label' });
  if (expandable) {
    const caret = el('span', { className: 'mem-tree-count', text: isOpen ? '▾ ' : '▸ ' });
    caret.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      toggleBlockExpand(path);
    });
    label.appendChild(caret);
  }
  label.appendChild(document.createTextNode(name + ' '));
  label.appendChild(el('span', { className: 'mem-tree-count', text: `(${count})` }));
  label.addEventListener('click', (event) => {
    event.preventDefault();
    loadBlockMemories(path);
  });
  const trash = el('button', {
    className: 'mem-icon-btn',
    attrs: { type: 'button', title: '删除区块', 'aria-label': '删除区块' },
    text: '×',
  });
  trash.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    openBlockDelete(path);
  });
  row.appendChild(label);
  row.appendChild(trash);
  return row;
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
  loadBlockTree();
  switchMemoryView('knowledge');
  const semEl = document.getElementById('memory-semantic');
  if (!semEl) return;

  if (!path) {
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
      semEl.innerHTML = emptyState('该区块暂无知识', '换一个区块，或把新知识归到这里。');
    } else {
      semEl.innerHTML = items.map((s) => renderSemanticMemoryItem(s)).join('');
      bindMemoryActions(semEl);
    }
    setLoadMoreVisible(false);
  } catch (e) {
    semEl.innerHTML = '<div class="mem-muted">加载失败: ' + escapeHtml(e.message) + '</div>';
  }
}

function getConfidenceBadge(confidence) {
  const c = confidence || 0.5;
  if (c >= 0.8) return { label: '高可信', tone: 'ok' };
  if (c >= 0.5) return { label: '中可信', tone: 'warn' };
  return { label: '低可信', tone: 'bad' };
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
  const memId = parseMemoryId(s.id);
  if (memId == null) return '';
  const confBadge = getConfidenceBadge(s.confidence);
  const etype = s.entity_type || 'general';
  const entityTone = ENTITY_TONES[etype] || ENTITY_TONES.general;
  const entityLabel = ENTITY_LABELS[etype] || etype;
  const catTone = CATEGORY_TONES[s.category] || 'mem-tone-neutral';
  const isVerified = (s.last_verified_at || 0) > 0;
  const pct = ((s.confidence || 0.5) * 100).toFixed(0);
  return `
    <article class="mem-card" data-memory-id="${memId}" data-category="${escapeHtml(s.category || 'fact')}" data-entity-type="${escapeHtml(etype)}" data-memory-path="${escapeHtml(s.memory_path || '')}" data-entity-name="${escapeHtml(s.entity_name || '')}">
      <div class="mem-card-head">
        <div class="mem-card-meta">
          <span class="mem-card-title">${escapeHtml(s.key || 'unknown')}</span>
          <span class="mem-badge ${catTone}">${escapeHtml(CATEGORY_LABELS[s.category] || s.category || 'fact')}</span>
          <span class="mem-conf mem-conf-${confBadge.tone}" title="${confBadge.label}"><span class="mem-conf-dot"></span>${pct}%</span>
          <span class="mem-badge">${escapeHtml(getSourceLabel(s.source))}</span>
          <span class="mem-badge ${entityTone}">${escapeHtml(entityLabel)}</span>
          ${isVerified ? '<span class="mem-chip mem-chip-ok">已验证</span>' : ''}
        </div>
        <div class="mem-card-actions">
          <button type="button" data-mem-action="verify" data-mem-id="${memId}" class="mem-icon-btn" title="验证" aria-label="验证"><i class="fas fa-check"></i></button>
          <button type="button" data-mem-action="audit" data-mem-id="${memId}" class="mem-icon-btn" title="历史版本" aria-label="历史版本"><i class="fas fa-history"></i></button>
          <button type="button" data-mem-action="edit" data-mem-id="${memId}" class="mem-icon-btn" title="编辑" aria-label="编辑"><i class="fas fa-pen"></i></button>
          <button type="button" data-mem-action="delete" data-mem-id="${memId}" class="mem-icon-btn" title="删除" aria-label="删除"><i class="fas fa-trash"></i></button>
        </div>
      </div>
      <div class="mem-card-body memory-value">${escapeHtml(s.value || '')}</div>
      ${s.memory_path ? `<div class="mem-card-path">${escapeHtml(s.memory_path)}</div>` : ''}
      <div class="memory-audit mem-audit hidden" id="memory-audit-${memId}"></div>
    </article>
  `;
}

export function editSemanticMemory(id) {
  const memId = parseMemoryId(id);
  if (memId == null) return;
  const card = document.querySelector(`[data-memory-id="${memId}"]`);
  if (!card) return;
  const valueEl = card.querySelector('.memory-value');
  const currentValue = valueEl.textContent;
  const currentCategory = card.dataset.category || 'fact';
  const currentEtype = card.dataset.entityType || 'general';
  const currentPath = card.dataset.memoryPath || '';
  const currentEname = card.dataset.entityName || '';

  valueEl.innerHTML = `
    <div class="mem-form">
      <textarea id="sem-edit-${memId}" rows="3">${escapeHtml(currentValue)}</textarea>
      <div class="mem-form-actions">
        <select id="sem-cat-${memId}">${categoryOptionsHtml(currentCategory)}</select>
        <select id="sem-etype-${memId}">${entityOptionsHtml(currentEtype)}</select>
        <input id="sem-path-${memId}" type="text" value="${escapeHtml(currentPath)}" placeholder="路径">
        <input id="sem-ename-${memId}" type="text" value="${escapeHtml(currentEname)}" placeholder="实体名">
        <button type="button" data-mem-action="save" data-mem-id="${memId}" class="mem-btn mem-btn-primary">保存</button>
        <button type="button" data-mem-action="cancel-edit" data-mem-id="${memId}" class="mem-btn">取消</button>
      </div>
    </div>
  `;
  bindMemoryActions(valueEl);
}

export async function showMemoryAudit(id) {
  const auditEl = document.getElementById(`memory-audit-${id}`);
  if (!auditEl) return;
  if (!auditEl.classList.contains('hidden')) {
    auditEl.classList.add('hidden');
    return;
  }
  auditEl.classList.remove('hidden');
  auditEl.textContent = '加载历史...';
  try {
    const res = await fetch(`/api/memory/audit?memory_id=${id}&limit=20`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const entries = data.entries || [];
    if (entries.length === 0) {
      auditEl.textContent = '暂无变更记录';
      return;
    }
    auditEl.innerHTML = entries.map((e) => {
      const actionMap = { create: '创建', update: '更新', delete: '删除', verify: '验证' };
      const time = new Date(e.created_at * 1000).toLocaleString();
      return `
        <div>
          <div>${escapeHtml(actionMap[e.action] || e.action)} · ${escapeHtml(time)} · ${escapeHtml(getSourceLabel(e.source))}</div>
          ${e.old_value ? `<div class="mem-muted">${escapeHtml(e.old_value.substring(0, 100))}</div>` : ''}
          ${e.new_value ? `<div>${escapeHtml(e.new_value.substring(0, 100))}</div>` : ''}
        </div>
      `;
    }).join('');
  } catch (e) {
    auditEl.textContent = '加载失败';
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

export function deleteSemanticMemory(id) {
  openConfirm('删除知识', '确定删除这条知识吗？此操作不可恢复。', () => doDeleteSemanticMemory(id));
}

async function doDeleteSemanticMemory(id) {
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

export async function loadProposals() {
  const root = document.getElementById('memory-proposals');
  if (!root) return;
  try {
    const res = await fetch('/api/memory/proposals?status=pending&limit=50');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const items = data.proposals || [];
    currentProposals = items;
    const countEl = document.getElementById('memory-proposals-count');
    if (countEl) countEl.textContent = items.length ? String(items.length) : '';
    const allBtn = document.getElementById('memory-approve-all-btn');
    if (allBtn) allBtn.classList.toggle('hidden', items.length === 0);
    if (items.length === 0) {
      root.innerHTML = emptyState('收件箱是空的', '整理最近对话后，待确认的记忆会出现在这里。', { id: 'organize', label: '立即整理' });
      bindEmptyActions(root);
      return;
    }
    root.innerHTML = items.map(renderProposal).join('');
    bindMemoryActions(root);
    loadedViews.add('inbox');
  } catch (e) {
    root.innerHTML = '<div class="mem-muted">加载收件箱失败</div>';
  }
}

function renderProposal(p) {
  const memId = parseMemoryId(p.id);
  if (memId == null) return '';
  const conf = Math.round((p.confidence || 0) * 100);
  const etype = p.entity_type || 'general';
  const entityTone = ENTITY_TONES[etype] || ENTITY_TONES.general;
  const entityLabel = ENTITY_LABELS[etype] || etype;
  const confInfo = getConfidenceBadge(p.confidence);
  const srcLabel = getSourceLabel(p.source);
  return `
    <article class="mem-card mem-inbox-card">
      <div class="mem-muted">${escapeHtml(srcLabel)}想记住 · <span class="mem-badge ${entityTone}">${escapeHtml(entityLabel)}</span></div>
      <div class="mem-card-head">
        <div class="mem-card-body">${p.key ? `<span class="mem-muted">${escapeHtml(p.key)}：</span>` : ''}${escapeHtml(p.value || '')}</div>
        <div class="mem-card-actions">
          <button type="button" data-mem-action="approve" data-mem-id="${memId}" class="mem-btn mem-btn-ok" title="确认并写入">确认</button>
          <button type="button" data-mem-action="edit-proposal" data-mem-id="${memId}" class="mem-btn" title="编辑后确认">编辑</button>
          <button type="button" data-mem-action="reject" data-mem-id="${memId}" class="mem-btn mem-btn-danger" title="拒绝">拒绝</button>
        </div>
      </div>
      ${p.memory_path ? `<div class="mem-card-path">${escapeHtml(p.memory_path)}</div>` : ''}
      <div class="mem-conf mem-conf-${confInfo.tone}" title="${confInfo.label}"><span class="mem-conf-dot"></span>${confInfo.label} ${conf}%</div>
      ${p.evidence ? `<details class="mem-muted"><summary>查看证据</summary><div>${escapeHtml(p.evidence)}</div></details>` : ''}
    </article>
  `;
}

export async function organizeNow() {
  const btn = document.getElementById('memory-organize-btn');
  const statusEl = document.getElementById('memory-organize-status');
  if (btn) { btn.disabled = true; btn.textContent = '整理中...'; }
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
    switchMemoryView('inbox');
    loadMemory();
  } catch (e) {
    showToast('整理失败: ' + e.message, 'error');
    if (statusEl) statusEl.textContent = '整理失败：' + e.message;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '立即整理'; }
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
  const ids = currentProposals.map((p) => p.id);
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
  const p = currentProposals.find((x) => x.id === id);
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
  const etype = (document.getElementById('proposal-edit-etype')?.value || '');
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
    btn.textContent = '恢复中...';
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
      btn.textContent = '恢复嵌入器';
    }
  }
}

export function toggleSearchScope() {
  searchScopeAll = !searchScopeAll;
  const btn = document.getElementById('semantic-search-scope');
  if (btn) {
    btn.textContent = searchScopeAll ? '全部' : '当前区块';
    btn.classList.toggle('is-active', !searchScopeAll);
  }
}

export async function searchSemantic() {
  switchMemoryView('knowledge');
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
      container.innerHTML = emptyState('未找到匹配的知识', '换个关键词，或清空搜索查看全部。');
    } else {
      container.innerHTML = items.map((s) => renderSemanticMemoryItem(s)).join('');
      bindMemoryActions(container);
    }
    setLoadMoreVisible(false);
  } catch (e) {
    container.innerHTML = '<div class="mem-muted">搜索失败: ' + escapeHtml(e.message) + '</div>';
  }
}

export function showAddSemanticModal() {
  switchMemoryView('knowledge');
  const container = document.getElementById('memory-semantic');
  const existing = document.getElementById('semantic-add-form');
  if (existing) {
    existing.remove();
    return;
  }
  const form = document.createElement('div');
  form.id = 'semantic-add-form';
  form.className = 'mem-card mem-form';
  form.innerHTML = `
    <div class="mem-form-actions">
      <input id="semantic-add-key" type="text" placeholder="键 (如: user_name)">
      <select id="semantic-add-cat">${categoryOptionsHtml('fact')}</select>
      <select id="semantic-add-etype">${entityOptionsHtml('', true)}</select>
    </div>
    <input id="semantic-add-path" type="text" placeholder="路径 (可选, 如 /user/preferences)">
    <textarea id="semantic-add-value" rows="2" placeholder="值..."></textarea>
    <div class="mem-form-actions">
      <button type="button" data-add-action="save" class="mem-btn mem-btn-primary">保存</button>
      <button type="button" data-add-action="cancel" class="mem-btn">取消</button>
    </div>
  `;
  form.querySelector('[data-add-action="save"]')?.addEventListener('click', () => submitSemanticMemory());
  form.querySelector('[data-add-action="cancel"]')?.addEventListener('click', () => form.remove());
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
  const safeName = sanitizeRuntimeId(name);
  if (!safeName) return;
  name = safeName;
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
    showToast('记忆文件已保存');
  } catch (e) {
    showToast('保存失败: ' + e.message, 'error');
  }
}

export function closeMemoryFileEditor() {
  const modal = document.getElementById('memory-file-modal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}
