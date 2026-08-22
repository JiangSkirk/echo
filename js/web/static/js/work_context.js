/* JS Agent — Work context panel (Work mode only).
   Data comes from the closed /api/appshell/work-context projection plus the
   existing per-child approval decision endpoints. No polling: refreshes on
   mode entry, session change, relevant WS events, and manual refresh only. */

import { state } from '../state/store.js';
import { escapeHtml, showToast } from '../utils/dom.js';
import { iconSvg } from './icons.js';

const GRANTS_LABELS = {
  bound: null, // rendered with count
  none: '尚无活动目录授权',
  unavailable: '授权状态不可用',
};

let _loading = false;
let _lastEnvelope = null;

function isWork() {
  return document.body.dataset.product === 'js-work';
}

function shortHandle(handle) {
  if (!handle || typeof handle !== 'string') return '工作区';
  return handle.length > 12 ? `${handle.slice(0, 10)}…` : handle;
}

function setText(id, text) {
  const node = document.getElementById(id);
  if (node) node.textContent = text;
}

function renderBand(summary) {
  setText('band-workspace', shortHandle(summary && summary.workspace));
  const grants = summary ? summary.grants_state : 'unavailable';
  if (grants === 'bound') {
    setText('band-grants', `${summary.grants_count} 个已授权目录`);
  } else {
    setText('band-grants', GRANTS_LABELS[grants] || GRANTS_LABELS.unavailable);
  }
  setText(
    'band-approval-mode',
    summary && summary.write_policy === 'requires_approval' ? '写入需审批' : '写入策略不可用',
  );
}

function renderList(containerId, items, renderItem, emptyText) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'wcp-empty';
    empty.textContent = emptyText;
    container.appendChild(empty);
    return;
  }
  for (const item of items) {
    container.appendChild(renderItem(item));
  }
}

function fileItem(ref) {
  const row = document.createElement('div');
  row.className = 'wcp-item';
  const iconName = ref.path.endsWith('.xlsx') || ref.path.endsWith('.xls')
    ? 'file-spreadsheet'
    : 'file-text';
  row.innerHTML = `${iconSvg(iconName)}<span class="wcp-item-text" title="${escapeHtml(
    `${ref.root}/${ref.path}`,
  )}">${escapeHtml(ref.path)}</span>`;
  return row;
}

function artifactItem(ref) {
  const row = document.createElement('div');
  row.className = 'wcp-item';
  const label = typeof ref.uri === 'string' ? ref.uri.replace(/^echo:\/\//, '') : 'artifact';
  row.innerHTML = `${iconSvg('file-output')}<span class="wcp-item-text" title="${escapeHtml(
    label,
  )}">${escapeHtml(label)}</span>`;
  return row;
}

function approvalItem(approval) {
  const wrap = document.createElement('div');
  const title = approval.tool_name || approval.tool || '工具调用';
  const target = approval.target || approval.summary || '';
  wrap.innerHTML =
    `<div class="wcp-item">${iconSvg('circle-alert')}<span class="wcp-item-text">${escapeHtml(
      title,
    )}</span></div>` +
    (target
      ? `<div class="wcp-item-sub">${escapeHtml(String(target)).slice(0, 80)}</div>`
      : '');
  const actions = document.createElement('div');
  actions.className = 'wcp-approval-actions';
  const approve = document.createElement('button');
  approve.type = 'button';
  approve.className = 'btn-approve';
  approve.textContent = '批准';
  approve.addEventListener('click', () => decideApproval(approval.id, 'approve'));
  const reject = document.createElement('button');
  reject.type = 'button';
  reject.className = 'btn-reject';
  reject.textContent = '拒绝';
  reject.addEventListener('click', () => decideApproval(approval.id, 'reject'));
  actions.appendChild(approve);
  actions.appendChild(reject);
  wrap.appendChild(actions);
  return wrap;
}

async function decideApproval(requestId, action) {
  try {
    const res = await fetch(`/api/echo/approvals/${encodeURIComponent(requestId)}/decision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || `HTTP ${res.status}`);
    }
    showToast(action === 'approve' ? '已批准' : '已拒绝');
  } catch (err) {
    showToast(`审批操作失败: ${err.message}`, 'error');
  }
  await refreshWorkContext();
}

function renderBlocked(note) {
  for (const id of ['wcp-files', 'wcp-artifacts', 'wcp-approvals', 'wcp-current-task']) {
    const container = document.getElementById(id);
    if (!container) continue;
    container.replaceChildren();
    const div = document.createElement('div');
    div.className = 'wcp-blocked';
    div.textContent = note;
    container.appendChild(div);
  }
}

/** Actionable approvals for the current session (real child endpoint). */
async function loadSessionApprovals() {
  const sessionId = state.sessionId;
  try {
    const res = await fetch('/api/echo/approvals');
    if (!res.ok) return { ok: false, items: [] };
    const data = await res.json();
    const all = Array.isArray(data.approvals) ? data.approvals : [];
    const items = sessionId
      ? all.filter((a) => !a.session_id || a.session_id === sessionId)
      : all;
    return { ok: true, items: items.slice(0, 10) };
  } catch (e) {
    return { ok: false, items: [] };
  }
}

export async function refreshWorkContext() {
  if (!isWork() || _loading) return;
  const sessionId = state.sessionId;
  const panel = document.getElementById('work-context-panel');
  if (!panel) return;
  _loading = true;
  try {
    if (!sessionId) {
      // No session yet: the workspace handle is still server-authoritative
      // (capabilities); grant/policy stay honestly unknown.
      const caps = state.appShellCapabilities;
      const handle = caps && caps.workspace_handles ? caps.workspace_handles.work : null;
      renderBand({ workspace: handle, grants_state: 'unavailable', write_policy: 'unknown' });
      renderList('wcp-files', [], fileItem, '发送消息后显示会话文件');
      renderList('wcp-artifacts', [], artifactItem, '暂无生成物');
      renderList('wcp-approvals', [], approvalItem, '暂无待审批事项');
      renderList('wcp-current-task', [], (x) => x, '暂无进行中的任务');
      return;
    }
    const params = new URLSearchParams({ session_id: sessionId, limit: '25' });
    const res = await fetch(`/api/appshell/work-context?${params}`);
    let envelope = null;
    try {
      envelope = await res.json();
    } catch (e) {
      envelope = null;
    }
    if (!envelope || envelope.schema !== 'WorkContextEnvelopeV1') {
      renderBlocked(res.status === 503 ? '工作上下文暂不可用' : '工作上下文数据无效');
      return;
    }
    _lastEnvelope = envelope;
    renderBand(envelope.workspace_summary);
    if (envelope.status === 'blocked') {
      renderBlocked('工作上下文数据源暂不可用');
      return;
    }
    renderList(
      'wcp-files',
      envelope.files || [],
      fileItem,
      '当前会话暂无文件',
    );
    renderList(
      'wcp-artifacts',
      envelope.artifacts || [],
      artifactItem,
      '暂无已验证生成物',
    );
    const task = envelope.current_task;
    renderList(
      'wcp-current-task',
      task ? [task] : [],
      (t) => {
        const row = document.createElement('div');
        row.className = 'wcp-item';
        const pct = Math.round((t.progress || 0) * 100);
        row.innerHTML = `${iconSvg('list-checks')}<span class="wcp-item-text">${escapeHtml(
          t.title,
        )} · ${escapeHtml(t.status)} ${pct}%</span>`;
        return row;
      },
      '暂无进行中的任务',
    );
    if (envelope.status === 'partial') {
      const note = document.createElement('div');
      note.className = 'wcp-blocked';
      note.textContent = '部分数据暂不可用';
      const body = panel.querySelector('.wcp-body');
      if (body) body.appendChild(note);
    }
    // Actionable approvals come from the real child endpoint (has request ids).
    const approvals = await loadSessionApprovals();
    renderList(
      'wcp-approvals',
      approvals.items,
      approvalItem,
      approvals.ok ? '暂无待审批事项' : '审批列表暂不可用',
    );
  } catch (e) {
    renderBlocked('工作上下文加载失败');
  } finally {
    _loading = false;
    // Clean up any stale partial note before next render cycle.
    const body = panel.querySelector('.wcp-body');
    if (body) {
      body.querySelectorAll(':scope > .wcp-blocked').forEach((node) => node.remove());
    }
  }
}

export function initWorkContext() {
  const grantBtn = document.getElementById('wcp-directory-grant');
  if (grantBtn) {
    grantBtn.addEventListener('click', () => {
      showToast(
        '目录授权尚未启用；当前仅使用已绑定工作区和本次上传文件，未授予额外目录权限。',
      );
    });
  }
  const refreshBtn = document.getElementById('wcp-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      refreshWorkContext();
    });
  }
  // Refresh triggers (no polling): session established/changed, turn finished,
  // mode entry (dispatched by shell.js), and explicit user refresh.
  document.addEventListener('js:session-updated', () => {
    refreshWorkContext();
  });
  document.addEventListener('js:approvals-updated', () => {
    if (isWork()) refreshWorkContext();
  });
  document.addEventListener('js:product-mode-applied', () => {
    if (isWork()) refreshWorkContext();
  });
  // First paint: initShell/applyProductMode ran before this listener existed.
  if (isWork()) refreshWorkContext();
}
