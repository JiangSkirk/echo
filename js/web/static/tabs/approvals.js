import { state } from '../state/store.js';
import { showToast } from '../utils/dom.js';

const POLL_INTERVAL_MS = 15_000;
let approvalsPollTimer = null;
let approvalsLoadPromise = null;

function element(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function safeText(value, fallback = '-') {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch (_) {
    return String(value);
  }
}

function formatArguments(argumentsValue) {
  try {
    return JSON.stringify(argumentsValue || {}, null, 2);
  } catch (_) {
    return '{}';
  }
}

function formatTimestamp(timestamp) {
  if (!timestamp) return '时间未知';
  const date = new Date(Number(timestamp) * 1000);
  return Number.isNaN(date.getTime()) ? '时间未知' : date.toLocaleString('zh-CN');
}

async function readApiError(response) {
  const data = await response.json().catch(() => null);
  return data?.detail || data?.error || `HTTP ${response.status}`;
}

function updatePendingCount(count) {
  const badge = document.getElementById('approvals-pending-count');
  if (!badge) return;
  badge.textContent = String(count);
  badge.classList.toggle('hidden', count === 0);
}

function renderLoading() {
  const container = document.getElementById('approvals-list');
  if (!container) return;
  container.replaceChildren(
    element('div', 'text-gray-400 text-sm py-8 text-center', '正在加载审批队列...'),
  );
}

function renderLoadError(message) {
  const container = document.getElementById('approvals-list');
  if (!container) return;
  const error = element('div', 'border border-red-800 bg-red-950/40 text-red-300 text-sm rounded-lg p-4');
  error.setAttribute('role', 'alert');
  error.textContent = `加载审批队列失败: ${message}`;
  container.replaceChildren(error);
}

function renderEmptyState() {
  const container = document.getElementById('approvals-list');
  if (!container) return;
  const empty = element('div', 'border border-gray-800 bg-gray-900 text-center rounded-lg py-12 px-4');
  const icon = element('i', 'fas fa-check-circle text-3xl text-green-400 mb-3');
  icon.setAttribute('aria-hidden', 'true');
  empty.append(icon, element('div', 'text-gray-200 font-medium', '暂无待审批操作'));
  empty.append(element('p', 'text-sm text-gray-500 mt-1', '需要人工确认的工具调用会显示在这里。'));
  container.replaceChildren(empty);
}

function createIconButton(iconClass, title, onClick, colorClass) {
  const button = element(
    'button',
    `w-8 h-8 rounded flex items-center justify-center transition ${colorClass}`,
  );
  button.type = 'button';
  button.title = title;
  button.setAttribute('aria-label', title);
  const icon = element('i', `fas ${iconClass}`);
  icon.setAttribute('aria-hidden', 'true');
  button.appendChild(icon);
  button.addEventListener('click', onClick);
  return button;
}

function showActionError(card, message) {
  let error = card.querySelector('[data-approval-action-error]');
  if (!error) {
    error = element('div', 'text-xs text-red-400 mt-3');
    error.dataset.approvalActionError = 'true';
    error.setAttribute('role', 'alert');
    card.appendChild(error);
  }
  error.textContent = message;
}

function clearActionError(card) {
  const error = card.querySelector('[data-approval-action-error]');
  if (error) error.remove();
}

function setCardBusy(card, busy) {
  card.querySelectorAll('button').forEach(button => {
    button.disabled = busy;
    button.classList.toggle('opacity-50', busy);
    button.classList.toggle('cursor-not-allowed', busy);
  });
}

async function postDecision(requestId, payload) {
  const response = await fetch(
    `/api/echo/approvals/${encodeURIComponent(requestId)}/decision`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
  );
  if (!response.ok) throw new Error(await readApiError(response));
  return response.json();
}

async function submitDecision(card, requestId, payload) {
  clearActionError(card);
  setCardBusy(card, true);
  try {
    await postDecision(requestId, payload);
    showToast('审批决定已提交', 'success');
    await loadApprovals();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    showActionError(card, `提交失败: ${message}`);
    showToast(`审批提交失败: ${message}`, 'error');
  } finally {
    if (card.isConnected) setCardBusy(card, false);
  }
}

function removeDecisionEditor(card) {
  const editor = card.querySelector('[data-approval-editor]');
  if (editor) editor.remove();
}

function showEditEditor(card, approval) {
  removeDecisionEditor(card);
  clearActionError(card);
  const editor = element('div', 'mt-3 border-t border-gray-800 pt-3');
  editor.dataset.approvalEditor = 'edit';
  const label = element('label', 'block text-xs text-gray-400 mb-1', '编辑后的参数 (JSON object)');
  const input = element('textarea', 'w-full min-h-32 bg-gray-950 border border-gray-700 rounded p-2 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500');
  input.value = formatArguments(approval.arguments);
  input.setAttribute('aria-label', '编辑后的参数 JSON');
  const actions = element('div', 'flex justify-end gap-2 mt-2');
  const cancel = createIconButton('fa-times', '取消编辑', () => removeDecisionEditor(card), 'bg-gray-800 hover:bg-gray-700 text-gray-300');
  const submit = createIconButton('fa-check', '提交编辑后的参数', async () => {
    let editedArguments;
    try {
      editedArguments = JSON.parse(input.value);
    } catch (_) {
      showActionError(card, 'edited_arguments must be a JSON object');
      return;
    }
    if (!editedArguments || Array.isArray(editedArguments) || typeof editedArguments !== 'object') {
      showActionError(card, 'edited_arguments must be a JSON object');
      return;
    }
    await submitDecision(card, approval.id, { action: 'edit', edited_arguments: editedArguments });
  }, 'bg-blue-700 hover:bg-blue-600 text-white');
  actions.append(cancel, submit);
  editor.append(label, input, actions);
  card.appendChild(editor);
  input.focus();
}

function showRespondEditor(card, approval) {
  removeDecisionEditor(card);
  clearActionError(card);
  const editor = element('div', 'mt-3 border-t border-gray-800 pt-3');
  editor.dataset.approvalEditor = 'respond';
  const label = element('label', 'block text-xs text-gray-400 mb-1', '给 Agent 的回复');
  const input = element('textarea', 'w-full min-h-24 bg-gray-950 border border-gray-700 rounded p-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500');
  input.setAttribute('aria-label', '给 Agent 的回复');
  const actions = element('div', 'flex justify-end gap-2 mt-2');
  const cancel = createIconButton('fa-times', '取消回复', () => removeDecisionEditor(card), 'bg-gray-800 hover:bg-gray-700 text-gray-300');
  const submit = createIconButton('fa-paper-plane', '提交回复', async () => {
    const response = input.value.trim();
    if (!response) {
      showActionError(card, 'response must not be empty');
      return;
    }
    await submitDecision(card, approval.id, { action: 'respond', response });
  }, 'bg-blue-700 hover:bg-blue-600 text-white');
  actions.append(cancel, submit);
  editor.append(label, input, actions);
  card.appendChild(editor);
  input.focus();
}

function renderApproval(approval) {
  const card = element('article', 'bg-gray-900 border border-gray-800 rounded-lg p-4');
  const header = element('div', 'flex flex-wrap items-start justify-between gap-3');
  const identity = element('div', 'min-w-0');
  const HIGHLIGHT_TOOLS = new Set(['python', 'shell']);
  const toolName = safeText(approval.tool_name, '未知工具');
  const isDangerous = HIGHLIGHT_TOOLS.has(String(approval.tool_name || ''));
  const title = element(
    'h3',
    isDangerous
      ? 'font-mono text-sm font-semibold text-amber-300 break-all'
      : 'font-mono text-sm font-semibold text-blue-300 break-all',
    toolName,
  );
  identity.append(title);
  if (isDangerous) {
    identity.append(
      element('p', 'text-xs text-amber-400 mt-1', '高危命令 — 请完整核对下方参数'),
    );
  }
  identity.append(element('p', 'text-xs text-gray-500 mt-1', `${safeText(approval.context, '未知上下文')} · ${formatTimestamp(approval.timestamp)}`));
  const actions = element('div', 'flex gap-1 shrink-0');
  actions.append(
    createIconButton('fa-check', '批准', () => submitDecision(card, approval.id, { action: 'approve' }), 'bg-green-900/50 hover:bg-green-800 text-green-300'),
    createIconButton('fa-pen', '编辑参数', () => showEditEditor(card, approval), 'bg-blue-900/50 hover:bg-blue-800 text-blue-300'),
    createIconButton('fa-comment-dots', '回复 Agent', () => showRespondEditor(card, approval), 'bg-yellow-900/50 hover:bg-yellow-800 text-yellow-300'),
    createIconButton('fa-times', '拒绝', () => submitDecision(card, approval.id, { action: 'reject' }), 'bg-red-900/50 hover:bg-red-800 text-red-300'),
  );
  header.append(identity, actions);
  const meta = element('p', 'text-xs text-gray-500 mt-3 break-all', `会话: ${safeText(approval.session_id)} · 运行: ${safeText(approval.run_id)}`);
  const argumentLabel = element('div', 'text-xs text-gray-400 mt-3 mb-1', '参数 (服务端已脱敏)');
  const argumentsPre = element('pre', 'bg-gray-950 border border-gray-800 rounded p-3 text-xs text-gray-300 font-mono whitespace-pre-wrap break-words max-h-64 overflow-auto');
  argumentsPre.textContent = formatArguments(approval.arguments);
  card.append(header, meta, argumentLabel, argumentsPre);
  return card;
}

function renderApprovals(approvals) {
  updatePendingCount(approvals.length);
  if (approvals.length === 0) {
    renderEmptyState();
    return;
  }
  const container = document.getElementById('approvals-list');
  if (!container) return;
  const fragment = document.createDocumentFragment();
  approvals.forEach(approval => fragment.appendChild(renderApproval(approval)));
  container.replaceChildren(fragment);
}

export async function loadApprovals() {
  if (approvalsLoadPromise) return approvalsLoadPromise;
  renderLoading();
  approvalsLoadPromise = (async () => {
    try {
      const response = await fetch('/api/echo/approvals');
      if (!response.ok) throw new Error(await readApiError(response));
      const data = await response.json();
      const approvals = Array.isArray(data.approvals) ? data.approvals : [];
      renderApprovals(approvals);
      document.dispatchEvent(
        new CustomEvent('js:approvals-updated', { detail: { count: approvals.length } }),
      );
    } catch (error) {
      updatePendingCount(0);
      renderLoadError(error instanceof Error ? error.message : String(error));
    } finally {
      approvalsLoadPromise = null;
    }
  })();
  return approvalsLoadPromise;
}

function shouldPollApprovals() {
  if (document.visibilityState !== 'visible') return false;
  const approvalsActive = state.currentTab === 'approvals';
  const badge = document.getElementById('approvals-pending-count');
  const hasPending = Boolean(badge && !badge.classList.contains('hidden'));
  return approvalsActive || hasPending;
}

export function startApprovalsPolling() {
  if (approvalsPollTimer) return;
  approvalsPollTimer = window.setInterval(() => {
    if (shouldPollApprovals()) loadApprovals();
  }, POLL_INTERVAL_MS);
}

export function stopApprovalsPolling() {
  if (!approvalsPollTimer) return;
  window.clearInterval(approvalsPollTimer);
  approvalsPollTimer = null;
}
