/* Friends v1 panel. Hidden unless friends_enabled mounts /api/friends. */

import { bindDataClicks, el, sanitizeRuntimeId, showToast } from '../utils/dom.js';

let selectedFriendId = '';
let lastAcceptReceipt = '';

function friendIdOf(item) {
  return sanitizeRuntimeId(item.friend_id_full || item.friend_id || '');
}

async function readApiError(response) {
  const data = await response.json().catch(() => null);
  const detail = data && data.detail;
  if (typeof detail === 'string' && detail) return detail;
  if (detail && typeof detail === 'object' && detail.code) return String(detail.code);
  return data && data.error ? String(data.error) : `HTTP ${response.status}`;
}

export async function loadFriends() {
  const panel = document.getElementById('friends-panel');
  const warning = document.getElementById('friends-warning');
  if (!panel) return;
  panel.replaceChildren(el('div', { className: 'text-gray-400 text-sm', text: '加载 Friends...' }));
  try {
    const status = await fetch('/api/friends/status');
    if (status.status === 404) {
      panel.replaceChildren(el('div', {
        className: 'text-gray-400 text-sm',
        text: 'Friends 默认关闭。开启 friends_enabled 后可邀请、拉黑与发污点任务。',
      }));
      if (warning) warning.classList.add('hidden');
      return;
    }
    if (!status.ok) throw new Error(await readApiError(status));
    const info = await status.json();
    if (warning) warning.classList.toggle('hidden', !info.warn_native);
    const list = await fetch('/api/friends');
    if (!list.ok) throw new Error(await readApiError(list));
    const data = await list.json();
    renderFriends(panel, Array.isArray(data.friends) ? data.friends : []);
    if (selectedFriendId) await loadFriendMessages(selectedFriendId, { silent: true });
  } catch (error) {
    panel.replaceChildren(el('div', {
      className: 'text-red-400 text-sm',
      text: '无法加载 Friends：' + (error && error.message ? error.message : '未知错误'),
    }));
  }
}

function renderFriends(panel, friends) {
  panel.replaceChildren();

  const inviteBox = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3' });
  inviteBox.appendChild(el('h3', { className: 'font-bold text-sm', text: '邀请卡' }));
  inviteBox.appendChild(el('p', {
    className: 'text-xs text-gray-500',
    text: '邀请卡是二维码载荷。本机离线复制给对方，不要发到公开网络。',
  }));
  const inviteActions = el('div', { className: 'flex flex-wrap gap-2' });
  const createBtn = el('button', {
    className: 'text-sm bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg',
    text: '生成邀请卡',
    dataset: { friendsAction: 'create-invite' },
  });
  inviteActions.appendChild(createBtn);
  inviteBox.appendChild(inviteActions);
  const inviteCard = el('textarea', {
    className: 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono',
    attrs: { id: 'friends-invite-card', rows: '3', readonly: true, spellcheck: 'false' },
  });
  inviteBox.appendChild(inviteCard);
  panel.appendChild(inviteBox);

  const acceptBox = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3' });
  acceptBox.appendChild(el('h3', { className: 'font-bold text-sm', text: '接受邀请' }));
  const acceptInput = el('textarea', {
    className: 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono',
    attrs: { id: 'friends-accept-card', rows: '3', placeholder: '粘贴对方的邀请卡', spellcheck: 'false' },
  });
  acceptBox.appendChild(acceptInput);
  const acceptMeta = el('div', { className: 'grid grid-cols-1 md:grid-cols-2 gap-2' });
  acceptMeta.appendChild(el('input', {
    className: 'bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm',
    attrs: { id: 'friends-accept-name', placeholder: '显示名', maxlength: '64' },
  }));
  acceptMeta.appendChild(el('input', {
    className: 'bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm',
    attrs: { id: 'friends-accept-endpoint', placeholder: '对方 endpoint（可选）' },
  }));
  acceptBox.appendChild(acceptMeta);
  acceptBox.appendChild(el('button', {
    className: 'text-sm bg-gray-800 hover:bg-gray-700 px-3 py-1.5 rounded-lg',
    text: '接受邀请',
    dataset: { friendsAction: 'accept-invite' },
  }));
  panel.appendChild(acceptBox);

  const completeBox = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3' });
  completeBox.appendChild(el('h3', { className: 'font-bold text-sm', text: '完成互认' }));
  completeBox.appendChild(el('p', {
    className: 'text-xs text-gray-500',
    text: '接受方把回执交给邀请方。邀请方粘贴回执后点完成，两边才会变成 confirmed。',
  }));
  const receipt = el('textarea', {
    className: 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono',
    attrs: { id: 'friends-accept-receipt', rows: '4', placeholder: '接受回执 JSON', spellcheck: 'false' },
  });
  if (lastAcceptReceipt) receipt.value = lastAcceptReceipt;
  completeBox.appendChild(receipt);
  completeBox.appendChild(el('button', {
    className: 'text-sm bg-gray-800 hover:bg-gray-700 px-3 py-1.5 rounded-lg',
    text: '完成互认',
    dataset: { friendsAction: 'complete-invite' },
  }));
  panel.appendChild(completeBox);

  const listBox = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3' });
  listBox.appendChild(el('h3', { className: 'font-bold text-sm', text: '朋友列表' }));
  if (!friends.length) {
    listBox.appendChild(el('p', { className: 'text-sm text-gray-500', text: '还没有朋友。先交换邀请卡。' }));
  } else {
    const list = el('div', { className: 'space-y-2', attrs: { id: 'friends-list' } });
    for (const item of friends) {
      const id = friendIdOf(item);
      if (!id) continue;
      const row = el('div', { className: 'bg-gray-800 rounded-lg px-3 py-2 text-sm flex flex-wrap items-center gap-2' });
      row.appendChild(el('span', { className: 'font-medium text-gray-100', text: item.display_name || 'Friend' }));
      row.appendChild(el('span', { className: 'text-xs text-gray-500', text: String(item.status || '') }));
      row.appendChild(el('button', {
        className: 'text-xs bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded',
        text: '时间线',
        dataset: { friendId: id, friendsAction: 'timeline' },
      }));
      row.appendChild(el('button', {
        className: 'text-xs bg-yellow-900/40 hover:bg-yellow-900/60 text-yellow-300 px-2 py-1 rounded',
        text: '拉黑',
        dataset: { friendId: id, friendsAction: 'block' },
      }));
      row.appendChild(el('button', {
        className: 'text-xs bg-red-900/40 hover:bg-red-900/60 text-red-300 px-2 py-1 rounded',
        text: '吊销',
        dataset: { friendId: id, friendsAction: 'revoke' },
      }));
      list.appendChild(row);
    }
    listBox.appendChild(list);
  }
  panel.appendChild(listBox);

  const timelineBox = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3' });
  timelineBox.appendChild(el('h3', { className: 'font-bold text-sm', text: '消息时间线' }));
  timelineBox.appendChild(el('div', {
    className: 'space-y-2 text-sm text-gray-400',
    attrs: { id: 'friends-timeline' },
    text: selectedFriendId ? '加载时间线...' : '选择一个朋友查看时间线。',
  }));
  const composer = el('div', { className: 'space-y-2' });
  composer.appendChild(el('textarea', {
    className: 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm',
    attrs: { id: 'friends-message-text', rows: '3', maxlength: '5000', placeholder: '发送加密文本（无附件）' },
  }));
  const sendRow = el('div', { className: 'flex flex-wrap gap-2' });
  sendRow.appendChild(el('button', {
    className: 'text-sm bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg',
    text: '发送消息',
    dataset: { friendsAction: 'send-message' },
  }));
  sendRow.appendChild(el('button', {
    className: 'text-sm bg-purple-900/40 hover:bg-purple-900/60 text-purple-300 px-3 py-1.5 rounded-lg',
    text: '发送 L2 任务',
    dataset: { friendsAction: 'send-task' },
  }));
  composer.appendChild(sendRow);
  timelineBox.appendChild(composer);
  panel.appendChild(timelineBox);

  const grantBox = el('div', { className: 'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-2' });
  grantBox.appendChild(el('h3', { className: 'font-bold text-sm', text: '协作授权' }));
  grantBox.appendChild(el('p', {
    className: 'text-sm text-gray-400',
    text: 'v1 协作授权是只读策略：L2 任务 allowed_tools 恒为空，禁止递归委托，朋友不能直接调本地工具。',
  }));
  panel.appendChild(grantBox);

  bindDataClicks(panel, 'friendsAction', (action, event) => {
    const node = event.currentTarget;
    const friendId = node instanceof HTMLElement ? sanitizeRuntimeId(node.dataset.friendId || '') : '';
    if (action === 'create-invite') createFriendInvite();
    else if (action === 'accept-invite') acceptFriendInvite();
    else if (action === 'complete-invite') completeFriendInvite();
    else if (action === 'timeline' && friendId) loadFriendMessages(friendId);
    else if (action === 'block' && friendId) blockFriend(friendId);
    else if (action === 'revoke' && friendId) revokeFriend(friendId);
    else if (action === 'send-message') sendFriendMessage();
    else if (action === 'send-task') sendFriendTask();
  });
}

export async function createFriendInvite() {
  try {
    const res = await fetch('/api/friends/invites', { method: 'POST' });
    if (!res.ok) throw new Error(await readApiError(res));
    const data = await res.json();
    const box = document.getElementById('friends-invite-card');
    if (box) box.value = String(data.invite_card || '');
    if (data.invite_card && navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(String(data.invite_card));
      showToast('邀请卡已生成并复制', 'success');
    } else {
      showToast('邀请卡已生成', 'success');
    }
  } catch (error) {
    showToast('生成邀请失败: ' + error.message, 'error');
  }
}

export async function acceptFriendInvite() {
  const card = document.getElementById('friends-accept-card');
  const name = document.getElementById('friends-accept-name');
  const endpoint = document.getElementById('friends-accept-endpoint');
  const inviteCard = card && 'value' in card ? String(card.value || '').trim() : '';
  if (!inviteCard) {
    showToast('请粘贴邀请卡', 'warning');
    return;
  }
  try {
    const res = await fetch('/api/friends/invites/accept', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        invite_card: inviteCard,
        display_name: name && 'value' in name ? String(name.value || 'Friend') : 'Friend',
        endpoint: endpoint && 'value' in endpoint ? String(endpoint.value || '') : '',
      }),
    });
    if (!res.ok) throw new Error(await readApiError(res));
    const data = await res.json();
    lastAcceptReceipt = JSON.stringify(data.accept || data, null, 2);
    const receiptBox = document.getElementById('friends-accept-receipt');
    if (receiptBox && 'value' in receiptBox) receiptBox.value = lastAcceptReceipt;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(lastAcceptReceipt);
    }
    showToast('已接受。回执已复制，交给邀请方完成互认', 'success');
  } catch (error) {
    showToast('接受邀请失败: ' + error.message, 'error');
  }
}

export async function completeFriendInvite() {
  const box = document.getElementById('friends-accept-receipt');
  const raw = box && 'value' in box ? String(box.value || '').trim() : lastAcceptReceipt;
  if (!raw) {
    showToast('请粘贴接受回执', 'warning');
    return;
  }
  let accept;
  try {
    accept = JSON.parse(raw);
  } catch (error) {
    showToast('回执不是合法 JSON', 'error');
    return;
  }
  if (accept && typeof accept === 'object' && accept.accept && typeof accept.accept === 'object') {
    accept = accept.accept;
  }
  try {
    const res = await fetch('/api/friends/invites/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accept }),
    });
    if (!res.ok) throw new Error(await readApiError(res));
    lastAcceptReceipt = '';
    showToast('互认完成', 'success');
    await loadFriends();
  } catch (error) {
    showToast('完成互认失败: ' + error.message, 'error');
  }
}

export async function blockFriend(friendId) {
  const id = sanitizeRuntimeId(friendId);
  if (!id) return;
  try {
    const res = await fetch(`/api/friends/${encodeURIComponent(id)}/block`, { method: 'POST' });
    if (!res.ok) throw new Error(await readApiError(res));
    if (selectedFriendId === id) selectedFriendId = '';
    showToast('已拉黑', 'success');
    await loadFriends();
  } catch (error) {
    showToast('拉黑失败: ' + error.message, 'error');
  }
}

export async function revokeFriend(friendId) {
  const id = sanitizeRuntimeId(friendId);
  if (!id) return;
  try {
    const res = await fetch(`/api/friends/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
    if (!res.ok) throw new Error(await readApiError(res));
    if (selectedFriendId === id) selectedFriendId = '';
    showToast('已吊销', 'success');
    await loadFriends();
  } catch (error) {
    showToast('吊销失败: ' + error.message, 'error');
  }
}

export async function loadFriendMessages(friendId, { silent = false } = {}) {
  const id = sanitizeRuntimeId(friendId);
  const timeline = document.getElementById('friends-timeline');
  if (!id || !timeline) return;
  selectedFriendId = id;
  timeline.replaceChildren(el('div', { className: 'text-gray-400', text: '加载时间线...' }));
  try {
    const res = await fetch(`/api/friends/${encodeURIComponent(id)}/messages`);
    if (!res.ok) throw new Error(await readApiError(res));
    const data = await res.json();
    const messages = Array.isArray(data.messages) ? data.messages : [];
    timeline.replaceChildren();
    if (!messages.length) {
      timeline.appendChild(el('div', { className: 'text-gray-500', text: '还没有消息。密文只在本地时间线记方向与时间。' }));
      return;
    }
    for (const item of messages) {
      const when = item.created_at ? new Date(Number(item.created_at) * 1000).toLocaleString() : '';
      const line = `${item.direction || '?'} · epoch ${item.epoch || 1}${when ? ' · ' + when : ''}`;
      timeline.appendChild(el('div', { className: 'bg-gray-800 rounded px-3 py-2 text-xs text-gray-300', text: line }));
    }
  } catch (error) {
    timeline.replaceChildren(el('div', { className: 'text-red-400', text: error.message || '加载失败' }));
    if (!silent) showToast('时间线加载失败: ' + error.message, 'error');
  }
}

async function sendToSelected(kind) {
  const id = sanitizeRuntimeId(selectedFriendId);
  const box = document.getElementById('friends-message-text');
  const text = box && 'value' in box ? String(box.value || '').trim() : '';
  if (!id) {
    showToast('先选择一个朋友', 'warning');
    return;
  }
  if (!text) {
    showToast('请输入文本', 'warning');
    return;
  }
  const path = kind === 'task' ? 'tasks' : 'messages';
  const body = kind === 'task' ? { task_text: text } : { text };
  try {
    const res = await fetch(`/api/friends/${encodeURIComponent(id)}/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(await readApiError(res));
    if (box && 'value' in box) box.value = '';
    showToast(kind === 'task' ? 'L2 任务已发出（allowed_tools 为空）' : '消息已发出', 'success');
    await loadFriendMessages(id);
  } catch (error) {
    showToast('发送失败: ' + error.message, 'error');
  }
}

export async function sendFriendMessage() {
  await sendToSelected('message');
}

export async function sendFriendTask() {
  await sendToSelected('task');
}
