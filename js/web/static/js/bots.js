/* Bots surface: named bots, rooms, WeChat-style bubbles. Local UI state only. */

let _rooms = [];
let _bots = [];
let _activeRoomId = '';
let _activeGoalId = '';
let _surfaceOn = false;

export function isBotsSurface() {
  return document.body.dataset.surface === 'bots';
}

export function enterBotsSurface() {
  _surfaceOn = true;
  document.body.dataset.surface = 'bots';
  const band = document.getElementById('bots-context-band');
  if (band) band.hidden = false;
  const workBand = document.getElementById('work-context-band');
  if (workBand) workBand.hidden = true;
  document.getElementById('product-bots-btn')?.classList.add('seg-active');
  document.getElementById('product-personal-btn')?.classList.remove('seg-active');
  document.getElementById('product-work-btn')?.classList.remove('seg-active');
  window.switchTab?.('bots');
  refreshBotsSurface();
}

export function exitBotsSurface() {
  _surfaceOn = false;
  delete document.body.dataset.surface;
  const band = document.getElementById('bots-context-band');
  if (band) band.hidden = true;
  document.getElementById('product-bots-btn')?.classList.remove('seg-active');
  window.switchTab?.('chat');
}

export async function refreshBotsSurface() {
  if (!_surfaceOn) return;
  try {
    const [botsRes, roomsRes] = await Promise.all([
      fetch('/api/bots'),
      fetch('/api/bots/rooms'),
    ]);
    if (botsRes.ok) {
      const data = await botsRes.json();
      _bots = data.bots || [];
    }
    if (roomsRes.ok) {
      const data = await roomsRes.json();
      _rooms = data.rooms || [];
    }
    if (!botsRes.ok || !roomsRes.ok) showBotsError('无法刷新机器人或房间列表');
    else hideBotsError();
  } catch (e) {
    showBotsError('无法连接 Bots 表面');
  }
  renderRoomList();
  renderBotsHome();
  if (_activeRoomId) await openRoom(_activeRoomId);
}

function renderRoomList() {
  const list = document.getElementById('session-list');
  if (!list || !_surfaceOn) return;
  list.innerHTML = '';
  if (!_rooms.length) {
    const empty = document.createElement('div');
    empty.className = 'session-item';
    empty.textContent = '还没有房间。创建机器人后会自动出现私聊。';
    list.appendChild(empty);
    return;
  }
  _rooms.forEach((room) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'session-item' + (room.id === _activeRoomId ? ' bots-room-active' : '');
    item.textContent = room.title || room.id;
    item.addEventListener('click', () => openRoom(room.id));
    list.appendChild(item);
  });
}

function renderBotsHome() {
  const roster = document.getElementById('bots-roster');
  if (roster) {
    roster.innerHTML = _bots.map((bot) => (
      `<li data-bot-id="${bot.id}">`
      + `<strong>${escapeHtml(bot.display_name)}</strong>`
      + ` <span>${bot.status}</span></li>`
    )).join('');
  }
  const members = document.getElementById('bots-room-members');
  if (members) {
    members.innerHTML = _bots.filter((bot) => bot.status === 'active').map((bot) => (
      `<label><input type="checkbox" value="${bot.id}"> ${escapeHtml(bot.display_name)}</label>`
    )).join('');
  }
}

async function openRoom(roomId) {
  _activeRoomId = roomId;
  renderRoomList();
  const res = await fetch(`/api/bots/rooms/${encodeURIComponent(roomId)}`);
  if (!res.ok) {
    showBotsError('无法打开房间');
    return;
  }
  hideBotsError();
  const data = await res.json();
  renderRoom(data);
}

function renderRoom(data) {
  const room = data.room || {};
  const messages = data.messages || [];
  const goal = data.goal;
  _activeGoalId = goal ? goal.id : '';
  const bandMembers = document.getElementById('bots-band-members');
  const bandPhase = document.getElementById('bots-band-phase');
  const bandHit = document.getElementById('bots-band-hit');
  if (bandMembers) bandMembers.textContent = `成员 ${ (room.member_bot_ids || []).length }`;
  if (bandPhase) bandPhase.textContent = goal ? `阶段 ${goal.phase}` : '闲聊';
  if (bandHit && Object.prototype.hasOwnProperty.call(data, 'hit_rate')) {
    const hit = data.hit_rate || {};
    if (typeof hit.hit_rate === 'number') {
      bandHit.textContent = `命中率 ${(hit.hit_rate * 100).toFixed(0)}%`;
      bandHit.classList.toggle('bots-hit-low', !!hit.below_target);
    } else {
      bandHit.textContent = '命中率 —';
      bandHit.classList.remove('bots-hit-low');
    }
  }
  const log = document.getElementById('bots-messages');
  if (!log) return;
  if (!messages.length) {
    log.innerHTML = '<div class="bots-empty">还没有消息。说一句任务，机器人会先澄清再执行。</div>';
  } else {
    log.innerHTML = messages.map((msg) => bubbleHtml(msg)).join('');
    log.scrollTop = log.scrollHeight;
  }
  renderSuggested(data.suggested_roster || []);
  renderGoalCard(goal);
}

function renderSuggested(suggested) {
  const box = document.getElementById('bots-suggested');
  if (!box) return;
  if (!suggested.length) {
    box.hidden = true;
    box.innerHTML = '';
    return;
  }
  box.hidden = false;
  box.innerHTML = '<span>建议拉进群：</span>' + suggested.map((bot) => (
    `<label><input type="checkbox" value="${escapeHtml(bot.id)}" checked> ${escapeHtml(bot.display_name)}</label>`
  )).join('') + '<button type="button" id="bots-pull-suggested">按建议拉人</button>';
  document.getElementById('bots-pull-suggested')?.addEventListener('click', pullSuggested);
}

function renderGoalCard(goal) {
  const clarify = document.getElementById('bots-clarify-card');
  if (!clarify) return;
  if (!goal || goal.phase === 'done') {
    clarify.hidden = true;
    clarify.innerHTML = '';
    return;
  }
  clarify.hidden = false;
  const questions = (goal.questions || []).map((q) => `<li>${escapeHtml(q)}</li>`).join('');
  const actions = [];
  if (goal.phase === 'clarify') {
    actions.push('<button type="button" data-bots-action="confirm">确认合同</button>');
  }
  if (goal.phase === 'confirmed' || goal.phase === 'blocked') {
    actions.push('<button type="button" data-bots-action="execute">继续执行</button>');
  }
  if (goal.phase !== 'done') {
    actions.push('<button type="button" data-bots-action="cancel">停止目标</button>');
  }
  clarify.innerHTML = `<h3>目标 · ${escapeHtml(goal.phase)}</h3>`
    + (questions ? `<ol>${questions}</ol>` : '')
    + (goal.pause_reason ? `<p>${escapeHtml(goal.pause_reason)}</p>` : '')
    + `<div class="bots-clarify-actions">${actions.join('')}</div>`;
  clarify.querySelectorAll('[data-bots-action]').forEach((btn) => {
    btn.addEventListener('click', () => goalAction(btn.getAttribute('data-bots-action')));
  });
}

async function pullSuggested() {
  if (!_activeRoomId) return;
  const picks = [...document.querySelectorAll('#bots-suggested input:checked')].map((el) => el.value);
  if (!picks.length) return;
  const res = await fetch(`/api/bots/rooms/${encodeURIComponent(_activeRoomId)}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ member_bot_ids: picks }),
  });
  if (!res.ok) {
    showBotsError('拉人失败');
    return;
  }
  await openRoom(_activeRoomId);
}

async function goalAction(action) {
  if (!_activeGoalId) return;
  const path = action === 'confirm'
    ? `/api/bots/goals/${encodeURIComponent(_activeGoalId)}/confirm`
    : action === 'execute'
      ? `/api/bots/goals/${encodeURIComponent(_activeGoalId)}/execute`
      : `/api/bots/goals/${encodeURIComponent(_activeGoalId)}/cancel`;
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(action === 'execute' ? { evidence: '' } : { answers: [] }),
  });
  if (!res.ok) {
    showBotsError('目标操作失败');
    return;
  }
  if (_activeRoomId) await openRoom(_activeRoomId);
}

function showBotsError(message) {
  const el = document.getElementById('bots-error');
  if (!el) return;
  el.hidden = false;
  el.textContent = message;
}

function hideBotsError() {
  const el = document.getElementById('bots-error');
  if (!el) return;
  el.hidden = true;
  el.textContent = '';
}

function bubbleHtml(msg) {
  const kind = msg.speaker_kind || 'bot';
  const name = kind === 'user' ? '我' : (botName(msg.speaker_id) || msg.speaker_id);
  return `<div class="bots-bubble bots-bubble-${kind}">`
    + `<div class="bots-bubble-meta">${escapeHtml(name)}</div>`
    + `<div class="bots-bubble-body">${escapeHtml(msg.content || '')}</div>`
    + `</div>`;
}

function botName(id) {
  const bot = _bots.find((item) => item.id === id);
  return bot ? bot.display_name : id;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function initBotsSurface() {
  const create = document.getElementById('bots-create-form');
  if (create) {
    create.addEventListener('submit', async (event) => {
      event.preventDefault();
      const input = document.getElementById('bots-create-name');
      const name = input && input.value.trim();
      if (!name) return;
      const res = await fetch('/api/bots', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ display_name: name }),
      });
      if (!res.ok) {
        showBotsError('创建机器人失败');
        return;
      }
      hideBotsError();
      const data = await res.json();
      const soul = document.getElementById('bots-soul-editor');
      if (soul && data.bot) {
        soul.dataset.botId = data.bot.id;
        soul.value = data.bot.soul_text || '';
      }
      await refreshBotsSurface();
    });
  }
  const activate = document.getElementById('bots-activate-btn');
  if (activate) {
    activate.addEventListener('click', async () => {
      const soul = document.getElementById('bots-soul-editor');
      const botId = soul && soul.dataset.botId;
      if (!botId || !soul.value.trim()) return;
      await fetch(`/api/bots/${encodeURIComponent(botId)}/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ soul_text: soul.value }),
      });
      await refreshBotsSurface();
    });
  }
  const send = document.getElementById('bots-send-btn');
  const input = document.getElementById('bots-input');
  if (send && input) {
    send.addEventListener('click', () => sendRoomMessage());
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendRoomMessage();
      }
    });
  }
  const roomForm = document.getElementById('bots-room-form');
  if (roomForm) {
    roomForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const title = document.getElementById('bots-room-title');
      const picks = [...document.querySelectorAll('#bots-room-members input:checked')]
        .map((el) => el.value);
      if (!title || !title.value.trim() || !picks.length) return;
      const res = await fetch('/api/bots/rooms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: title.value.trim(), member_bot_ids: picks }),
      });
      if (!res.ok) {
        showBotsError('建群失败');
        return;
      }
      hideBotsError();
      const data = await res.json();
      await refreshBotsSurface();
      if (data.room) await openRoom(data.room.id);
    });
  }
}

async function sendRoomMessage() {
  const input = document.getElementById('bots-input');
  if (!input || !_activeRoomId) return;
  const content = input.value.trim();
  if (!content) return;
  input.value = '';
  const res = await fetch(`/api/bots/rooms/${encodeURIComponent(_activeRoomId)}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
  if (!res.ok) {
    showBotsError('发送失败');
    return;
  }
  hideBotsError();
  const data = await res.json();
  renderRoom(data);
  if (_activeRoomId) await openRoom(_activeRoomId);
}

window.enterBotsSurface = enterBotsSurface;
window.exitBotsSurface = exitBotsSurface;
window.isBotsSurface = isBotsSurface;
