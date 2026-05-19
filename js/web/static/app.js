let sessionId = null;
let ws = null;
let currentTab = 'chat';
let selectedModel = localStorage.getItem('js-selected-model') || '';
let availableModels = [];

// ===== File Attachments =====
let pendingAttachments = []; // { id, path, name, type, size, previewUrl? }

function connectWS() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
  ws.onopen = () => {
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> <span class="text-green-400">已连接</span>';
  };
  ws.onclose = () => {
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500"></span> <span class="text-red-400">断开 - 重连中...</span>';
    setTimeout(connectWS, 3000);
  };
  ws.onerror = () => {
    document.getElementById('conn-status').innerHTML = '<span class="w-2 h-2 rounded-full bg-yellow-500"></span> <span class="text-yellow-400">连接错误</span>';
  };
  ws.onmessage = (e) => {
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
      sessionId = data.session_id;
      finishResponse(data.content);
    } else if (data.type === 'done') {
      if (data.session_id) sessionId = data.session_id;
      finishStream();
    } else if (data.type === 'status') {
      showTyping();
    } else if (data.type === 'error') {
      appendMessage('system', '错误: ' + data.content);
    }
  };
}

function appendMessage(role, content) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = `flex ${role === 'user' ? 'justify-end' : 'justify-start'}`;
  const bubble = document.createElement('div');
  bubble.className = `max-w-3xl px-4 py-3 rounded-2xl ${role === 'user' ? 'msg-user text-white rounded-br-md' : 'msg-assistant text-gray-200 rounded-bl-md markdown'}`;
  bubble.innerHTML = role === 'user' ? escapeHtml(content) : renderMarkdown(content);
  div.appendChild(bubble);
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

let currentBubble = null;
let streamBuffer = '';

function appendToken(token) {
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  if (!currentBubble) {
    currentBubble = appendMessage('assistant', '');
    currentBubble.id = 'streaming-bubble';
  }
  streamBuffer += token;
  currentBubble.innerHTML = renderMarkdown(streamBuffer);
  const container = document.getElementById('chat-messages');
  container.scrollTop = container.scrollHeight;
}

function finishResponse(content) {
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
  if (!currentBubble) {
    appendMessage('assistant', content);
  } else {
    currentBubble.innerHTML = renderMarkdown(content || streamBuffer);
    currentBubble.id = '';
    currentBubble = null;
    streamBuffer = '';
  }
  const container = document.getElementById('chat-messages');
  container.scrollTop = container.scrollHeight;
}

function finishStream() {
  if (currentBubble) {
    currentBubble.id = '';
    currentBubble = null;
  }
  streamBuffer = '';
}

function sendMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text && pendingAttachments.length === 0) return;

  // Build display text with attachment names
  let displayText = text || '';
  if (pendingAttachments.length > 0) {
    const attNames = pendingAttachments.map(a => `[${a.name}]`).join(' ');
    displayText = (text ? text + ' ' : '') + attNames;
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    appendMessage('system', '连接已断开，请等待重连或刷新页面');
    return;
  }

  input.value = '';
  appendMessage('user', displayText);
  showTyping();

  ws.send(JSON.stringify({
    type: 'message',
    content: text,
    session_id: sessionId,
    model: selectedModel || null,
    attachments: pendingAttachments.map(a => a.path),
  }));

  // Clear attachments after sending
  clearAttachments();
}

function clearAttachments() {
  pendingAttachments.forEach(a => {
    if (a.previewUrl) URL.revokeObjectURL(a.previewUrl);
  });
  pendingAttachments = [];
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
      pendingAttachments.push(r.attachment);
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

  card.innerHTML = `${iconHtml}${nameHtml}<button onclick="removeAttachment('${att.id}')" class="ml-1 text-gray-500 hover:text-red-400 transition flex-shrink-0" title="移除"><i class="fas fa-times"></i></button>`;
  bar.appendChild(card);
  updateAttachmentBar();
}

function removeAttachment(id) {
  const idx = pendingAttachments.findIndex(a => a.id === id);
  if (idx >= 0) {
    if (pendingAttachments[idx].previewUrl) {
      URL.revokeObjectURL(pendingAttachments[idx].previewUrl);
    }
    pendingAttachments.splice(idx, 1);
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
  sessionId = null;
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
      const isActive = s.session_id === sessionId;
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
  sessionId = sid;
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
        if (sessionId === sid) sessionId = null;
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
    if (sessionId === sid) {
      sessionId = null;
      document.getElementById('chat-messages').innerHTML = '';
      appendMessage('system', '会话已删除');
    }
    showToast('会话已删除');
    loadSessions();
  } catch (e) {
    showToast('删除失败: ' + e.message, true);
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
  currentTab = tab;

  if (tab === 'files') loadFiles();
  if (tab === 'memory') loadMemory();
  if (tab === 'audit') loadAudit();
  if (tab === 'status') loadStatus();
  if (tab === 'skills') loadSkills();
  if (tab === 'agents') loadAgents();
  if (tab === 'evolution') loadEvolution();
  if (tab === 'models') loadModels();
  if (tab === 'search') loadSearch();
  if (tab === 'stats') loadStats();
}

function showLoading(id, text = '加载中...') {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>${text}</div>`;
}

function showError(id, text) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="text-red-400 text-sm"><i class="fas fa-exclamation-circle mr-2"></i>${text}</div>`;
}

async function loadFiles() {
  showLoading('files-content', '加载文件...');
  try {
    const res = await fetch('/api/files');
    const data = await res.json();
    document.getElementById('files-content').textContent = data.output || data.error || '无内容';
  } catch (e) {
    showError('files-content', '加载失败: ' + e.message);
  }
}

async function loadMemory() {
  // Set loading states for all sections
  showLoading('memory-context', '加载记忆中...');
  showLoading('memory-working', '加载工作记忆...');
  showLoading('memory-semantic', '加载长期知识...');
  showLoading('memory-episodes', '加载情景记忆...');
  showLoading('memory-dreams', '加载梦境日志...');
  showLoading('memory-files', '加载记忆文件...');

  try {
    const res = await fetch('/api/memory/enhanced');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

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
        semEl.innerHTML = items.map(s => `
          <div class="bg-gray-800 rounded-lg px-3 py-2">
            <div class="flex items-center justify-between">
              <span class="text-xs font-mono text-pink-400">${escapeHtml(s.key || 'unknown')}</span>
              <span class="text-[10px] text-gray-500">${s.category || 'fact'} · 置信度 ${((s.confidence || 0.5) * 100).toFixed(0)}%</span>
            </div>
            <div class="text-sm text-gray-300 mt-0.5">${escapeHtml(s.value || '')}</div>
            ${s.source ? `<div class="text-[10px] text-gray-600 mt-0.5">来源: ${escapeHtml(s.source)}</div>` : ''}
          </div>
        `).join('');
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

// Search semantic memories
async function searchSemantic() {
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
      container.innerHTML = items.map(s => `
        <div class="bg-gray-800 rounded-lg px-3 py-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-mono text-pink-400">${escapeHtml(s.key || 'unknown')}</span>
            <span class="text-[10px] text-gray-500">${s.category || 'fact'} · 置信度 ${((s.confidence || 0.5) * 100).toFixed(0)}%</span>
          </div>
          <div class="text-sm text-gray-300 mt-0.5">${escapeHtml(s.value || '')}</div>
        </div>
      `).join('');
    }
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-sm">搜索失败: ' + escapeHtml(e.message) + '</div>';
  }
}

// Show inline add semantic memory form
function showAddSemanticModal() {
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

async function submitSemanticMemory() {
  const key = document.getElementById('semantic-add-key').value.trim();
  const value = document.getElementById('semantic-add-value').value.trim();
  const category = document.getElementById('semantic-add-cat').value;
  if (!key || !value) {
    showToast('键和值不能为空', true);
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
    showToast('保存失败: ' + e.message, true);
  }
}

// Run evolution cycle on demand
async function runEvolutionNow() {
  const btn = document.querySelector('#tab-evolution button[onclick="runEvolutionNow()"]');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin text-xs"></i> 检查中...';
  }

  // Pre-flight diagnostic to catch stale server versions gracefully
  try {
    const diagRes = await fetch('/api/diag');
    if (diagRes.ok) {
      const diag = await diagRes.json();
      if (!diag.has_evolution_api) {
        showToast('服务器版本过旧，请重启服务器以支持自主进化', true);
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-play text-xs"></i> 立即运行';
        }
        return;
      }
    }
  } catch (_) {
    // Proceed anyway; the main call will surface real errors
  }

  if (btn) {
    btn.innerHTML = '<i class="fas fa-spinner fa-spin text-xs"></i> 运行中...';
  }

  try {
    const res = await fetch('/api/evolution/run', { method: 'POST' });
    if (!res.ok) {
      let detail = '';
      try {
        const errData = await res.json();
        detail = errData.detail || '';
      } catch (_) {}
      if (res.status === 404) {
        throw new Error('404 — 服务器未暴露进化接口，请重启服务器');
      } else if (res.status === 501) {
        throw new Error('501 — ' + (detail || 'Agent 不支持进化，请更新代码并重启'));
      } else if (res.status === 502) {
        throw new Error('502 — ' + (detail || 'LLM API 错误，请检查模型配置'));
      } else if (res.status === 503) {
        throw new Error('503 — ' + (detail || '进化子系统未就绪，请稍后再试'));
      } else {
        throw new Error('HTTP ' + res.status + (detail ? ': ' + detail : ''));
      }
    }
    const data = await res.json();
    const report = data.report || {};
    const parts = [];
    if (report.profile_update && report.profile_update.ok) parts.push('画像更新');
    if (report.dreaming && report.dreaming.ok) parts.push('记忆整合');
    if (report.skill_evolution && report.skill_evolution.evolved && report.skill_evolution.evolved.length) {
      parts.push('技能进化(' + report.skill_evolution.evolved.length + ')');
    }
    const msg = parts.length ? '进化完成: ' + parts.join('、') : '进化周期已完成';
    showToast(msg);
    loadEvolution();
  } catch (e) {
    showToast('运行失败: ' + e.message, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-play text-xs"></i> 立即运行';
    }
  }
}

// ----- Memory File Editor -----

async function openMemoryFileEditor(name) {
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

async function saveMemoryFile(name) {
  const textarea = document.getElementById('memory-file-editor');
  try {
    const res = await fetch(`/api/memory/files/${name}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: textarea.value }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    closeMemoryFileEditor();
    // Refresh memory tab so prompt context picks up changes
    loadMemory();
  } catch (e) {
    alert('保存失败: ' + e.message);
  }
}

function closeMemoryFileEditor() {
  const modal = document.getElementById('memory-file-modal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}

async function loadAudit() {
  showLoading('audit-content', '加载审计日志...');
  try {
    const res = await fetch('/api/audit?limit=50');
    const data = await res.json();
    const container = document.getElementById('audit-content');
    if (!data.events || data.events.length === 0) {
      container.innerHTML = '<div class="text-gray-400 text-sm">暂无审计日志</div>';
      return;
    }
    container.innerHTML = data.events.map(e => `
      <div class="bg-gray-900 border border-gray-800 rounded-lg p-3 text-sm">
        <span class="text-blue-400 font-mono">${new Date(e.timestamp * 1000).toLocaleTimeString()}</span>
        <span class="text-gray-400 mx-2">${escapeHtml(e.type)}</span>
        <span class="text-green-400">${escapeHtml(e.actor)}</span>:
        <span class="text-gray-300">${escapeHtml(e.action)}</span>
      </div>
    `).join('');
  } catch (e) {
    showError('audit-content', '加载失败: ' + e.message);
  }
}

async function loadStatus() {
  showLoading('status-content', '加载系统状态...');
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('status-content').textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    showError('status-content', '加载失败: ' + e.message);
  }
}

let currentSkillId = null;

async function loadSkills() {
  showLoading('skills-content', '加载 Skills...');
  try {
    const category = document.getElementById('skill-category-filter').value;
    const skillType = document.getElementById('skill-type-filter').value;
    const query = document.getElementById('skill-search').value;
  let url = '/api/skills';
  const params = [];
  if (category) params.push('category=' + encodeURIComponent(category));
  if (skillType) params.push('skill_type=' + encodeURIComponent(skillType));
  if (query) params.push('query=' + encodeURIComponent(query));
  if (params.length) url += '?' + params.join('&');

  const res = await fetch(url);
  if (!res.ok) {
    const container = document.getElementById('skills-content');
    container.innerHTML = '<div class="text-red-400">加载 Skills 失败: HTTP ' + res.status + '</div>';
    return;
  }
  const data = await res.json();
  const container = document.getElementById('skills-content');

  // Update category filter options
  const catSelect = document.getElementById('skill-category-filter');
  const currentCat = catSelect.value;
  if (data.categories && catSelect.options.length <= 1) {
    data.categories.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c.name;
      opt.textContent = `${c.name} (${c.count})`;
      catSelect.appendChild(opt);
    });
    catSelect.value = currentCat;
  }

  if (!data.skills || data.skills.length === 0) {
    container.innerHTML = '<div class="text-gray-400 col-span-full">暂无匹配的 Skills</div>';
    return;
  }

  container.innerHTML = data.skills.map(s => {
    const trustCls = s.trust_css || 'bg-gray-800 text-gray-400';
    const compatIcon = s.compatible ? '<i class="fas fa-check-circle text-green-400" title="Compatible"></i>' : '<i class="fas fa-times-circle text-red-400" title="Incompatible"></i>';
    const prereqIcon = s.prerequisites_ok ? '' : '<i class="fas fa-exclamation-triangle text-yellow-400 ml-1" title="Prerequisites missing"></i>';
    const riskBadge = s.risk_flags && s.risk_flags.length > 0 ? `<span class="text-xs bg-red-900 text-red-400 px-2 py-0.5 rounded ml-1">${s.risk_flags.length} risk</span>` : '';

    return `
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 cursor-pointer hover:border-blue-500 transition" onclick="showSkillDetail(${JSON.stringify(s.id)})">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2">
          <h3 class="font-bold">${escapeHtml(s.name)}</h3>
          ${prereqIcon}
        </div>
        <span class="text-xs ${trustCls} px-2 py-1 rounded">${escapeHtml(s.trust_level)}</span>
      </div>
      <p class="text-sm text-gray-400 mb-2">${escapeHtml(s.description || '')}</p>
      <div class="flex items-center gap-3 text-xs text-gray-500">
        <span>${compatIcon} ${escapeHtml(s.type)}</span>
        <span><i class="fas fa-folder mr-1"></i>${escapeHtml(s.category)}</span>
        <span><i class="fas fa-bolt mr-1"></i>${s.usage_count}</span>
        <span><i class="fas fa-percentage mr-1"></i>${(s.success_rate * 100).toFixed(0)}%</span>
        ${riskBadge}
      </div>
      ${s.tags && s.tags.length > 0 ? `<div class="flex flex-wrap gap-1 mt-2">${s.tags.map(t => `<span class="text-xs bg-gray-800 px-2 py-0.5 rounded">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>
  `}).join('');
  } catch (e) {
    showError('skills-content', '加载失败: ' + e.message);
  }
}

async function showSkillDetail(skillId) {
  currentSkillId = skillId;
  try {
  const res = await fetch('/api/skills/' + encodeURIComponent(skillId));
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const s = await res.json();
  if (s.error) {
    alert(s.error);
    return;
  }

  document.getElementById('modal-skill-name').textContent = `${escapeHtml(s.name)} v${escapeHtml(String(s.version))}`;
  document.getElementById('modal-trust-select').value = s.trust_level;

  const trustColor = escapeHtml(s.trust_color || 'gray');

  let html = `
    <div class="grid grid-cols-2 gap-2">
      <div><span class="text-gray-500">ID:</span> <span class="font-mono">${escapeHtml(s.id)}</span></div>
      <div><span class="text-gray-500">Type:</span> ${escapeHtml(s.type)}</div>
      <div><span class="text-gray-500">Category:</span> ${escapeHtml(s.category)}</div>
      <div><span class="text-gray-500">Author:</span> ${escapeHtml(s.author)}</div>
      <div><span class="text-gray-500">Trust:</span> <span class="text-${trustColor}-400">${escapeHtml(s.trust_level)}</span></div>
      <div><span class="text-gray-500">Compatible:</span> ${s.compatible ? '<span class="text-green-400">Yes</span>' : '<span class="text-red-400">No</span>'}</div>
      <div><span class="text-gray-500">Prerequisites:</span> ${s.prerequisites_ok ? '<span class="text-green-400">OK</span>' : '<span class="text-yellow-400">Missing</span>'}</div>
      <div><span class="text-gray-500">Usage:</span> ${s.usage_count} calls | ${(s.success_rate * 100).toFixed(1)}% success</div>
    </div>
  `;

  if (s.risk_flags && s.risk_flags.length > 0) {
    html += `<div class="mt-2 p-2 bg-red-900/30 border border-red-800 rounded"><span class="text-red-400 font-bold">Risk Flags:</span> ${s.risk_flags.map(f => escapeHtml(f)).join(', ')}</div>`;
  }
  if (s.tags && s.tags.length > 0) {
    html += `<div class="mt-2"><span class="text-gray-500">Tags:</span> ${s.tags.map(t => `<span class="bg-gray-800 px-2 py-0.5 rounded text-xs">${escapeHtml(t)}</span>`).join(' ')}</div>`;
  }
  if (s.platforms && s.platforms.length > 0) {
    html += `<div class="mt-1"><span class="text-gray-500">Platforms:</span> ${s.platforms.map(p => escapeHtml(p)).join(', ')}</div>`;
  }
  if (s.content) {
    html += `<div class="mt-3 p-3 bg-gray-950 rounded-lg border border-gray-800"><pre class="whitespace-pre-wrap text-gray-300">${escapeHtml(s.content.substring(0, 3000))}${s.content.length > 3000 ? '...' : ''}</pre></div>`;
  }

  document.getElementById('modal-skill-content').innerHTML = html;
  document.getElementById('skill-detail-modal').classList.remove('hidden');
  } catch (e) {
    alert('加载 Skill 详情失败: ' + e.message);
  }
}

function closeSkillModal() {
  document.getElementById('skill-detail-modal').classList.add('hidden');
  currentSkillId = null;
}

async function updateTrust() {
  if (!currentSkillId) return;
  const level = document.getElementById('modal-trust-select').value;
  try {
    const res = await fetch('/api/skills/' + encodeURIComponent(currentSkillId) + '/trust', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({level}),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'HTTP ' + res.status);
    }
    const data = await res.json();
    if (data.success) {
      loadSkills();
      closeSkillModal();
      showToast('信任级别已更新');
    } else {
      showToast(data.error || '更新失败', true);
    }
  } catch (e) {
    showToast('更新信任级别失败: ' + e.message, true);
  }
}

async function uninstallSkill() {
  if (!currentSkillId) return;
  if (!confirm(`Uninstall skill '${currentSkillId}'?`)) return;
  try {
    const res = await fetch('/api/skills/' + encodeURIComponent(currentSkillId), {method: 'DELETE'});
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'HTTP ' + res.status);
    }
    loadSkills();
    closeSkillModal();
    showToast('Skill 已卸载');
  } catch (e) {
    showToast('卸载失败: ' + e.message, true);
  }
}

async function loadAgents() {
  const container = document.getElementById('agents-content');

  // Fetch current config and available models
  let config = {};
  try {
    const cfgRes = await fetch('/api/agents/config');
    const cfgData = await cfgRes.json();
    config = cfgData.config || {};
  } catch (e) {
    console.error('Failed to load agent config', e);
  }

  const roles = [
    { key: 'orchestrator', label: '主控 (Orchestrator)', icon: 'fa-chess-king', color: 'text-red-400' },
    { key: 'coder', label: '编码 (Coder)', icon: 'fa-code', color: 'text-blue-400' },
    { key: 'reviewer', label: '审查 (Reviewer)', icon: 'fa-eye', color: 'text-yellow-400' },
    { key: 'researcher', label: '研究 (Researcher)', icon: 'fa-search', color: 'text-green-400' },
    { key: 'tester', label: '测试 (Tester)', icon: 'fa-vial', color: 'text-purple-400' },
  ];

  const modelOptions = availableModels.length > 0
    ? availableModels.map(m => `<option value="${escapeHtml(m.id)}">${escapeHtml(m.name)}</option>`).join('')
    : '<option value="">加载中...</option>';

  container.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-4">
      <h3 class="font-bold mb-2">多 Agent 模型分配</h3>
      <p class="text-sm text-gray-400 mb-4">为每个 Agent 角色分配专用模型，未设置时将使用默认模型。</p>
      <div class="space-y-3">
        ${roles.map(r => `
          <div class="flex items-center justify-between bg-gray-800 rounded-lg px-4 py-3">
            <div class="flex items-center gap-3">
              <i class="fas ${r.icon} ${r.color} w-5"></i>
              <span class="text-sm font-medium">${r.label}</span>
            </div>
            <select
              id="agent-model-${r.key}"
              onchange="updateAgentModel('${r.key}', this.value)"
              class="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-blue-500 min-w-[200px]"
            >
              <option value="">默认模型</option>
              ${modelOptions}
            </select>
          </div>
        `).join('')}
      </div>
      <div class="mt-4 flex justify-end">
        <button onclick="saveAgentConfig()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm transition">
          <i class="fas fa-save mr-1"></i>保存配置
        </button>
      </div>
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <p class="text-gray-400 text-sm">多 Agent 协作系统已就绪。通过 CLI 使用 <code>js run</code> 或 API 调用触发。</p>
      <div class="mt-4 grid grid-cols-2 md:grid-cols-5 gap-3">
        ${roles.map(r => `
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <i class="fas ${r.icon} ${r.color} mb-1"></i>
            <div class="text-xs">${r.label.split(' ')[0]}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  // Restore current values
  roles.forEach(r => {
    const sel = document.getElementById(`agent-model-${r.key}`);
    if (sel && config[r.key]) sel.value = config[r.key];
  });
}

let _agentConfigDraft = {};

function updateAgentModel(role, modelId) {
  _agentConfigDraft[role] = modelId;
}

async function saveAgentConfig() {
  const res = await fetch('/api/agents/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({config: _agentConfigDraft}),
  });
  const data = await res.json();
  if (data.success) {
    alert('配置已保存');
    _agentConfigDraft = {};
  } else {
    alert('保存失败: ' + (data.error || '未知错误'));
  }
}

async function loadEvolution() {
  const container = document.getElementById('evolution-content');
  container.innerHTML = '<div class="text-gray-400"><i class="fas fa-spinner fa-spin mr-2"></i>加载进化数据...</div>';

  try {
    const [reportsRes, insightsRes] = await Promise.all([
      fetch('/api/evolution/reports?limit=5'),
      fetch('/api/evolution/insights?limit=10'),
    ]);
    if (!reportsRes.ok || !insightsRes.ok) throw new Error('API error');
    const reportsData = await reportsRes.json();
    const insightsData = await insightsRes.json();

    const reports = reportsData.reports || [];
    const learning = insightsData.learning || {};
    const compression = insightsData.compression || {};
    const stats = learning.stats || {};

    // Health score from latest report
    const latestHealth = reports.length > 0 ? (reports[0].health_score || 0) : 1.0;
    const healthColor = latestHealth >= 0.8 ? 'text-green-400' : latestHealth >= 0.5 ? 'text-yellow-400' : 'text-red-400';
    const healthLabel = latestHealth >= 0.8 ? '健康' : latestHealth >= 0.5 ? '一般' : '需关注';

    // Proposals from latest report
    const latestProposals = reports.length > 0 ? (reports[0].proposals || []) : [];
    const proposalHtml = latestProposals.length > 0
      ? latestProposals.map(p => `
        <div class="bg-gray-800 rounded-lg px-3 py-2 text-sm">
          <span class="text-xs px-1.5 py-0.5 rounded ${p.area === 'compression' ? 'bg-blue-900 text-blue-400' : p.area === 'learning' ? 'bg-green-900 text-green-400' : p.area === 'optimization' ? 'bg-yellow-900 text-yellow-400' : 'bg-purple-900 text-purple-400'}">${p.area}</span>
          <span class="text-gray-300 ml-2">${escapeHtml(p.proposal)}</span>
        </div>
      `).join('')
      : '<div class="text-gray-500 text-sm">暂无改进建议</div>';

    // Learning insights
    const insights = learning.insights || [];
    const insightHtml = insights.length > 0
      ? insights.slice(0, 5).map(i => `
        <div class="bg-gray-800 rounded-lg px-3 py-2 text-sm flex items-center justify-between">
          <span class="text-gray-300">${escapeHtml(i.pattern || i.name || '未知')}</span>
          <span class="text-xs ${(i.success_rate || 1) >= 0.8 ? 'text-green-400' : 'text-yellow-400'}">${((i.success_rate || 1) * 100).toFixed(0)}% 成功率</span>
        </div>
      `).join('')
      : '<div class="text-gray-500 text-sm">交互数据不足，多使用几次后会自动生成洞察</div>';

    // Subsystem status
    const hasInteractions = (stats.total_interactions || 0) > 0;
    const selfLearnStatus = hasInteractions
      ? { icon: 'fa-check-circle', color: 'text-green-400', label: '活跃', detail: `${stats.total_interactions || 0} 条交互记录` }
      : { icon: 'fa-clock', color: 'text-gray-400', label: '等待数据', detail: '暂无交互记录' };
    const dreamStatus = { icon: 'fa-moon', color: 'text-purple-400', label: '自动触发', detail: '空闲 30 秒后自动运行' };
    const skillEvolveStatus = { icon: 'fa-dna', color: 'text-cyan-400', label: '后台运行', detail: '低成功率技能自动进化' };
    const promptOptStatus = { icon: 'fa-flask', color: 'text-gray-500', label: '实验性', detail: '尚未激活' };

    container.innerHTML = `
      <!-- Subsystem Status -->
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <h3 class="font-bold mb-3"><i class="fas fa-server text-blue-400 mr-2"></i>子系统状态</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <i class="fas ${selfLearnStatus.icon} ${selfLearnStatus.color} mb-1"></i>
            <div class="text-sm font-medium">自学习</div>
            <div class="text-[10px] text-gray-500">${selfLearnStatus.label}</div>
            <div class="text-[10px] text-gray-600 mt-0.5">${selfLearnStatus.detail}</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <i class="fas ${dreamStatus.icon} ${dreamStatus.color} mb-1"></i>
            <div class="text-sm font-medium">梦境整合</div>
            <div class="text-[10px] text-gray-500">${dreamStatus.label}</div>
            <div class="text-[10px] text-gray-600 mt-0.5">${dreamStatus.detail}</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <i class="fas ${skillEvolveStatus.icon} ${skillEvolveStatus.color} mb-1"></i>
            <div class="text-sm font-medium">技能进化</div>
            <div class="text-[10px] text-gray-500">${skillEvolveStatus.label}</div>
            <div class="text-[10px] text-gray-600 mt-0.5">${skillEvolveStatus.detail}</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <i class="fas ${promptOptStatus.icon} ${promptOptStatus.color} mb-1"></i>
            <div class="text-sm font-medium">Prompt 优化</div>
            <div class="text-[10px] text-gray-500">${promptOptStatus.label}</div>
            <div class="text-[10px] text-gray-600 mt-0.5">${promptOptStatus.detail}</div>
          </div>
        </div>
      </div>

      <!-- Health Overview -->
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="font-bold">系统健康度</h3>
          <span class="text-sm ${healthColor} font-bold">${(latestHealth * 100).toFixed(0)}% · ${healthLabel}</span>
        </div>
        <div class="w-full bg-gray-800 rounded-full h-2 mb-4">
          <div class="h-2 rounded-full ${latestHealth >= 0.8 ? 'bg-green-500' : latestHealth >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'} transition-all" style="width: ${(latestHealth * 100).toFixed(0)}%"></div>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <div class="text-xl font-bold text-blue-400">${stats.total_interactions || 0}</div>
            <div class="text-xs text-gray-500">总交互</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <div class="text-xl font-bold text-green-400">${stats.learned_patterns || 0}</div>
            <div class="text-xs text-gray-500">学习模式</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <div class="text-xl font-bold text-yellow-400">${stats.intent_clusters || 0}</div>
            <div class="text-xs text-gray-500">意图聚类</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 text-center">
            <div class="text-xl font-bold text-purple-400">${compression.total_compression_events || 0}</div>
            <div class="text-xs text-gray-500">压缩事件</div>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <!-- Proposals -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <h3 class="font-bold mb-3"><i class="fas fa-lightbulb text-yellow-400 mr-2"></i>改进建议 (${latestProposals.length})</h3>
          <div class="space-y-2 max-h-64 overflow-y-auto">${proposalHtml}</div>
        </div>

        <!-- Insights -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <h3 class="font-bold mb-3"><i class="fas fa-brain text-green-400 mr-2"></i>学习洞察</h3>
          <div class="space-y-2 max-h-64 overflow-y-auto">${insightHtml}</div>
        </div>
      </div>

      <!-- Compression Stats -->
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <h3 class="font-bold mb-3"><i class="fas fa-compress-alt text-blue-400 mr-2"></i>上下文压缩</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div class="bg-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">压缩次数</div>
            <div class="text-sm text-gray-300 mt-1">${compression.total_compression_events || 0} 次</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">平均减少 tokens</div>
            <div class="text-sm text-blue-400 mt-1">${compression.avg_token_reduction || 0}</div>
          </div>
          <div class="bg-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">压缩成功率</div>
            <div class="text-sm text-gray-300 mt-1">${compression.compression_success_rate !== undefined ? (compression.compression_success_rate * 100).toFixed(0) : '—'}%</div>
          </div>
        </div>
      </div>

      <!-- Reports History -->
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <h3 class="font-bold mb-3"><i class="fas fa-history text-blue-400 mr-2"></i>历史报告 (${reports.length})</h3>
        ${reports.length > 0 ? `
          <div class="space-y-2">
            ${reports.map(r => `
              <div class="bg-gray-800 rounded-lg px-3 py-2 text-sm flex items-center justify-between">
                <div>
                  <span class="text-gray-400">${new Date(r.timestamp * 1000).toLocaleString()}</span>
                  <span class="ml-2 ${(r.health_score || 0) >= 0.8 ? 'text-green-400' : 'text-yellow-400'}">${((r.health_score || 0) * 100).toFixed(0)}%</span>
                </div>
                <span class="text-xs text-gray-500">${(r.proposals || []).length} 建议 · ${(r.actions_taken || []).length} 行动</span>
              </div>
            `).join('')}
          </div>
        ` : '<div class="text-gray-500 text-sm">暂无历史报告</div>'}
      </div>
    `;
  } catch (e) {
    container.innerHTML = `<div class="text-red-400 p-4">加载失败: ${escapeHtml(e.message)} <button onclick="loadEvolution()" class="ml-2 text-blue-400 hover:text-blue-300 underline">重试</button></div>`;
  }
}

function setCurrentModel(modelId) {
  selectedModel = modelId;
  localStorage.setItem('js-selected-model', modelId);
  const select = document.getElementById('current-model');
  if (select) select.value = modelId;
  const label = availableModels.find(m => m.id === modelId);
  const display = label ? (label.name || label.id) : '默认模型';
  const badge = document.getElementById('model-badge');
  if (badge) badge.textContent = display;
}

let discoveredModels = [];

function toggleAddProvider() {
  const form = document.getElementById('add-provider-form');
  const chevron = document.getElementById('add-provider-chevron');
  const isHidden = form.classList.contains('hidden');
  form.classList.toggle('hidden');
  chevron.classList.toggle('rotate-180');
  if (isHidden) {
    // Reset state when opening
    document.getElementById('provider-error').classList.add('hidden');
    document.getElementById('discover-results').classList.add('hidden');
    document.getElementById('btn-save-provider').classList.add('hidden');
    discoveredModels = [];
  }
}

async function discoverModels() {
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
  // Basic URL validation
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

    discoveredModels = data.models || [];
    if (discoveredModels.length === 0) {
      errEl.textContent = '未发现任何模型，请检查 URL 是否正确';
      errEl.classList.remove('hidden');
      resultsEl.classList.add('hidden');
      document.getElementById('btn-save-provider').classList.add('hidden');
      return;
    }

    listEl.innerHTML = discoveredModels.map(m => `
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

async function saveProvider() {
  const name = document.getElementById('provider-name').value.trim();
  const url = document.getElementById('provider-url').value.trim();
  const key = document.getElementById('provider-key').value.trim();
  const errEl = document.getElementById('provider-error');
  const btn = document.getElementById('btn-save-provider');

  if (!name) { errEl.textContent = '请输入 Provider 名称'; errEl.classList.remove('hidden'); return; }
  if (!url) { errEl.textContent = '请输入 Base URL'; errEl.classList.remove('hidden'); return; }

  const checks = document.querySelectorAll('.discover-model-check:checked');
  const selectedIds = new Set(Array.from(checks).map(c => c.value));
  const selectedModels = discoveredModels.filter(m => selectedIds.has(m.id));
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

    // Reset form
    document.getElementById('provider-name').value = '';
    document.getElementById('provider-url').value = '';
    document.getElementById('provider-key').value = '';
    document.getElementById('discover-results').classList.add('hidden');
    document.getElementById('btn-save-provider').classList.add('hidden');
    discoveredModels = [];

    showToast('Provider 添加成功: ' + data.provider);
    toggleAddProvider(); // collapse form
    loadModels();
  } catch (e) {
    errEl.textContent = '保存失败: ' + e.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-check mr-1"></i>保存 Provider';
  }
}

async function deleteProvider(name) {
  const display = name.length > 50 ? name.slice(0, 50) + '...' : name;
  if (!confirm('确定删除 Provider "' + display.replace(/[\r\n]/g, '') + '" 吗？')) return;
  try {
    const res = await fetch('/api/providers/' + encodeURIComponent(name), { method: 'DELETE' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    showToast('Provider 已删除');
    loadModels();
  } catch (e) {
    showToast('删除失败: ' + e.message, true);
  }
}

function showToast(msg, isError) {
  const div = document.createElement('div');
  div.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm z-50 transition-opacity ${isError ? 'bg-red-600' : 'bg-green-600'} text-white`;
  div.textContent = msg;
  document.body.appendChild(div);
  setTimeout(() => { div.style.opacity = '0'; setTimeout(() => div.remove(), 300); }, 2500);
}

async function loadModels() {
  showLoading('models-content', '加载模型...');
  try {
  const res = await fetch('/api/models');
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const data = await res.json();
  const container = document.getElementById('models-content');
  const select = document.getElementById('current-model');

  // Build flat model list for dropdown
  availableModels = [];
  if (data.providers) {
    data.providers.forEach(p => {
      p.models.forEach(m => {
        availableModels.push({
          id: `${p.name}/${m.id}`,
          name: `${p.name}/${m.name || m.id}`,
          provider: p.name,
          ...m
        });
      });
    });
  }

  // Update header dropdown
  if (select) {
    const currentVal = select.value;
    select.innerHTML = '<option value="">默认模型</option>' +
      availableModels.map(m => `<option value="${escapeHtml(m.id)}">${escapeHtml(m.name)}</option>`).join('');
    select.value = currentVal || selectedModel || '';
  }

  if (!data.providers || data.providers.length === 0) {
    container.innerHTML = '<div class="text-gray-400">未配置模型 Provider</div>';
    return;
  }

  container.innerHTML = data.providers.map(p => `
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div class="flex items-center justify-between mb-3">
        <h3 class="font-bold text-lg">${escapeHtml(p.name)}</h3>
        <div class="flex items-center gap-2">
          <span class="text-xs px-2 py-1 rounded ${data.health && p.name in data.health ? (data.health[p.name] ? 'bg-green-900 text-green-400' : 'bg-red-900 text-red-400') : 'bg-gray-800 text-gray-500'}">
            ${data.health && p.name in data.health ? (data.health[p.name] ? '在线' : '离线') : '未知'}
          </span>
          <button onclick='deleteProvider(${JSON.stringify(p.name)})' class="text-xs bg-red-900/50 hover:bg-red-900 text-red-400 px-2 py-1 rounded transition" title="删除">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
      <p class="text-sm text-gray-400 mb-3">${escapeHtml(p.base_url)}</p>
      <div class="space-y-2">
        ${p.models.map(m => {
          const fullId = `${p.name}/${m.id}`;
          const isActive = selectedModel === fullId;
          return `
          <div class="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2 ${isActive ? 'ring-1 ring-blue-500' : ''}">
            <div>
              <span class="text-sm">${escapeHtml(m.name || m.id)}</span>
              <span class="text-xs text-gray-500 font-mono ml-2">${escapeHtml(m.id)}</span>
              ${isActive ? '<span class="text-xs bg-blue-900 text-blue-400 px-1.5 py-0.5 rounded ml-2">当前</span>' : ''}
            </div>
            <button onclick="setCurrentModel(${JSON.stringify(fullId)})" class="text-xs ${isActive ? 'bg-gray-700 text-gray-400 cursor-default' : 'bg-blue-600 hover:bg-blue-700 text-white'} px-2 py-1 rounded transition">
              ${isActive ? '使用中' : '使用'}
            </button>
          </div>
          `;
        }).join('')}
      </div>
    </div>
  `).join('');
  } catch (e) {
    showError('models-content', '加载模型失败: ' + e.message);
  }
}

async function loadSearch() {
  document.getElementById('search-results').innerHTML = '';
}

async function doSearch() {
  const input = document.getElementById('search-input');
  const query = input.value.trim();
  if (!query) return;
  const container = document.getElementById('search-results');
  container.innerHTML = '<div class="text-gray-400"><i class="fas fa-spinner fa-spin mr-2"></i>搜索中...</div>';
  try {
    const res = await fetch('/api/search?query=' + encodeURIComponent(query) + '&max_results=5');
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'HTTP ' + res.status);
    }
    const data = await res.json();
    if (!data.results || data.results.length === 0) {
      container.innerHTML = '<div class="text-gray-400">未找到结果</div>';
      return;
    }
    container.innerHTML = data.results.map((r, i) => `
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div class="flex items-start gap-3">
          <span class="text-blue-400 font-bold">${i + 1}</span>
          <div class="flex-1">
            <a href="${escapeHtml(r.url)}" target="_blank" class="font-bold hover:text-blue-400 transition">${escapeHtml(r.title)}</a>
            <p class="text-sm text-gray-400 mt-1">${escapeHtml(r.snippet)}</p>
            <span class="text-xs text-gray-600 mt-1 inline-block">${escapeHtml(r.source)}</span>
          </div>
        </div>
      </div>
    `).join('');
  } catch (e) {
    container.innerHTML = '<div class="text-red-400">搜索失败: ' + escapeHtml(e.message) + '</div>';
  }
}

async function loadStats() {
  showLoading('stats-content', '加载统计...');
  try {
  const res = await fetch('/api/stats/tokens');
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const data = await res.json();
  const container = document.getElementById('stats-content');

  if (data.error) {
    container.innerHTML = `<div class="text-red-400">${escapeHtml(data.error)}</div>`;
    return;
  }

  const totalPrompt = data.total_prompt_tokens || 0;
  const totalCompletion = data.total_completion_tokens || 0;
  const totalTokens = data.total_tokens || 0;
  const totalCost = data.total_cost || 0;
  const cacheRate = data.cache_rate || 0;

  let html = `
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-blue-400">${data.total_calls || 0}</div>
        <div class="text-xs text-gray-500 mt-1">总调用次数</div>
      </div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-green-400">${totalTokens.toLocaleString()}</div>
        <div class="text-xs text-gray-500 mt-1">总 Token 数</div>
      </div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-purple-400">$${totalCost.toFixed(4)}</div>
        <div class="text-xs text-gray-500 mt-1">预估成本</div>
      </div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-yellow-400">${cacheRate}%</div>
        <div class="text-xs text-gray-500 mt-1">缓存率</div>
      </div>
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-4">
      <h3 class="font-bold mb-3">模型用量明细</h3>
      ${!data.models || data.models.length === 0 ? '<div class="text-gray-400">暂无数据</div>' : `
        <div class="space-y-2">
          ${data.models.map(m => `
            <div class="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
              <div class="flex-1">
                <div class="text-sm font-medium">${escapeHtml(m.model)}</div>
                <div class="text-xs text-gray-500">调用 ${m.calls} 次 | 缓存率 ${m.cache_rate}%</div>
              </div>
              <div class="text-right">
                <div class="text-sm text-blue-400">${(m.total_tokens || 0).toLocaleString()}</div>
                <div class="text-xs text-gray-500">$${(m.cost || 0).toFixed(4)}</div>
              </div>
            </div>
          `).join('')}
        </div>
      `}
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <h3 class="font-bold mb-3">近 14 日趋势</h3>
      ${!data.daily || data.daily.length === 0 ? '<div class="text-gray-400">暂无数据</div>' : `
        <div class="space-y-2">
          ${data.daily.map(d => `
            <div class="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
              <span class="text-sm">${d.day}</span>
              <div class="text-right">
                <span class="text-sm text-blue-400 mr-3">${(d.tokens || 0).toLocaleString()} tokens</span>
                <span class="text-xs text-gray-500">${d.calls} 次</span>
              </div>
            </div>
          `).join('')}
        </div>
      `}
    </div>
  `;

  container.innerHTML = html;
  } catch (e) {
    showError('stats-content', '加载统计失败: ' + e.message);
  }
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('-translate-x-full');
}

function escapeHtml(text) {
  if (text == null) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}



document.getElementById('chat-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

// Close modals on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeSkillModal();
    closeMemoryFileEditor();
  }
});

// Debounced skill search
let _skillSearchTimeout;
document.getElementById('skill-search').addEventListener('input', () => {
  clearTimeout(_skillSearchTimeout);
  _skillSearchTimeout = setTimeout(loadSkills, 300);
});

// Add fade-in keyframes for attachment cards
const styleSheet = document.createElement('style');
styleSheet.textContent = `
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
  }
`;
document.head.appendChild(styleSheet);

connectWS();
loadModels();
loadSessions();
initDragDrop();

function renderMarkdown(text) {
  if (!text) return '';
  const result = [];
  const blockRegex = /(```(?:\w+)?\n[\s\S]*?```)/g;
  let lastIndex = 0;
  let match;
  while ((match = blockRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      result.push(_renderTextSegment(text.slice(lastIndex, match.index)));
    }
    const m = match[1].match(/```(\w+)?\n([\s\S]*?)```/);
    if (m) {
      result.push(`<pre class="bg-gray-950 p-3 rounded-lg overflow-x-auto my-2"><code>${escapeHtml(m[2])}</code></pre>`);
    }
    lastIndex = match.index + match[1].length;
  }
  if (lastIndex < text.length) {
    result.push(_renderTextSegment(text.slice(lastIndex)));
  }
  if (result.length === 0) {
    result.push(_renderTextSegment(text));
  }
  return result.join('');

  function _renderTextSegment(seg) {
    let html = escapeHtml(seg);
    html = html.replace(/`([^`]+)`/g, '<code class="bg-gray-700 px-1 rounded text-sm">$1</code>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
    return html.replace(/\n/g, '<br>');
  }
}
