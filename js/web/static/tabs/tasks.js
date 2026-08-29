import { escapeHtml } from '../utils/dom.js';

let tasksPollInterval = null;

export async function loadTasks() {
  const container = document.getElementById('tasks-list');
  if (!container) return;
  container.innerHTML = '<div class="text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>加载任务...</div>';

  try {
    const res = await fetch('/api/tasks?limit=50');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const tasks = data.tasks || [];
    renderTasks(tasks, container);
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-sm">加载失败: ' + escapeHtml(e.message) + '</div>';
  }
}

function renderTasks(tasks, container) {
  if (tasks.length === 0) {
    container.innerHTML = '<div class="text-gray-400 text-sm text-center py-8">暂无 Goal。从场景模板启动，或在 Bots 房间里提出任务。</div>';
    return;
  }

  const statusConfig = {
    running: { color: 'text-blue-400', bg: 'bg-blue-900/30', icon: 'fa-spinner fa-spin', label: '执行中' },
    paused: { color: 'text-yellow-400', bg: 'bg-yellow-900/30', icon: 'fa-pause', label: '已暂停' },
    completed: { color: 'text-green-400', bg: 'bg-green-900/30', icon: 'fa-check', label: '已完成' },
    failed: { color: 'text-red-400', bg: 'bg-red-900/30', icon: 'fa-times', label: '失败' },
    pending: { color: 'text-gray-400', bg: 'bg-gray-800', icon: 'fa-clock', label: '澄清中' },
  };

  container.innerHTML = tasks.map(t => {
    const cfg = statusConfig[t.status] || statusConfig.pending;
    const progressRaw = Number(t.progress);
    const progressPct = Number.isFinite(progressRaw)
      ? Math.min(100, Math.max(0, Math.round(progressRaw * 100)))
      : 0;
    const timeStr = t.updated_at ? new Date(t.updated_at * 1000).toLocaleString() : '--';
    return `
      <div class="bg-gray-800 rounded-lg p-3 border border-gray-700">
        <div class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span class="text-xs px-2 py-0.5 rounded ${cfg.bg} ${cfg.color}">
              <i class="fas ${cfg.icon} mr-1"></i>${cfg.label}
            </span>
            <span class="text-sm font-medium text-gray-200">${escapeHtml(t.name)}</span>
            <span class="text-[10px] text-gray-500">${escapeHtml(t.type || 'bots_goal')}</span>
            ${t.phase ? `<span class="text-[10px] text-gray-500">${escapeHtml(t.phase)}</span>` : ''}
          </div>
        </div>
        <div class="w-full bg-gray-700 rounded-full h-1.5 mb-2">
          <div class="bg-blue-500 h-1.5 rounded-full transition-all" style="width: ${progressPct}%"></div>
        </div>
        <div class="flex items-center justify-between text-[10px] text-gray-500">
          <span>进度: ${progressPct}%</span>
          <span>更新: ${timeStr}</span>
        </div>
        ${t.result_preview ? `<div class="text-xs text-gray-400 mt-1 truncate">${escapeHtml(t.result_preview)}</div>` : ''}
        ${t.error ? `<div class="text-xs text-red-400 mt-1">${escapeHtml(t.error)}</div>` : ''}
      </div>
    `;
  }).join('');
}

export function startTasksPolling() {
  if (tasksPollInterval) return;
  tasksPollInterval = setInterval(() => {
    const tab = document.getElementById('tab-tasks');
    if (tab && !tab.classList.contains('hidden')) {
      loadTasks();
    }
  }, 5000);
}

export function stopTasksPolling() {
  if (tasksPollInterval) {
    clearInterval(tasksPollInterval);
    tasksPollInterval = null;
  }
}
