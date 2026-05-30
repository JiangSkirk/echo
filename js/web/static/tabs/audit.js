import { escapeHtml, showLoading, showError } from '../utils/dom.js';

export async function loadAudit() {
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
