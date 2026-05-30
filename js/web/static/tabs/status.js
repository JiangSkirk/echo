import { showLoading, showError } from '../utils/dom.js';

export async function loadStatus() {
  showLoading('status-content', '加载系统状态...');
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('status-content').textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    showError('status-content', '加载失败: ' + e.message);
  }
}
