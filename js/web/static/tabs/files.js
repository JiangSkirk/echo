import { showLoading, showError } from '../utils/dom.js';

export async function loadFiles() {
  showLoading('files-content', '加载文件...');
  try {
    const res = await fetch('/api/files');
    const data = await res.json();
    document.getElementById('files-content').textContent = data.output || data.error || '无内容';
  } catch (e) {
    showError('files-content', '加载失败: ' + e.message);
  }
}
