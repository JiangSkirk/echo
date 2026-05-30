import { escapeHtml } from '../utils/dom.js';

export async function loadSearch() {
  document.getElementById('search-results').innerHTML = '';
}

export async function doSearch() {
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
