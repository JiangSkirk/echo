import { escapeHtml, showLoading, showError } from '../utils/dom.js';

export async function loadStats() {
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
