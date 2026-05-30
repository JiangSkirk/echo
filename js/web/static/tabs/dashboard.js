import { escapeHtml } from '../utils/dom.js';

export async function loadDashboard() {
  const cardsEl = document.getElementById('dashboard-cards');
  const providersEl = document.getElementById('dashboard-providers');
  const tokenChartEl = document.getElementById('dashboard-token-chart');
  const toolsEl = document.getElementById('dashboard-tools');
  const healthEl = document.getElementById('dashboard-health');

  if (!cardsEl) return;

  cardsEl.innerHTML = '<div class="col-span-full text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>加载仪表盘...</div>';

  try {
    const res = await fetch('/api/dashboard');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const d = await res.json();

    // Top cards
    const totalCalls = d.token_stats?.total?.calls || 0;
    const totalTokens = (d.token_stats?.total?.prompt_tokens || 0) + (d.token_stats?.total?.completion_tokens || 0);
    const totalCost = d.token_stats?.total?.cost || 0;
    const healthyProviders = d.providers ? d.providers.filter(p => p.healthy).length : 0;
    const totalProviders = d.providers ? d.providers.length : 0;
    const sessionCount = d.session_count || 0;

    cardsEl.innerHTML = `
      <div class="bg-gray-800 rounded-xl p-4 border-l-4 border-blue-500">
        <div class="text-gray-400 text-xs mb-1">当前模型</div>
        <div class="text-lg font-bold truncate">${escapeHtml(d.active_model || '未设置')}</div>
        <div class="text-xs mt-1 ${d.overall_healthy ? 'text-green-400' : 'text-red-400'}">
          <i class="fas fa-circle text-[8px] mr-1"></i>${d.overall_healthy ? '全部健康' : '部分异常'}
        </div>
      </div>
      <div class="bg-gray-800 rounded-xl p-4 border-l-4 border-green-500">
        <div class="text-gray-400 text-xs mb-1">总调用 / Token</div>
        <div class="text-lg font-bold">${totalCalls.toLocaleString()} <span class="text-sm font-normal text-gray-400">/ ${totalTokens.toLocaleString()}</span></div>
        <div class="text-xs mt-1 text-gray-400">${d.token_stats?.total?.prompt_tokens?.toLocaleString() || 0} 输入 + ${d.token_stats?.total?.completion_tokens?.toLocaleString() || 0} 输出</div>
      </div>
      <div class="bg-gray-800 rounded-xl p-4 border-l-4 border-yellow-500">
        <div class="text-gray-400 text-xs mb-1">预估成本</div>
        <div class="text-lg font-bold">$${totalCost.toFixed(4)}</div>
        <div class="text-xs mt-1 text-gray-400">缓存率 ${(d.token_stats?.total?.cache_rate || 0).toFixed(1)}%</div>
      </div>
      <div class="bg-gray-800 rounded-xl p-4 border-l-4 border-purple-500">
        <div class="text-gray-400 text-xs mb-1">Provider / 会话</div>
        <div class="text-lg font-bold">${healthyProviders}/${totalProviders} <span class="text-sm font-normal text-gray-400">/ ${sessionCount}</span></div>
        <div class="text-xs mt-1 text-gray-400">${d.skills?.total || 0} skills · ${d.fleet?.agents || 0} agents</div>
      </div>
    `;

    // Providers grid
    if (d.providers && d.providers.length > 0) {
      providersEl.innerHTML = d.providers.map(p => {
        const circuitColor = p.circuit?.state === 'CLOSED' ? 'text-green-400' :
                            p.circuit?.state === 'HALF_OPEN' ? 'text-yellow-400' :
                            p.circuit?.state === 'OPEN' ? 'text-red-400' : 'text-gray-400';
        return `
          <div class="bg-gray-900 rounded-lg p-3 border ${p.healthy ? 'border-green-700/50' : 'border-red-700/50'}">
            <div class="flex items-center justify-between mb-2">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full ${p.healthy ? 'bg-green-400' : 'bg-red-400'}"></span>
                <span class="font-semibold text-sm">${escapeHtml(p.name)}</span>
              </div>
              <span class="text-xs ${circuitColor}">${p.circuit?.state || '?'}</span>
            </div>
            <div class="text-xs text-gray-400 mb-1 truncate">${escapeHtml(p.base_url || '')}</div>
            <div class="flex items-center justify-between text-xs">
              <span class="text-gray-500">${p.models_count} 模型</span>
              <span class="text-gray-500">默认: ${escapeHtml(p.default_model || '-')}</span>
            </div>
          </div>
        `;
      }).join('');
    } else {
      providersEl.innerHTML = '<div class="text-gray-400 text-sm col-span-full">未配置 Provider</div>';
    }

    // Token chart (CSS bar chart)
    const trend = d.token_stats?.daily_trend || [];
    if (trend.length > 0) {
      const maxTokens = Math.max(...trend.map(t => t.total_tokens || 0), 1);
      tokenChartEl.innerHTML = trend.map(t => {
        const h = Math.max((t.total_tokens / maxTokens) * 100, 4);
        return `<div class="flex-1 flex flex-col items-center gap-1 group" title="${t.date}: ${(t.total_tokens || 0).toLocaleString()} tokens">
          <div class="w-full bg-blue-600/80 rounded-t hover:bg-blue-500 transition relative" style="height:${h}px;">
            <div class="absolute -top-6 left-1/2 -translate-x-1/2 bg-gray-700 text-white text-[10px] px-1.5 py-0.5 rounded opacity-0 group-hover:opacity-100 transition whitespace-nowrap pointer-events-none z-10">${(t.total_tokens || 0).toLocaleString()}</div>
          </div>
          <div class="text-[9px] text-gray-500">${t.date?.slice(5) || ''}</div>
        </div>`;
      }).join('');
    } else {
      tokenChartEl.innerHTML = '<div class="text-gray-400 text-sm w-full text-center">暂无数据</div>';
    }

    // Tool stats
    if (d.tool_stats && Object.keys(d.tool_stats).length > 0) {
      const tools = Object.entries(d.tool_stats).sort((a, b) => (b[1] || 0) - (a[1] || 0)).slice(0, 10);
      const maxCount = Math.max(...tools.map(t => t[1] || 0), 1);
      toolsEl.innerHTML = tools.map(([name, count]) => {
        const pct = ((count || 0) / maxCount) * 100;
        return `<div class="flex items-center gap-2">
          <span class="text-xs text-gray-400 w-24 truncate">${escapeHtml(name)}</span>
          <div class="flex-1 bg-gray-700 rounded-full h-2 overflow-hidden">
            <div class="bg-green-500 h-full rounded-full" style="width:${pct}%"></div>
          </div>
          <span class="text-xs text-gray-400 w-8 text-right">${count || 0}</span>
        </div>`;
      }).join('');
    } else {
      toolsEl.innerHTML = '<div class="text-gray-400 text-sm">暂无工具使用数据</div>';
    }

    // Health
    healthEl.innerHTML = `
      <div class="flex items-center justify-between py-1 border-b border-gray-700/50">
        <span class="text-sm text-gray-400">Agent 状态</span>
        <span class="text-sm ${d.degraded ? 'text-yellow-400' : 'text-green-400'}">${d.degraded ? '降级模式' : '正常运行'}</span>
      </div>
      <div class="flex items-center justify-between py-1 border-b border-gray-700/50">
        <span class="text-sm text-gray-400">嵌入模型</span>
        <span class="text-sm ${d.embedder?.active ? 'text-green-400' : 'text-red-400'}">${d.embedder?.active ? '运行中' : '不可用'} (${escapeHtml(d.embedder?.provider || '-')})</span>
      </div>
      <div class="flex items-center justify-between py-1 border-b border-gray-700/50">
        <span class="text-sm text-gray-400">Skill 总数</span>
        <span class="text-sm text-gray-300">${d.skills?.total || 0} (内置 ${d.skills?.builtin || 0}, Hermes ${d.skills?.hermes || 0})</span>
      </div>
      <div class="flex items-center justify-between py-1 border-b border-gray-700/50">
        <span class="text-sm text-gray-400">Fleet 状态</span>
        <span class="text-sm text-gray-300">${d.fleet?.enabled ? `运行中 (${d.fleet.agents} agents)` : '未启用'}</span>
      </div>
      <div class="flex items-center justify-between py-1">
        <span class="text-sm text-gray-400">版本</span>
        <span class="text-sm text-gray-300 font-mono">${escapeHtml(d.version || '')}</span>
      </div>
    `;

  } catch (e) {
    cardsEl.innerHTML = `<div class="col-span-full text-red-400 text-sm"><i class="fas fa-exclamation-circle mr-2"></i>加载失败: ${escapeHtml(e.message)}</div>`;
    providersEl.innerHTML = '<div class="text-red-400 text-sm col-span-full">加载失败</div>';
    tokenChartEl.innerHTML = '<div class="text-red-400 text-sm w-full text-center">加载失败</div>';
    toolsEl.innerHTML = '<div class="text-red-400 text-sm">加载失败</div>';
    healthEl.innerHTML = '<div class="text-red-400 text-sm">加载失败</div>';
  }
}
