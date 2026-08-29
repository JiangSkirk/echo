import { bindDataClicks, escapeHtml, sanitizeRuntimeId, showToast } from '../utils/dom.js';

export async function runEvolutionNow() {
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
        showToast('服务器版本过旧，请重启服务器以支持自主进化', 'warning');
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
    showToast('运行失败: ' + e.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-play text-xs"></i> 立即运行';
    }
  }
}

export async function loadEvolution() {
  const container = document.getElementById('evolution-content');
  container.innerHTML = '<div class="text-gray-400"><i class="fas fa-spinner fa-spin mr-2"></i>加载进化数据...</div>';

  try {
    const [reportsRes, insightsRes, proposalsRes] = await Promise.all([
      fetch('/api/evolution/reports?limit=5'),
      fetch('/api/evolution/insights?limit=10'),
      fetch('/api/evolution/proposals?limit=20'),
    ]);
    if (!reportsRes.ok || !insightsRes.ok) throw new Error('API error');
    const reportsData = await reportsRes.json();
    const insightsData = await insightsRes.json();
    const proposalsData = proposalsRes.ok ? await proposalsRes.json() : { cycle_proposals: [] };
    const cycleProposals = Array.isArray(proposalsData.cycle_proposals)
      ? proposalsData.cycle_proposals
      : [];

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

    // Prompt optimizer status — driven by real backend data
    const opt = insightsData.optimization || {};
    const promptOptStatus = (opt.total_variants || 0) > 0
      ? ((opt.best_usage || 0) > 0
        ? { icon: 'fa-check-circle', color: 'text-green-400', label: '活跃', detail: `${opt.total_variants} 变体 · 最佳 ${((opt.best_success_rate || 0) * 100).toFixed(0)}%` }
        : { icon: 'fa-flask', color: 'text-blue-400', label: '已注册', detail: `${opt.total_variants} 个变体等待测试` })
      : { icon: 'fa-clock', color: 'text-gray-400', label: '等待数据', detail: '暂无变体记录' };

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

      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4" id="evolution-cycle-desk">
        <h3 class="font-bold mb-3"><i class="fas fa-gavel text-purple-400 mr-2"></i>进化提案审批 (${cycleProposals.length})</h3>
        <p class="text-xs text-gray-500 mb-3">生成只写提案。批准走 Echo control_evolution_action，回归则自动回滚。无人值守自改不存在。</p>
        <div class="space-y-2" id="evolution-cycle-list">${renderCycleProposals(cycleProposals)}</div>
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
    bindCycleProposalActions(container);
  } catch (e) {
    container.innerHTML = `<div class="text-red-400 p-4">加载失败: ${escapeHtml(e.message)} <button onclick="loadEvolution()" class="ml-2 text-blue-400 hover:text-blue-300 underline">重试</button></div>`;
  }
}

function renderCycleProposals(rows) {
  if (!rows.length) {
    return '<div class="text-gray-500 text-sm">暂无待审批提案。定时 skill_evolve 只会生成提案，不会自动应用。</div>';
  }
  return rows.map((item) => {
    const id = sanitizeRuntimeId(item.proposal_id || '');
    const status = escapeHtml(item.status || '');
    const title = escapeHtml(item.title || item.kind || id || 'proposal');
    const open = String(item.status || '') === 'proposed';
    const actions = open && id
      ? `<button class="text-xs bg-green-900/40 hover:bg-green-900/60 text-green-300 px-2 py-1 rounded" data-proposal-id="${escapeHtml(id)}" data-evolution-action="approve">批准并应用</button>
         <button class="text-xs bg-red-900/40 hover:bg-red-900/60 text-red-300 px-2 py-1 rounded" data-proposal-id="${escapeHtml(id)}" data-evolution-action="reject">驳回</button>`
      : `<span class="text-xs text-gray-500">${status}</span>`;
    return `<div class="bg-gray-800 rounded-lg px-3 py-2 text-sm flex flex-wrap items-center justify-between gap-2">
      <div>
        <div class="text-gray-200">${title}</div>
        <div class="text-xs text-gray-500">${escapeHtml(item.kind || '')} · ${status}</div>
      </div>
      <div class="flex gap-2">${actions}</div>
    </div>`;
  }).join('');
}

function bindCycleProposalActions(root) {
  bindDataClicks(root, 'evolutionAction', (action, event) => {
    const node = event.currentTarget;
    const proposalId = node instanceof HTMLElement
      ? sanitizeRuntimeId(node.dataset.proposalId || '')
      : '';
    if (!proposalId) return;
    if (action === 'approve') decideEvolutionProposal(proposalId, 'approve');
    if (action === 'reject') decideEvolutionProposal(proposalId, 'reject');
  });
}

export async function decideEvolutionProposal(proposalId, action) {
  const id = sanitizeRuntimeId(proposalId);
  if (!id || (action !== 'approve' && action !== 'reject')) return;
  try {
    const res = await fetch(`/api/evolution/proposals/${encodeURIComponent(id)}/${action}`, {
      method: 'POST',
    });
    if (!res.ok) {
      let detail = '';
      try {
        const err = await res.json();
        detail = err.detail || '';
      } catch (_) {}
      throw new Error(detail || ('HTTP ' + res.status));
    }
    const data = await res.json();
    showToast(
      action === 'approve'
        ? `提案 ${data.status || '已处理'}`
        : '提案已驳回',
      data.status === 'regressed' ? 'warning' : 'success',
    );
    loadEvolution();
  } catch (error) {
    showToast('审批失败: ' + error.message, 'error');
  }
}
