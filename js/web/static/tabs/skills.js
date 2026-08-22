import { state } from '../state/store.js';
import { bindDataClicks, escapeHtml, showToast, showLoading, showError, sanitizeRuntimeId } from '../utils/dom.js';

export async function loadSkills() {
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
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 cursor-pointer hover:border-blue-500 transition" data-skill-id="${escapeHtml(String(s.id ?? ''))}">
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
    bindDataClicks(container, 'skillId', (rawId) => {
      const skillId = sanitizeRuntimeId(rawId);
      if (skillId) showSkillDetail(skillId);
    });
  } catch (e) {
    showError('skills-content', '加载失败: ' + e.message);
  }
}

export async function showSkillDetail(skillId) {
  state.currentSkillId = skillId;
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

export function closeSkillModal() {
  document.getElementById('skill-detail-modal').classList.add('hidden');
  state.currentSkillId = null;
}

export async function updateTrust() {
  if (!state.currentSkillId) return;
  const level = document.getElementById('modal-trust-select').value;
  try {
    const res = await fetch('/api/skills/' + encodeURIComponent(state.currentSkillId) + '/trust', {
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
      showToast(data.error || '更新失败', 'error');
    }
  } catch (e) {
    showToast('更新信任级别失败: ' + e.message, 'error');
  }
}

export async function uninstallSkill() {
  if (!state.currentSkillId) return;
  if (!confirm(`Uninstall skill '${state.currentSkillId}'?`)) return;
  try {
    const res = await fetch('/api/skills/' + encodeURIComponent(state.currentSkillId), {method: 'DELETE'});
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'HTTP ' + res.status);
    }
    loadSkills();
    closeSkillModal();
    showToast('Skill 已卸载');
  } catch (e) {
    showToast('卸载失败: ' + e.message, 'error');
  }
}
