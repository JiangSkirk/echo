import { bindDataClicks, escapeHtml, sanitizeRuntimeId, showToast } from '../utils/dom.js';

export async function refreshCronJobs() {
  try {
    const res = await fetch('/api/cron/jobs');
    const data = await res.json();
    renderCronJobs(data.jobs || []);
  } catch (e) {
    console.error('Failed to load cron jobs:', e);
    document.getElementById('cron-jobs-list').innerHTML =
      '<tr><td colspan="7" class="p-4 text-red-400 text-center">加载失败</td></tr>';
  }
  // Also refresh stats
  try {
    const statsRes = await fetch('/api/cron/stats');
    const stats = await statsRes.json();
    document.getElementById('cron-stat-total').textContent = stats.total_jobs || 0;
    document.getElementById('cron-stat-active').textContent = stats.active_jobs || 0;
    document.getElementById('cron-stat-runs').textContent = stats.total_runs || 0;
    document.getElementById('cron-stat-rate').textContent =
      (stats.success_rate || 0).toFixed(1) + '%';
  } catch (e) {
    console.error('Failed to load cron stats:', e);
  }
}

export function renderCronJobs(jobs) {
  const tbody = document.getElementById('cron-jobs-list');
  if (!jobs.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-gray-500 text-center">暂无定时任务</td></tr>';
    return;
  }
  tbody.innerHTML = jobs.map(job => {
    const statusColor = {
      'pending': 'text-gray-400',
      'running': 'text-blue-400',
      'completed': 'text-green-400',
      'failed': 'text-red-400',
      'paused': 'text-yellow-400',
      'disabled': 'text-gray-600'
    }[job.status] || 'text-gray-400';
    const nextRun = job.next_run_at ? new Date(job.next_run_at * 1000).toLocaleString('zh-CN', {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}) : '-';
    const isEnabled = job.enabled;
    return `<tr class="hover:bg-gray-800/50">
      <td class="p-3"><span class="${statusColor} text-xs">● ${escapeHtml(String(job.status || ''))}</span></td>
      <td class="p-3">${escapeHtml(job.name)}</td>
      <td class="p-3 text-gray-400 text-xs">${escapeHtml(job.schedule_summary || job.cron_expr)}</td>
      <td class="p-3 text-xs"><span class="bg-gray-800 px-2 py-0.5 rounded">${escapeHtml(String(job.task_type || ''))}</span></td>
      <td class="p-3 text-gray-400 text-xs">${escapeHtml(nextRun)}</td>
      <td class="p-3 text-xs">${escapeHtml(String(job.run_count))} / ${escapeHtml(String(job.fail_count))}</td>
      <td class="p-3 text-right">
        <button type="button" data-cron-action="run" data-job-id="${escapeHtml(String(job.id ?? ''))}" class="text-xs text-blue-400 hover:text-blue-300 mr-2" title="立即执行"><i class="fas fa-play"></i></button>
        <button type="button" data-cron-action="toggle" data-job-id="${escapeHtml(String(job.id ?? ''))}" data-enabled="${isEnabled ? '0' : '1'}" class="text-xs ${isEnabled ? 'text-yellow-400' : 'text-green-400'} hover:opacity-80 mr-2" title="${isEnabled ? '暂停' : '启用'}"><i class="fas fa-${isEnabled ? 'pause' : 'play'}"></i></button>
        <button type="button" data-cron-action="delete" data-job-id="${escapeHtml(String(job.id ?? ''))}" class="text-xs text-red-400 hover:text-red-300" title="删除"><i class="fas fa-trash"></i></button>
      </td>
    </tr>`;
  }).join('');
  bindDataClicks(tbody, 'jobId', (rawId, event) => {
    const jobId = sanitizeRuntimeId(rawId);
    if (!jobId) return;
    const action = event.currentTarget.dataset.cronAction;
    if (action === 'run') runCronJob(jobId);
    else if (action === 'toggle') toggleCronJob(jobId, event.currentTarget.dataset.enabled === '1');
    else if (action === 'delete') deleteCronJob(jobId);
  });
}

export async function runCronJob(jobId) {
  try {
    const res = await fetch(`/api/cron/jobs/${encodeURIComponent(jobId)}/run`, {method: 'POST'});
    const data = await res.json();
    if (data.success) {
      showToast('任务执行成功', 'success');
    } else {
      showToast('任务执行失败: ' + (data.error || ''), 'error');
    }
    refreshCronJobs();
  } catch (e) {
    showToast('执行失败', 'error');
  }
}

export async function toggleCronJob(jobId, enabled) {
  try {
    await fetch(`/api/cron/jobs/${encodeURIComponent(jobId)}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled})
    });
    showToast(enabled ? '任务已启用' : '任务已暂停', 'success');
    refreshCronJobs();
  } catch (e) {
    showToast('操作失败', 'error');
  }
}

export async function deleteCronJob(jobId) {
  if (!confirm('确定要删除这个定时任务吗？')) return;
  try {
    await fetch(`/api/cron/jobs/${encodeURIComponent(jobId)}`, {method: 'DELETE'});
    showToast('任务已删除', 'success');
    refreshCronJobs();
  } catch (e) {
    showToast('删除失败', 'error');
  }
}

export async function loadCronTemplates() {
  try {
    const res = await fetch('/api/cron/templates');
    const data = await res.json();
    const select = document.getElementById('cron-template-select');
    data.templates.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = `${t.icon} ${t.name}`;
      select.appendChild(opt);
    });
  } catch (e) {
    console.error('Failed to load templates:', e);
  }
}

export function showCronCreateModal() {
  document.getElementById('cron-create-modal').classList.remove('hidden');
  loadCronTemplates();
}

export function hideCronCreateModal() {
  document.getElementById('cron-create-modal').classList.add('hidden');
}

export async function onCronTemplateChange() {
  const templateId = document.getElementById('cron-template-select').value;
  if (!templateId) return;
  try {
    const res = await fetch('/api/cron/templates');
    const data = await res.json();
    const t = data.templates.find(x => x.id === templateId);
    if (t) {
      document.getElementById('cron-name').value = t.name;
      document.getElementById('cron-expr').value = t.default_cron;
      document.getElementById('cron-task-type').value = t.task_type;
      document.getElementById('cron-payload').value = JSON.stringify(t.default_payload || {}, null, 2);
    }
  } catch (e) {
    console.error(e);
  }
}

export async function parseCronNatural() {
  const text = document.getElementById('cron-natural').value;
  if (!text) return;
  try {
    const res = await fetch('/api/cron/parse', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text})
    });
    const data = await res.json();
    const resultEl = document.getElementById('cron-parse-result');
    if (data.matched) {
      document.getElementById('cron-expr').value = data.cron_expr;
      resultEl.textContent = `✓ 解析为: ${data.summary}`;
      resultEl.classList.remove('hidden', 'text-red-400');
      resultEl.classList.add('text-green-400');
    } else {
      resultEl.textContent = '✗ 无法解析，请尝试标准 Cron 表达式';
      resultEl.classList.remove('hidden', 'text-green-400');
      resultEl.classList.add('text-red-400');
    }
  } catch (e) {
    console.error(e);
  }
}

export async function submitCronJob() {
  const name = document.getElementById('cron-name').value;
  const cronExpr = document.getElementById('cron-expr').value;
  const taskType = document.getElementById('cron-task-type').value;
  const payloadStr = document.getElementById('cron-payload').value;
  const templateId = document.getElementById('cron-template-select').value;

  if (!name || !cronExpr) {
    showToast('请填写任务名称和调度规则', 'error');
    return;
  }

  let payload = {};
  try {
    payload = JSON.parse(payloadStr || '{}');
  } catch (e) {
    showToast('参数 JSON 格式错误', 'error');
    return;
  }

  const body = templateId
    ? {template_id: templateId, name, cron_expr: cronExpr, payload}
    : {name, cron_expr: cronExpr, task_type: taskType, payload};

  try {
    const res = await fetch('/api/cron/jobs', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.success) {
      showToast('任务创建成功', 'success');
      hideCronCreateModal();
      refreshCronJobs();
    } else {
      showToast(data.error || '创建失败', 'error');
    }
  } catch (e) {
    showToast('创建失败', 'error');
  }
}
