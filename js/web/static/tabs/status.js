import { showLoading, showError, showToast, escapeHtml } from '../utils/dom.js';

// Fixed Tailwind classes per health state (no string interpolation, so the
// CDN build always ships these utilities).
const _HEALTH_STYLES = {
  ok:          { box: 'bg-green-900/20 border-green-900/40',  text: 'text-green-400',  icon: 'check-circle' },
  degraded:    { box: 'bg-yellow-900/20 border-yellow-900/40', text: 'text-yellow-400', icon: 'exclamation-triangle' },
  no_provider: { box: 'bg-red-900/20 border-red-900/40',      text: 'text-red-400',    icon: 'times-circle' },
};

export async function loadStatus() {
  showLoading('status-content', '加载系统状态...');
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const style = _HEALTH_STYLES[data.overall_status] || {
      box: 'bg-gray-800 border-gray-700', text: 'text-gray-300', icon: 'info-circle',
    };
    let html = `<div class="mb-3 p-3 rounded border ${style.box}">
      <div class="${style.text} font-medium">
        <i class="fas fa-${style.icon} mr-1.5"></i>${escapeHtml(data.overall_status_text || '状态未知')}
      </div>`;
    if (data.suggestion) {
      html += `<div class="text-xs text-gray-400 mt-1">${escapeHtml(data.suggestion)}</div>`;
    }
    html += `</div>
      <details class="text-xs">
        <summary class="cursor-pointer text-gray-500 hover:text-gray-300">技术详情</summary>
        <pre class="mt-2 whitespace-pre-wrap break-all text-gray-400">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
      </details>`;
    document.getElementById('status-content').innerHTML = html;
    await loadDesktopWizard();
  } catch (e) {
    showError('status-content', '加载失败: ' + e.message);
  }
}

// ── Desktop Control First-Use Wizard ──

let _wizardPollTimer = null;

async function loadDesktopWizard() {
  const container = document.getElementById('desktop-wizard-container');
  if (!container) return;
  try {
    const res = await fetch('/api/desktop/wizard');
    if (!res.ok) {
      const errText = await res.text();
      let errMsg = errText;
      try { const j = JSON.parse(errText); errMsg = j.detail || j.error || errText; } catch (_) {}
      container.innerHTML = `<div class="text-xs text-red-400"><i class="fas fa-exclamation-triangle mr-1"></i>服务器错误 (${res.status}): ${errMsg.substring(0, 300)}</div>`;
      return;
    }
    const data = await res.json();
    renderWizard(container, data);
  } catch (e) {
    container.innerHTML = `<div class="text-xs text-red-400"><i class="fas fa-exclamation-triangle mr-1"></i>网络错误: ${e.message}。请检查服务器是否在运行。</div>`;
  }
}

function _stepIcon(status) {
  return status === 'ok' ? 'check-circle' :
         status === 'unavailable' ? 'times-circle' :
         status === 'error' ? 'exclamation-triangle' : 'exclamation-circle';
}

function _stepColor(status) {
  return status === 'ok' ? 'text-green-400' :
         status === 'unavailable' ? 'text-red-400' :
         status === 'error' ? 'text-red-400' : 'text-yellow-400';
}

function renderWizard(container, data) {
  if (data.overall_status === 'unsupported') {
    container.innerHTML = '<div class="text-xs text-gray-500"><i class="fas fa-info-circle mr-1"></i>桌面控制仅支持 macOS 平台</div>';
    return;
  }

  // Step cards
  let html = '<div class="space-y-1">';
  for (const step of data.steps) {
    html += `<div class="flex items-center justify-between py-0.5">
      <div class="flex items-center gap-1.5">
        <i class="fas fa-${_stepIcon(step.status)} ${_stepColor(step.status)} text-xs"></i>
        <span class="text-xs ${_stepColor(step.status)}">${step.title}</span>
        <span class="text-xs text-gray-600">— ${step.detail}</span>
      </div>`;
    if (step.action_type === 'install') {
      html += `<button onclick="window._wizardConfirmInstall()"
        class="px-2 py-0.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-400 text-xs rounded transition-colors flex-shrink-0 ml-1">
        一键安装</button>`;
    } else if (step.action_type === 'open_accessibility' || step.action_type === 'open_screen_recording') {
      html += `<button onclick="window._wizardAction('${step.action_type}')"
        class="px-2 py-0.5 bg-yellow-600/30 hover:bg-yellow-600/50 text-yellow-400 text-xs rounded transition-colors flex-shrink-0 ml-1">
        ${step.action_label}</button>`;
    }
    html += '</div>';
  }
  html += '</div>';

  // Install summary (copyable error)
  if (data.install_summary && !data.ready) {
    html += `<div class="mt-2 p-2 bg-red-900/20 border border-red-900/30 rounded text-xs">
      <div class="text-red-400 font-medium mb-1">安装详情</div>
      <pre class="text-red-300 whitespace-pre-wrap break-all max-h-20 overflow-y-auto">${data.install_summary}</pre>
      <button onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent);showToast('已复制到剪贴板','success')"
        class="mt-1 px-2 py-0.5 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded">复制错误信息</button>
    </div>`;
  }

  // All ready — staged enable
  if (data.ready && !data.enabled) {
    html += `<div class="mt-2 pt-2 border-t border-gray-700">
      <button onclick="window._wizardEnableDesktop()"
        class="w-full py-1.5 bg-purple-600 hover:bg-purple-700 text-white text-xs rounded transition-colors font-medium">
        启用桌面控制（仅截图和诊断）
      </button>
      <div class="text-xs text-gray-500 mt-1">首次启用只开截图和诊断。点击、键盘、App 控制需二次确认。</div>
    </div>`;
  }

  // Read-only enabled — offer write tools
  if (data.enabled && !data.write_tools_enabled) {
    html += `<div class="mt-2 pt-2 border-t border-gray-700">
      <div class="text-xs text-green-400 mb-1"><i class="fas fa-check-circle mr-1"></i>只读工具已启用（截图、列表、诊断、操作日志、紧急停止）</div>
      <button onclick="window._wizardEnableWrites()"
        class="w-full py-1.5 bg-yellow-600 hover:bg-yellow-700 text-white text-xs rounded transition-colors font-medium">
        确认启用手写操作工具
      </button>
      <div class="text-xs text-red-400 mt-1"><i class="fas fa-exclamation-triangle mr-1"></i>包括点击、键盘输入、拖拽、App 控制、窗口管理。所有写操作需审批。</div>
    </div>`;
  }

  // Fully enabled
  if (data.enabled && data.write_tools_enabled) {
    html += `<div class="mt-2 pt-2 border-t border-gray-700">
      <div class="text-xs text-green-400"><i class="fas fa-check-circle mr-1"></i>桌面控制已完全启用（只读 + 写操作工具）</div>
    </div>`;
  }

  container.innerHTML = html;

  // Auto-poll
  if (!data.ready && !_wizardPollTimer) {
    _wizardPollTimer = setInterval(loadDesktopWizard, 3000);
  } else if (data.ready && _wizardPollTimer) {
    clearInterval(_wizardPollTimer);
    _wizardPollTimer = null;
  }
}

// ── Global handlers ──

window._wizardConfirmInstall = function() {
  if (!confirm('将使用 brew install cliclick 安装约 200KB 的开源命令行工具。\n\n该工具用于模拟 macOS 鼠标和键盘操作。\n\n是否继续？')) return;
  window._wizardAction('install');
};

window._wizardAction = async function(actionType) {
  try {
    const res = await fetch('/api/desktop/wizard/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action_type: actionType }),
    });
    const data = await res.json();
    showToast(data.success ? (data.message || '成功') : (data.error || '失败'), data.success ? 'success' : 'error');
    setTimeout(loadDesktopWizard, 1500);
  } catch (e) {
    showToast('请求失败: ' + e.message, 'error');
  }
};

window._wizardEnableDesktop = async function() {
  try {
    const res = await fetch('/api/desktop/wizard/enable', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(data.message, 'success');
      await loadDesktopWizard();
    } else {
      showToast(data.error || '启用失败', 'error');
    }
  } catch (e) {
    showToast('请求失败: ' + e.message, 'error');
  }
};

window._wizardEnableWrites = function() {
  if (!confirm('确认启用写操作工具？\n\n这将允许 AI 控制鼠标点击、键盘输入、打开和操作 App。\n所有写操作需要用户审批，且可在状态页随时紧急停止。\n\n确认启用？')) return;
  (async () => {
    try {
      const res = await fetch('/api/desktop/wizard/enable-writes', { method: 'POST' });
      const data = await res.json();
      showToast(data.success ? data.message : (data.error || '失败'), data.success ? 'success' : 'error');
      if (data.success) await loadDesktopWizard();
    } catch (e) {
      showToast('请求失败: ' + e.message, 'error');
    }
  })();
};
