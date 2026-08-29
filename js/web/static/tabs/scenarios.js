import { bindDataClicks, el, escapeHtml, showToast } from '../utils/dom.js';

export async function loadScenarios() {
  const container = document.getElementById('scenarios-grid');
  if (!container) return;
  container.innerHTML = '<div class="text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>加载场景...</div>';

  try {
    const res = await fetch('/api/scenarios');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const scenarios = data.scenarios || [];
    renderScenarios(scenarios, container);
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-sm">加载失败: ' + escapeHtml(e.message) + '</div>';
  }
}

function renderScenarios(scenarios, container) {
  if (scenarios.length === 0) {
    container.innerHTML = '<div class="text-gray-400 text-sm text-center py-8">暂无场景模板</div>';
    return;
  }

  container.replaceChildren();
  for (const s of scenarios) {
    const card = document.createElement('div');
    card.className = 'bg-gray-800 rounded-xl p-5 border border-gray-700 hover:border-blue-600 transition group';
    const skills = (s.suggested_skills || []).map((sk) => escapeHtml(sk)).join(', ');
    card.innerHTML = `
      <div class="flex items-start gap-4">
        <div class="w-12 h-12 bg-blue-900/40 rounded-xl flex items-center justify-center flex-shrink-0">
          <i class="fas ${escapeHtml(s.icon)} text-blue-400 text-xl"></i>
        </div>
        <div class="flex-1 min-w-0">
          <h3 class="text-lg font-bold text-gray-100">${escapeHtml(s.name)}</h3>
          <p class="text-sm text-gray-400 mt-1">${escapeHtml(s.description)}</p>
          <div class="flex flex-wrap gap-2 mt-3">${(s.roles || []).map((r) => `<span class="text-[10px] bg-gray-700 text-gray-300 px-2 py-0.5 rounded">${escapeHtml(r.name)}</span>`).join('')}</div>
          <div class="mt-3 text-xs text-gray-500">
            模式: <span class="text-blue-400">${escapeHtml(s.default_mode)}</span>
            ${skills ? `· 技能: ${skills}` : ''}
          </div>
          <div data-prompt-list class="mt-3 space-y-1"></div>
        </div>
      </div>
      <div class="mt-4 flex gap-2" data-start-slot></div>
    `;
    const promptList = card.querySelector('[data-prompt-list]');
    const prompts = Array.isArray(s.example_prompts) ? s.example_prompts.slice(0, 2) : [];
    if (prompts.length && promptList) {
      promptList.appendChild(el('div', { className: 'text-[10px] text-gray-500', text: '示例提示:' }));
      for (const prompt of prompts) {
        const chip = el('div', {
          className: 'text-xs text-gray-400 bg-gray-900/50 rounded px-2 py-1 truncate cursor-pointer hover:text-blue-400 transition',
          text: String(prompt ?? ''),
        });
        chip.addEventListener('click', () => fillScenarioPrompt(String(prompt ?? '')));
        promptList.appendChild(chip);
      }
    }
    const startSlot = card.querySelector('[data-start-slot]');
    if (startSlot) {
      const startBtn = el('button', {
        className: 'flex-1 bg-blue-600 hover:bg-blue-700 text-white text-sm py-2 rounded-lg transition',
        dataset: { scenarioId: String(s.id ?? '') },
      });
      startBtn.appendChild(el('i', { className: 'fas fa-rocket mr-1' }));
      startBtn.appendChild(document.createTextNode('一键启动'));
      startSlot.appendChild(startBtn);
    }
    container.appendChild(card);
  }
  bindDataClicks(container, 'scenarioId', (scenarioId) => {
    if (scenarioId) startScenario(scenarioId);
  });
}

export async function startScenario(scenarioId) {
  try {
    const res = await fetch(`/api/scenarios/${encodeURIComponent(scenarioId)}/start`, { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.success) {
      showToast(`场景「${data.scenario_name}」已启动为 Goal`);
      if (typeof window.enterBotsSurface === 'function') {
        window.enterBotsSurface();
      }
    }
  } catch (e) {
    showToast('启动失败: ' + e.message, 'error');
  }
}

export function fillScenarioPrompt(prompt) {
  const input = document.getElementById('chat-input');
  if (input) {
    input.value = prompt;
    input.focus();
  }
}
