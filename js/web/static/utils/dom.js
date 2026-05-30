export function escapeHtml(text) {
  if (text == null) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function showToast(message, type) {
  const div = document.createElement('div');
  const color = type === 'success' ? 'bg-green-600' : type === 'error' ? 'bg-red-600' : 'bg-blue-600';
  div.className = `fixed bottom-4 right-4 ${color} text-white px-4 py-2 rounded-lg text-sm shadow-lg z-50 transition-opacity`;
  div.textContent = message;
  document.body.appendChild(div);
  setTimeout(() => {
    div.style.opacity = '0';
    setTimeout(() => div.remove(), 300);
  }, 3000);
}

export function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('-translate-x-full');
}

export function showLoading(id, text = '加载中...') {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>${text}</div>`;
}

export function showError(id, text) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="text-red-400 text-sm"><i class="fas fa-exclamation-circle mr-2"></i>${text}</div>`;
}
