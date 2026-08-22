export function escapeHtml(text) {
  if (text == null) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Create an element with optional className and textContent (never HTML). */
export function el(tag, { className = '', text = null, attrs = {}, dataset = {} } = {}) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = String(text);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  for (const [key, value] of Object.entries(dataset)) {
    if (value == null) continue;
    node.dataset[key] = String(value);
  }
  return node;
}

/** Bind a click handler that reads a dataset key as opaque data (never eval). */
export function onDataClick(node, dataKey, handler) {
  node.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    handler(node.dataset[dataKey], event);
  });
  return node;
}

/** Bind onDataClick for every descendant that already has the matching data-* attr. */
export function bindDataClicks(root, dataKey, handler) {
  if (!root) return;
  const attr = 'data-' + String(dataKey).replace(/[A-Z]/g, (ch) => '-' + ch.toLowerCase());
  root.querySelectorAll('[' + attr + ']').forEach((node) => {
    onDataClick(node, dataKey, handler);
  });
}

export function onDataChange(node, dataKey, handler) {
  node.addEventListener('change', (event) => {
    handler(node.dataset[dataKey] ?? node.value, event);
  });
  return node;
}

/**
 * Assert a runtime id is safe to store in dataset/value (mirrors js.web.ids).
 * Returns the id or empty string when invalid.
 */
export function sanitizeRuntimeId(value) {
  if (typeof value !== 'string') return '';
  const normalized = value.normalize('NFC').trim();
  if (!normalized || normalized.length > 192) return '';
  if (/[\u0000-\u001f\u007f"'<>`\\]/.test(normalized)) return '';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,191}$/.test(normalized)) return '';
  return normalized;
}

export function showToast(message, type) {
  const normalizedType = type === 'success' || type === 'error' || type === 'warning'
    ? type
    : 'info';
  let region = document.getElementById('toast-region');
  if (!region) {
    region = document.createElement('div');
    region.id = 'toast-region';
    region.className = 'fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2 pointer-events-none';
    region.setAttribute('aria-live', 'polite');
    region.setAttribute('aria-relevant', 'additions text');
    region.setAttribute('aria-atomic', 'false');
    document.body.appendChild(region);
  }
  const div = document.createElement('div');
  const color = normalizedType === 'success'
    ? 'bg-green-600'
    : normalizedType === 'error'
      ? 'bg-red-600'
      : normalizedType === 'warning'
        ? ''
        : 'bg-blue-600';
  div.className = `${color} text-white px-4 py-2 rounded-lg text-sm shadow-lg transition-opacity pointer-events-auto max-w-sm`;
  // The bundled offline Tailwind stylesheet does not contain bg-yellow-600.
  // Keep warnings visually distinct in the packaged app without a network or
  // runtime Tailwind dependency.
  if (normalizedType === 'warning') div.style.backgroundColor = '#a16207';
  div.dataset.toastType = normalizedType;
  div.setAttribute('role', normalizedType === 'error' ? 'alert' : 'status');
  div.setAttribute('aria-live', normalizedType === 'error' ? 'assertive' : 'polite');
  div.setAttribute('aria-atomic', 'true');
  div.textContent = String(message ?? '');
  region.appendChild(div);
  setTimeout(() => {
    div.style.opacity = '0';
    setTimeout(() => div.remove(), 300);
  }, 5000);
}

export function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('-translate-x-full');
}

export function showLoading(id, text = '加载中...') {
  const node = document.getElementById(id);
  if (node) {
    node.replaceChildren();
    const wrap = el('div', { className: 'text-gray-400 text-sm' });
    const icon = el('i', { className: 'fas fa-spinner fa-spin mr-2' });
    wrap.appendChild(icon);
    wrap.appendChild(document.createTextNode(String(text)));
    node.appendChild(wrap);
  }
}

export function showError(id, text) {
  const node = document.getElementById(id);
  if (node) {
    node.replaceChildren();
    const wrap = el('div', { className: 'text-red-400 text-sm' });
    const icon = el('i', { className: 'fas fa-exclamation-circle mr-2' });
    wrap.appendChild(icon);
    wrap.appendChild(document.createTextNode(String(text)));
    node.appendChild(wrap);
  }
}
