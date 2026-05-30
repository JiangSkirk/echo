import { escapeHtml } from './dom.js';

export function renderMarkdown(text) {
  if (!text) return '';
  const result = [];
  const blockRegex = /(```(?:\w+)?\n[\s\S]*?```)/g;
  let lastIndex = 0;
  let match;
  while ((match = blockRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      result.push(_renderTextSegment(text.slice(lastIndex, match.index)));
    }
    const m = match[1].match(/```(\w+)?\n([\s\S]*?)```/);
    if (m) {
      result.push(`<pre class="bg-gray-950 p-3 rounded-lg overflow-x-auto my-2"><code>${escapeHtml(m[2])}</code></pre>`);
    }
    lastIndex = match.index + match[1].length;
  }
  if (lastIndex < text.length) {
    result.push(_renderTextSegment(text.slice(lastIndex)));
  }
  if (result.length === 0) {
    result.push(_renderTextSegment(text));
  }
  return result.join('');

  function _renderTextSegment(seg) {
    let html = escapeHtml(seg);
    html = html.replace(/`([^`]+)`/g, '<code class="bg-gray-700 px-1 rounded text-sm">$1</code>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
    return html.replace(/\n/g, '<br>');
  }
}
