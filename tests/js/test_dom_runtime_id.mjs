/**
 * Behavior test for sanitizeRuntimeId + dataset binding (no HTML attribute JS).
 * Run: node --test tests/js/test_dom_runtime_id.mjs
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..');
const domPath = path.join(root, 'js/web/static/utils/dom.js');

function loadDomHelpers() {
  const source = readFileSync(domPath, 'utf8');
  // Minimal browser stubs for createElement helpers.
  class FakeNode {
    constructor(tag) {
      this.tagName = tag;
      this.children = [];
      this.attrs = {};
      this.dataset = {};
      this.listeners = {};
      this.textContent = '';
      this.className = '';
      this.value = '';
    }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    appendChild(c) { this.children.push(c); return c; }
    addEventListener(type, fn) {
      (this.listeners[type] ||= []).push(fn);
    }
    replaceChildren(...nodes) {
      this.children = nodes;
    }
  }
  const document = {
    createElement: (tag) => new FakeNode(tag),
    createTextNode: (t) => ({ textContent: String(t) }),
    body: new FakeNode('body'),
    getElementById: () => null,
  };
  const sandbox = { document, exports: {}, module: { exports: {} }, console };
  // Transform ESM export to CJS-ish assignments for vm.
  const transformed = source
    .replace(/export function (\w+)/g, 'function $1')
    + '\nmodule.exports = { escapeHtml, el, onDataClick, onDataChange, sanitizeRuntimeId, showToast, toggleSidebar, showLoading, showError };\n';
  vm.runInNewContext(transformed, sandbox, { filename: domPath });
  return sandbox.module.exports;
}

const dom = loadDomHelpers();

test('sanitizeRuntimeId rejects XSS payloads', () => {
  const bad = [
    "');window.__xss=1;//",
    'x" onclick="alert(1)',
    'a<script>',
    'id\nbreak',
    '`tick`',
    'a'.repeat(200),
  ];
  for (const value of bad) {
    assert.equal(dom.sanitizeRuntimeId(value), '');
  }
});

test('sanitizeRuntimeId accepts common model ids', () => {
  assert.equal(dom.sanitizeRuntimeId('openai/gpt-4o'), 'openai/gpt-4o');
  assert.equal(dom.sanitizeRuntimeId('qwen2.5:14b'), 'qwen2.5:14b');
});

test('dynamic ids are stored in dataset, not onclick attributes', () => {
  const btn = dom.el('button', {
    className: 'x',
    dataset: { modelId: dom.sanitizeRuntimeId("openai/gpt-4o") },
    text: '切换',
  });
  let seen = null;
  dom.onDataClick(btn, 'modelId', (id) => { seen = id; });
  assert.equal(btn.attrs.onclick, undefined);
  assert.equal(btn.dataset.modelId, 'openai/gpt-4o');
  btn.listeners.click[0]({ preventDefault() {}, stopPropagation() {}, currentTarget: btn });
  assert.equal(seen, 'openai/gpt-4o');
});

test('malicious id never reaches dataset binding', () => {
  const evil = "');alert(1);//";
  const safe = dom.sanitizeRuntimeId(evil);
  assert.equal(safe, '');
  const btn = dom.el('button', { dataset: { modelId: safe || 'fallback' } });
  assert.notEqual(btn.dataset.modelId, evil);
});
