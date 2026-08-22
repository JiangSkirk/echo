/* JS Agent — theme control (toggle + system tracking).
   Preference whitelist is enforced here too; see theme-init.js. */

const KEY = 'js-theme';
const VALID = new Set(['light', 'dark', 'system']);

export function currentPref() {
  let stored = null;
  try {
    stored = window.localStorage.getItem(KEY);
  } catch (e) {
    stored = null;
  }
  if (stored !== null && !VALID.has(stored)) {
    try {
      window.localStorage.removeItem(KEY);
    } catch (e) { /* ignore */ }
    return 'system';
  }
  return stored || 'system';
}

function resolve(pref) {
  if (pref !== 'system') return pref;
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch (e) {
    return 'light';
  }
}

export function applyTheme(pref) {
  const clean = VALID.has(pref) ? pref : 'system';
  const resolved = resolve(clean);
  const root = document.documentElement;
  root.setAttribute('data-theme', resolved);
  root.setAttribute('data-theme-pref', clean);
  root.style.colorScheme = resolved;
  return resolved;
}

export function setTheme(pref) {
  const clean = VALID.has(pref) ? pref : 'system';
  try {
    window.localStorage.setItem(KEY, clean);
  } catch (e) { /* storage unavailable — theme still applies in-session */ }
  return applyTheme(clean);
}

/** Toggle between explicit light and dark (user intent always explicit). */
export function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') === 'dark'
    ? 'dark'
    : 'light';
  return setTheme(current === 'dark' ? 'light' : 'dark');
}

export function initThemeListener(onChange) {
  let media = null;
  try {
    media = window.matchMedia('(prefers-color-scheme: dark)');
  } catch (e) {
    return;
  }
  const handler = () => {
    if (currentPref() === 'system') {
      const resolved = applyTheme('system');
      if (typeof onChange === 'function') onChange(resolved);
    }
  };
  if (typeof media.addEventListener === 'function') {
    media.addEventListener('change', handler);
  }
}
