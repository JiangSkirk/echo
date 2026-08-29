/* JS Agent — theme bootstrap. Must run before first paint (loaded as a
   blocking external script in <head>). CSP-safe: no eval, no remote.
   Stored preference whitelist: light | dark | system. Anything else is
   cleared and falls back to system. */
(function () {
  'use strict';
  var KEY = 'js-theme';
  var stored = null;
  try {
    stored = window.localStorage.getItem(KEY);
  } catch (e) {
    stored = null;
  }
  if (stored !== 'light' && stored !== 'dark' && stored !== 'system') {
    if (stored !== null) {
      try {
        window.localStorage.removeItem(KEY);
      } catch (e) { /* storage unavailable */ }
    }
    stored = 'system';
  }
  var resolved = stored;
  if (stored === 'system') {
    var dark = false;
    try {
      dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    } catch (e) { /* matchMedia unavailable */ }
    resolved = dark ? 'dark' : 'light';
  }
  var root = document.documentElement;
  root.setAttribute('data-theme', resolved);
  root.setAttribute('data-theme-pref', stored);
  root.style.colorScheme = resolved;
  try {
    var switching = window.sessionStorage.getItem('js:switching-to');
    if (switching === 'js-work' || switching === 'js-agent') {
      root.setAttribute('data-switch-handoff', switching);
    }
  } catch (e) { /* storage unavailable */ }
})();
