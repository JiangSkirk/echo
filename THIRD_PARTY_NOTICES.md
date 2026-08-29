# Third Party Notices

This repository uses the Python dependencies declared in `pyproject.toml` and
pinned in `uv.lock`.

The local Host UI vendors these static window assets so a local installation does
not contact a public CDN:

- Tailwind CSS 3.4.17 generated utility stylesheet, MIT License.
- Font Awesome Free 6.7.2 CSS and web fonts. CSS is MIT licensed; fonts are
  SIL OFL 1.1 licensed. Copyright 2024 Fonticons, Inc.

The complete upstream Font Awesome license is shipped beside the vendored
assets as `js/web/static/vendor/fontawesome/LICENSE.txt`. The Tailwind license
is shipped as `js/web/static/vendor/tailwind.LICENSE.txt`.

Before a stable release, `scripts/release_smoke.py --stable` requires these
artifacts to exist and contain no unresolved markers:

- SBOM SPDX document for the final build.
- License scan result for all runtime and optional dependencies.
- Notice text for dependencies that require attribution.
- External FTO and trademark review records where required.
