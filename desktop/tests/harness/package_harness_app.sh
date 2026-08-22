#!/bin/bash
# Package the Swift UI test harness as an ad-hoc signed .app for local Accessibility grants.
# Usage:
#   package_harness_app.sh <output_dir>
# Produces:
#   <output_dir>/JS Agent UI Test Harness.app
set -euo pipefail

OUT_DIR="${1:?output directory required}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/tauri_webview_harness.swift"
APP_NAME="JS Agent UI Test Harness.app"
APP_PATH="$OUT_DIR/$APP_NAME"
BIN_NAME="js-agent-ui-test-harness"
BUNDLE_ID="local.js-agent.ui-test-harness"

mkdir -p "$OUT_DIR"
rm -rf "$APP_PATH"
mkdir -p "$APP_PATH/Contents/MacOS"
mkdir -p "$APP_PATH/Contents/Resources"

# Compile arm64 binary
swiftc -O -target arm64-apple-macos13 \
  -o "$APP_PATH/Contents/MacOS/$BIN_NAME" \
  "$SRC" \
  -framework Cocoa \
  -framework ApplicationServices

chmod +x "$APP_PATH/Contents/MacOS/$BIN_NAME"

cat > "$APP_PATH/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>JS Agent UI Test Harness</string>
  <key>CFBundleExecutable</key>
  <string>${BIN_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>JS Agent UI Test Harness</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>0.1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <false/>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
  </dict>
</dict>
</plist>
EOF

echo -n "APPL????" > "$APP_PATH/Contents/PkgInfo"

# Ad-hoc sign entire app bundle
/usr/bin/codesign -s - --force --deep "$APP_PATH"
/usr/bin/codesign --verify --deep --strict "$APP_PATH"

SOURCE_SHA256="$(/usr/bin/shasum -a 256 "$SRC" | /usr/bin/awk '{print $1}')"
EXECUTABLE_SHA256="$(/usr/bin/shasum -a 256 "$APP_PATH/Contents/MacOS/$BIN_NAME" | /usr/bin/awk '{print $1}')"
cat > "$OUT_DIR/manifest.json" <<EOF
{
  "bundle_identifier": "${BUNDLE_ID}",
  "executable_path": "${APP_NAME}/Contents/MacOS/${BIN_NAME}",
  "executable_sha256": "${EXECUTABLE_SHA256}",
  "schema_version": "JSAgentTauriHarnessProvenanceV1",
  "source_path": "desktop/tests/harness/tauri_webview_harness.swift",
  "source_sha256": "${SOURCE_SHA256}"
}
EOF

echo "PACKAGED=$APP_PATH"
echo "BUNDLE_ID=$BUNDLE_ID"
echo "HARNESS_MANIFEST=$OUT_DIR/manifest.json"
echo "EXECUTABLE_SHA256=$EXECUTABLE_SHA256"
file "$APP_PATH/Contents/MacOS/$BIN_NAME"
/usr/bin/codesign -dv --verbose=2 "$APP_PATH" 2>&1 | head -20
