#!/bin/bash
# Turn target/release/g-ssh into a disk image a Finder user can open.
# The image contains g-ssh.app and a shortcut to /Applications.
#
# The identifier, category, icon, and minimum system version match
# package.metadata.bundle in Cargo.toml. The signature is ad-hoc: Apple
# silicon will launch the bundle, and Gatekeeper still asks the first time
# a downloaded copy is opened, because this is not a Developer ID signature.
set -euo pipefail

if [ "$(uname)" != "Darwin" ]; then
  echo "macos-dmg.sh only runs on macOS" >&2
  exit 1
fi
if [ $# -ne 1 ]; then
  echo "usage: scripts/macos-dmg.sh <output.dmg>" >&2
  exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/target/release/g-ssh"
icon="$root/assets/app-icon/g-ssh.icns"
out=$1

if [ ! -f "$binary" ]; then
  echo "missing $binary (cargo build --release first)" >&2
  exit 1
fi
if [ ! -f "$icon" ]; then
  echo "missing $icon" >&2
  exit 1
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)
if [ -z "$version" ]; then
  echo "could not read version from Cargo.toml" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

app="$stage/g-ssh.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$binary" "$app/Contents/MacOS/g-ssh"
chmod 755 "$app/Contents/MacOS/g-ssh"
cp "$icon" "$app/Contents/Resources/g-ssh.icns"
cp "$root/assets/fonts/CascadiaCode-LICENSE.txt" \
  "$root/assets/fonts/SourceSans3-OFL.txt" \
  "$root/assets/icons/LUCIDE-LICENSE.txt" \
  "$app/Contents/Resources/"
printf 'APPL????' > "$app/Contents/PkgInfo"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>g-ssh</string>
  <key>CFBundleExecutable</key>
  <string>g-ssh</string>
  <key>CFBundleIconFile</key>
  <string>g-ssh</string>
  <key>CFBundleIdentifier</key>
  <string>app.g-ssh</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>g-ssh</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${version}</string>
  <key>CFBundleVersion</key>
  <string>${version}</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.developer-tools</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
EOF

plutil -lint "$app/Contents/Info.plist" >/dev/null
# A signature copied off the raw binary, or a quarantine mark, makes
# codesign refuse the bundle.
xattr -cr "$app"
codesign --force --sign - "$app"
codesign --verify --strict "$app"

ln -s /Applications "$stage/Applications"

# DiskImages locks an image so it cannot be opened twice. XProtect on a
# GitHub macOS runner often still holds that lock, and hdiutil then
# reports "Resource temporarily unavailable" or "Resource busy" for an
# image that is valid. Retry only that failure.
run_hdiutil() {
  local log attempt
  log=$(mktemp)
  for attempt in 1 2 3 4 5; do
    if "$@" >"$log" 2>&1; then
      rm -f "$log"
      return 0
    fi
    if grep -F -q -e 'Resource temporarily unavailable' -e 'Resource busy' "$log" \
        && [ "$attempt" -lt 5 ]; then
      echo "disk image is locked (attempt ${attempt}); waiting to retry" >&2
      sleep $((2 ** attempt))
      continue
    fi
    cat "$log" >&2
    rm -f "$log"
    return 1
  done
}

rm -f "$out"
run_hdiutil hdiutil create -volname "g-ssh" -srcfolder "$stage" -ov -format UDZO "$out"
run_hdiutil hdiutil verify "$out"
