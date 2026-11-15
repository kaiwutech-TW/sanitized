#!/usr/bin/env bash
# Builds Sanitized.app and a drag-to-Applications DMG in dist/.
# Usage: scripts/build-dmg.sh
set -euo pipefail
cd "$(dirname "$0")/.."

APP=Sanitized
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
ARCH=$(uname -m)
DIST=dist
BUNDLE="$DIST/$APP.app"
DMG="$DIST/$APP-$VERSION-$ARCH.dmg"

# Keep local paths (home folder, cargo registry) out of the binary.
# (CARGO_ENCODED_RUSTFLAGS uses 0x1f as separator, so paths with spaces work.)
US=$'\x1f'
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=~${US}--remap-path-prefix=$PWD=."
cargo build --release

rm -rf "$DIST"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"
cp target/release/sanitized "$BUNDLE/Contents/MacOS/sanitized"
sed "s/__VERSION__/$VERSION/g" packaging/Info.plist > "$BUNDLE/Contents/Info.plist"
printf 'APPL????' > "$BUNDLE/Contents/PkgInfo"

# App icon from assets/logo_512.png
ICONSET="$DIST/AppIcon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s assets/logo_512.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2))
  [ $d -le 512 ] && sips -z $d $d assets/logo_512.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$BUNDLE/Contents/Resources/AppIcon.icns"
rm -rf "$ICONSET"

# Ad-hoc signature (no Apple Developer ID). Set SIGN_ID to sign with a real identity.
codesign --force --deep --options runtime --sign "${SIGN_ID:--}" "$BUNDLE"

# DMG with an Applications shortcut so users can drag the app across.
STAGE="$DIST/dmg"
mkdir -p "$STAGE"
cp -R "$BUNDLE" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

echo "Built $DMG"
