#!/usr/bin/env bash
# Builds Sanitized.app and a drag-to-Applications DMG in dist/.
# Usage: scripts/build-dmg.sh
#
# Signing: uses the first "Developer ID Application" identity in the keychain (or SIGN_ID);
# falls back to an ad-hoc signature when there is none.
# Notarization: set NOTARY_PROFILE to a profile saved with
#   xcrun notarytool store-credentials <profile> --apple-id <id> --team-id <team>
# (defaults to "sanitized" when that profile exists).
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

if [ -z "${SIGN_ID:-}" ]; then
  SIGN_ID=$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:.*\)"/\1/p' | head -1)
fi
SIGN_ID=${SIGN_ID:--}
echo "Signing with: $SIGN_ID"
codesign --force --options runtime --timestamp --entitlements packaging/entitlements.plist --sign "$SIGN_ID" "$BUNDLE"
codesign --verify --strict "$BUNDLE"

# DMG with an Applications shortcut so users can drag the app across.
STAGE="$DIST/dmg"
mkdir -p "$STAGE"
cp -R "$BUNDLE" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

if [ "$SIGN_ID" != "-" ]; then
  codesign --force --timestamp --sign "$SIGN_ID" "$DMG"
  PROFILE=${NOTARY_PROFILE:-sanitized}
  if xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>&1; then
    echo "Notarizing (usually a few minutes)…"
    xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
    xcrun stapler staple "$DMG"
    spctl --assess --type open --context context:primary-signature -v "$DMG"
  else
    echo "Skipping notarization: no notarytool profile \"$PROFILE\"."
  fi
fi

# Fixed-name copy for "latest" download links (…/releases/latest/download/Sanitized-<arch>.dmg).
cp "$DMG" "$DIST/$APP-$ARCH.dmg"

echo "Built $DMG (and $DIST/$APP-$ARCH.dmg)"
