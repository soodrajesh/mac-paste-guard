#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

APP="PasteGuard.app"
BIN="PasteGuard"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>PasteGuard</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>com.rajeshsood.pasteguard</string>
	<key>CFBundleName</key>
	<string>PasteGuard</string>
	<key>CFBundleDisplayName</key>
	<string>PasteGuard</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>0.1</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	<key>NSInputMonitoringUsageDescription</key>
	<string>PasteGuard watches for ⌘V so it can check what you are about to paste into an AI app before it leaves your Mac. Keystrokes are never recorded or transmitted.</string>
	<key>NSAppleEventsUsageDescription</key>
	<string>PasteGuard reads the frontmost window's title to tell whether a paste is headed for an AI site. It never reads page content.</string>
	<key>NSHumanReadableCopyright</key>
	<string>© 2026 Rajesh Sood</string>
</dict>
</plist>
PLIST

# --- App icon: render from an SF Symbol (stays crisp at every size, no text) ---
ICON_SCRIPT="$(mktemp /tmp/rendericon-XXXX).swift"
cat > "$ICON_SCRIPT" <<'SWIFT'
import AppKit

let size: CGFloat = 1024
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()

let bgRect = NSRect(x: 0, y: 0, width: size, height: size)
NSGradient(starting: NSColor(calibratedRed: 0.85, green: 0.25, blue: 0.20, alpha: 1),
           ending: NSColor(calibratedRed: 0.24, green: 0.06, blue: 0.10, alpha: 1))?
    .draw(in: bgRect, angle: -90)

let config = NSImage.SymbolConfiguration(pointSize: size * 0.52, weight: .semibold)
if let symbol = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil)?
        .withSymbolConfiguration(config),
   let cg = symbol.cgImage(forProposedRect: nil, context: nil, hints: nil),
   let ctx = NSGraphicsContext.current?.cgContext {
    let symSize = symbol.size
    let rect = CGRect(x: (size - symSize.width) / 2, y: (size - symSize.height) / 2,
                       width: symSize.width, height: symSize.height)
    ctx.saveGState()
    ctx.clip(to: rect, mask: cg)
    NSColor.white.setFill()
    ctx.fill(rect)
    ctx.restoreGState()
}

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write("Failed to render icon\n".data(using: .utf8)!)
    exit(1)
}
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
SWIFT

SQ="$(mktemp /tmp/appicon-XXXX).png"
swift "$ICON_SCRIPT" "$SQ"

ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s "$SQ" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$SQ" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
echo "Icon:  AppIcon.icns rendered from SF Symbol"

# Detection core is verified before anything is installed — a build that ships
# a regression in the detectors is worse than no build at all.
./test.sh >/dev/null && echo "Tests: detection core passing"

SOURCES=$(find Sources -name '*.swift')
swiftc -O -o "$APP/Contents/MacOS/$BIN" $SOURCES \
  -framework AppKit -framework CoreGraphics -framework ApplicationServices -framework IOKit

# Sign with a stable local identity so macOS treats rebuilds as the same app.
# An ad-hoc signature (--sign -) is just a hash of the raw binary with no
# identity string, so the CDHash — and any TCC grant keyed to it — changes on
# every rebuild. The app keeps its row in System Settings with the toggle
# still on, but AXIsProcessTrusted() returns false and the tap never arms:
# protection that looks enabled while checking nothing. Falls back to ad-hoc
# with a warning if the cert hasn't been created yet.
#
# The check is `find-identity -v -p codesigning`, not `find-certificate -a`:
# the latter exits 0 even with zero matches (an empty "find all" result is not
# an error), so it silently passes when no cert exists and codesign then fails
# with "no identity found" — aborting the build under `set -e` before anything
# is installed. `find-identity -v` also asks the right question: not "does a
# certificate exist" but "is there a *valid* signing identity", which is what
# the trust step in setup-signing.sh actually produces.
SIGN_IDENTITY="PasteGuard Local Dev"
if ! security find-identity -v -p codesigning 2>/dev/null | grep -qF "$SIGN_IDENTITY"; then
    echo "WARN: no local signing cert — falling back to ad-hoc. Permissions will"
    echo "      need re-granting after every rebuild. Run ./setup-signing.sh once."
    SIGN_IDENTITY="-"
fi
codesign --force --deep --sign "$SIGN_IDENTITY" "$APP"

echo "Built $APP"

# --- Install to /Applications ---
DEST="/Applications/$APP"
if [ -d "$DEST" ]; then rm -rf "$DEST"; fi
if ditto "$APP" "$DEST" 2>/dev/null; then
  echo "Installed to $DEST"
  echo "Run:  open \"$DEST\""
else
  echo "WARN: could not write to /Applications (permissions?). Retrying with sudo…"
  sudo rm -rf "$DEST" && sudo ditto "$APP" "$DEST" && echo "Installed to $DEST (sudo)"
fi
