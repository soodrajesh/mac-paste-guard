import AppKit
import ApplicationServices

struct Destination {
    let appName: String
    let bundleID: String
    /// For a browser, the window title that identified the AI site.
    let detail: String?
    let app: NSRunningApplication
}

/// Decides whether a ⌘V is headed somewhere the text leaves the machine to a
/// model provider. Everything else is passed through untouched — the tap must
/// be invisible during normal work, or it gets turned off within a day.
enum AISurfaces {
    /// Native apps that are AI surfaces in their entirety.
    static let nativeBundleIDs: Set<String> = [
        "com.anthropic.claudefordesktop",
        "com.openai.chat",
        "com.google.GeminiApp",
        "com.microsoft.copilot",
        "ai.perplexity.mac",
        "com.todesktop.230313mzl4w4u92",   // Cursor
        "dev.warp.Warp-Stable",
        "com.exafunction.windsurf",
    ]

    /// Browsers, where the destination depends on the active tab rather than
    /// the app. Chromium and WebKit browsers both expose the active tab's
    /// title as the window title, which is enough to identify the site without
    /// reading any page content.
    static let browserBundleIDs: Set<String> = [
        "com.apple.Safari",
        "com.google.Chrome",
        "com.google.Chrome.canary",
        "com.microsoft.edgemac",
        "org.mozilla.firefox",
        "com.brave.Browser",
        "company.thebrowser.Browser",      // Arc
        "com.vivaldi.Vivaldi",
    ]

    /// Matched case-insensitively against the browser window title.
    static let webSurfaceMarkers: [String] = [
        "claude", "chatgpt", "openai", "gemini", "copilot", "perplexity",
        "mistral", "deepseek", "grok", "poe.com", "huggingface",
    ]

    static func currentDestination() -> Destination? {
        guard let app = NSWorkspace.shared.frontmostApplication,
              let bundleID = app.bundleIdentifier else { return nil }
        let name = app.localizedName ?? bundleID

        if nativeBundleIDs.contains(bundleID) {
            return Destination(appName: name, bundleID: bundleID, detail: nil, app: app)
        }

        if browserBundleIDs.contains(bundleID) {
            guard let title = focusedWindowTitle(for: app) else { return nil }
            let lowered = title.lowercased()
            guard let marker = webSurfaceMarkers.first(where: { lowered.contains($0) }) else { return nil }
            return Destination(appName: name, bundleID: bundleID, detail: marker, app: app)
        }

        return nil
    }

    /// Reads only the window's title via the Accessibility API. No page
    /// content, no DOM, no text fields are ever inspected.
    private static func focusedWindowTitle(for app: NSRunningApplication) -> String? {
        guard AXIsProcessTrusted() else { return nil }
        let element = AXUIElementCreateApplication(app.processIdentifier)

        var windowRef: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXFocusedWindowAttribute as CFString, &windowRef) == .success,
              let window = windowRef else { return nil }

        // AXUIElement is an opaque CF type with no Swift-visible dynamic cast,
        // so the previous `as! AXUIElement` trusted the Accessibility API's
        // contract unconditionally. That contract isn't enforced by the type
        // system, and a nonconforming AX implementation returning something
        // else would crash the whole app — taking paste protection down with
        // it — instead of just skipping this one check. CFGetTypeID is the
        // actual runtime check; unsafeBitCast only reinterprets the pointer
        // after it has passed.
        guard CFGetTypeID(window) == AXUIElementGetTypeID() else { return nil }
        let windowElement = unsafeBitCast(window, to: AXUIElement.self)

        var titleRef: CFTypeRef?
        guard AXUIElementCopyAttributeValue(windowElement, kAXTitleAttribute as CFString, &titleRef) == .success,
              let title = titleRef as? String else { return nil }

        return title
    }
}
