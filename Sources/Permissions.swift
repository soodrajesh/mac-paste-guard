import AppKit
import ApplicationServices
import IOKit.hid

/// PasteGuard needs two separate TCC grants and they fail differently:
///
/// - **Input Monitoring** lets the event tap see ⌘V at all. Without it,
///   `CGEvent.tapCreate` returns nil and nothing works.
/// - **Accessibility** lets the tap *suppress* an event and re-post one, and
///   lets us read a browser's window title. Without it the tap can observe but
///   not intervene, which is worse than useless — it would warn after the
///   paste had already landed.
///
/// So the app refuses to arm the tap until both are granted, rather than
/// running in a half-state the user would mistake for protection.
enum Permissions {
    static var hasAccessibility: Bool {
        AXIsProcessTrusted()
    }

    static var hasInputMonitoring: Bool {
        IOHIDCheckAccess(kIOHIDRequestTypeListenEvent) == kIOHIDAccessTypeGranted
    }

    static var allGranted: Bool {
        hasAccessibility && hasInputMonitoring
    }

    static func requestAccessibility() {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
    }

    static func requestInputMonitoring() {
        // Returns false when already denied; the system prompt only appears
        // the first time, so we also offer the Settings deep link below.
        _ = IOHIDRequestAccess(kIOHIDRequestTypeListenEvent)
    }

    static func openAccessibilitySettings() {
        open("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
    }

    static func openInputMonitoringSettings() {
        open("x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent")
    }

    private static func open(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        NSWorkspace.shared.open(url)
    }
}
