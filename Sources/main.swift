import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let interceptor = PasteInterceptor()
    private var permissionTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        interceptor.onDecision = { [weak self] in self?.refreshIcon() }

        if !interceptor.arm() {
            requestPermissions()
            // TCC grants land asynchronously and without notification — the
            // user goes to System Settings, flips a switch, and comes back.
            // Polling is the only way to notice.
            permissionTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] timer in
                guard let self else { return }
                if self.interceptor.arm() {
                    timer.invalidate()
                    self.permissionTimer = nil
                    self.refreshIcon()
                }
            }
        }
        refreshIcon()
    }

    private func requestPermissions() {
        if !Permissions.hasAccessibility { Permissions.requestAccessibility() }
        if !Permissions.hasInputMonitoring { Permissions.requestInputMonitoring() }
    }

    private func refreshIcon() {
        let symbol = interceptor.isArmed ? "shield.lefthalf.filled" : "shield.slash"
        statusItem.button?.image = NSImage(systemSymbolName: symbol, accessibilityDescription: "PasteGuard")
        statusItem.button?.toolTip = interceptor.isArmed
            ? "PasteGuard is watching pastes into AI apps"
            : "PasteGuard needs permissions"
    }

    // MARK: Menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        let status = NSMenuItem(
            title: interceptor.isArmed ? "Guarding pastes into AI apps" : "Inactive — permissions needed",
            action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        if !interceptor.isArmed {
            menu.addItem(.separator())
            if !Permissions.hasAccessibility {
                menu.addItem(action("Grant Accessibility…", #selector(openAccessibility)))
            }
            if !Permissions.hasInputMonitoring {
                menu.addItem(action("Grant Input Monitoring…", #selector(openInputMonitoring)))
            }
        }

        menu.addItem(.separator())
        menu.addItem(action("Scan Clipboard Now", #selector(scanClipboard)))

        let recent = AuditLog.recentEntries(limit: 5)
        if !recent.isEmpty {
            menu.addItem(.separator())
            let header = NSMenuItem(title: "Recent", action: nil, keyEquivalent: "")
            header.isEnabled = false
            menu.addItem(header)
            for entry in recent {
                let kinds = entry.findings.map { "\($0.key)×\($0.value)" }.sorted().joined(separator: ", ")
                let item = NSMenuItem(title: "  \(entry.decision) → \(entry.destinationApp): \(kinds)",
                                      action: nil, keyEquivalent: "")
                item.isEnabled = false
                menu.addItem(item)
            }
            menu.addItem(action("Reveal Audit Log", #selector(revealLog)))
        }

        menu.addItem(.separator())
        menu.addItem(action("Quit PasteGuard", #selector(quit), key: "q"))
    }

    private func action(_ title: String, _ selector: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        return item
    }

    // MARK: Actions

    @objc private func openAccessibility() { Permissions.openAccessibilitySettings() }
    @objc private func openInputMonitoring() { Permissions.openInputMonitoringSettings() }

    /// Runs the detectors over whatever is on the clipboard right now and
    /// reports what *would* be caught — the fastest way to sanity-check
    /// detection quality without staging a real paste.
    @objc private func scanClipboard() {
        let alert = NSAlert()
        guard let text = NSPasteboard.general.string(forType: .string), !text.isEmpty else {
            alert.messageText = "Clipboard is empty"
            alert.informativeText = "Copy some text first, then scan again."
            alert.runModal()
            return
        }

        let findings = DetectionEngine.standard.scan(text)
        if findings.isEmpty {
            alert.messageText = "Nothing sensitive found"
            alert.informativeText = "Scanned \(text.count) characters. This paste would go through untouched."
        } else {
            alert.messageText = "\(Redactor.summary(of: findings)) found"
            let list = Redactor.grouped(findings)
                .map { "• \($0.label)\($0.count > 1 ? " ×\($0.count)" : "") — \($0.severity.label)" }
                .joined(separator: "\n")
            alert.informativeText = "\(list)\n\nRedacted preview:\n\(preview(Redactor.redact(text, findings: findings)))"
        }
        alert.runModal()
    }

    private func preview(_ text: String) -> String {
        text.count > 600 ? String(text.prefix(600)) + "…" : text
    }

    @objc private func revealLog() {
        NSWorkspace.shared.activateFileViewerSelecting([AuditLog.fileURL])
    }

    @objc private func quit() {
        interceptor.disarm()
        NSApplication.shared.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
