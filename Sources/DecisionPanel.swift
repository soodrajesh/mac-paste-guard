import AppKit

enum PasteDecision {
    case redact
    case allow
    case cancel

    var auditName: String {
        switch self {
        case .redact: return "redacted"
        case .allow: return "allowed"
        case .cancel: return "cancelled"
        }
    }
}

/// The panel shown when a ⌘V has been suppressed.
///
/// Deliberately not an `NSAlert`: `runModal` blocks the main run loop, and the
/// event tap's callback runs on that same run loop — a blocked main thread
/// means macOS decides the tap has timed out and disables it. A non-modal
/// panel with a completion handler keeps the tap alive while the user reads.
final class DecisionPanel: NSObject, NSWindowDelegate {
    private static var active: DecisionPanel?

    private let panel: NSPanel
    private let completion: (PasteDecision) -> Void
    private var finished = false

    static func present(findings: [Finding],
                        destination: Destination,
                        completion: @escaping (PasteDecision) -> Void) {
        // Only ever one panel; a second suppressed paste while this is open
        // would otherwise queue up behind it.
        active?.finish(.cancel)
        let panel = DecisionPanel(findings: findings, destination: destination, completion: completion)
        active = panel
        panel.show()
    }

    private init(findings: [Finding],
                 destination: Destination,
                 completion: @escaping (PasteDecision) -> Void) {
        self.completion = completion
        self.panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 440, height: 100),
                             styleMask: [.titled, .fullSizeContentView],
                             backing: .buffered,
                             defer: false)
        super.init()

        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.delegate = self

        panel.contentView = buildContent(findings: findings, destination: destination)
    }

    // MARK: Layout

    private func buildContent(findings: [Finding], destination: Destination) -> NSView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 22, left: 22, bottom: 20, right: 22)
        stack.translatesAutoresizingMaskIntoConstraints = false

        let target = destination.detail.map { "\(destination.appName) — \($0)" } ?? destination.appName

        let heading = label("Paste blocked", font: .systemFont(ofSize: 17, weight: .semibold))
        let subtitle = label("\(Redactor.summary(of: findings)) found in what you're pasting into \(target).",
                             font: .systemFont(ofSize: 12),
                             color: .secondaryLabelColor)
        subtitle.preferredMaxLayoutWidth = 396

        stack.addArrangedSubview(heading)
        stack.addArrangedSubview(subtitle)
        stack.setCustomSpacing(14, after: subtitle)

        for group in Redactor.grouped(findings) {
            stack.addArrangedSubview(findingRow(group))
        }

        let note = label("Nothing has left this Mac. PasteGuard makes no network connections.",
                         font: .systemFont(ofSize: 11),
                         color: .tertiaryLabelColor)
        stack.setCustomSpacing(16, after: stack.arrangedSubviews.last ?? note)
        stack.addArrangedSubview(note)

        let buttons = NSStackView(views: [
            button("Cancel", action: #selector(cancelTapped), key: "\u{1b}"),
            button("Paste Original", action: #selector(allowTapped), key: ""),
            button("Redact & Paste", action: #selector(redactTapped), key: "\r"),
        ])
        buttons.orientation = .horizontal
        buttons.spacing = 8
        stack.setCustomSpacing(18, after: note)
        stack.addArrangedSubview(buttons)

        let container = NSView()
        container.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: container.topAnchor),
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            stack.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            buttons.trailingAnchor.constraint(equalTo: stack.trailingAnchor, constant: -22),
        ])
        return container
    }

    private func findingRow(_ group: (label: String, severity: Severity, count: Int)) -> NSView {
        let dot = label("●", font: .systemFont(ofSize: 10), color: color(for: group.severity))
        let text = group.count > 1 ? "\(group.label) ×\(group.count)" : group.label
        let name = label(text, font: .systemFont(ofSize: 12, weight: .medium))
        let severity = label(group.severity.label,
                             font: .systemFont(ofSize: 11),
                             color: .tertiaryLabelColor)

        let row = NSStackView(views: [dot, name, severity])
        row.orientation = .horizontal
        row.spacing = 7
        return row
    }

    private func color(for severity: Severity) -> NSColor {
        switch severity {
        case .critical: return .systemRed
        case .high: return .systemOrange
        case .medium: return .systemYellow
        }
    }

    private func label(_ text: String,
                       font: NSFont,
                       color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = font
        field.textColor = color
        field.lineBreakMode = .byWordWrapping
        field.maximumNumberOfLines = 3
        return field
    }

    private func button(_ title: String, action: Selector, key: String) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        button.keyEquivalent = key
        return button
    }

    // MARK: Presentation

    private func show() {
        panel.layoutIfNeeded()
        panel.setContentSize(panel.contentView?.fittingSize ?? NSSize(width: 440, height: 220))
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        NSSound.beep()
    }

    @objc private func redactTapped() { finish(.redact) }
    @objc private func allowTapped() { finish(.allow) }
    @objc private func cancelTapped() { finish(.cancel) }

    /// Closing the window by any route must resolve the pending paste exactly
    /// once, or the interceptor stays stuck with `isPresenting == true` and
    /// silently stops guarding.
    func windowWillClose(_ notification: Notification) {
        finish(.cancel)
    }

    private func finish(_ decision: PasteDecision) {
        guard !finished else { return }
        finished = true
        panel.delegate = nil
        panel.orderOut(nil)
        if DecisionPanel.active === self { DecisionPanel.active = nil }
        completion(decision)
    }
}
