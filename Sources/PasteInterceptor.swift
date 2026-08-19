import AppKit
import CoreGraphics

/// The heart of the POC.
///
/// An **active** `CGEventTap` on ⌘V. Active (`.defaultTap`) rather than
/// listen-only is the entire point: returning nil from the callback swallows
/// the keystroke, so the paste never reaches the destination app and the
/// decision happens *before* the data moves, not after.
final class PasteInterceptor {
    /// Stamped into the ⌘V we synthesize after a decision, so our own paste is
    /// not re-intercepted into an infinite loop. `eventSourceUserData` is a
    /// free-form 64-bit field that survives posting.
    private static let bypassMarker: Int64 = 0x50475F42_5950_4153   // "PG_BYPAS"

    private var tap: CFMachPort?
    private var runLoopSource: CFRunLoopSource?
    private let engine = DetectionEngine.standard

    /// Belt-and-braces companion to the marker, for the case where
    /// `eventSourceUserData` is stripped somewhere in the event pipeline.
    /// Deliberately narrow: it only ever excuses the *next plain ⌘V*, not any
    /// keystroke, and is consumed the instant that one event is seen. A
    /// window that stayed open for its full duration and matched any keyDown
    /// would let a second, genuinely sensitive paste from the user — landing
    /// in the same half-second — skip scanning entirely.
    private var expectingSyntheticPasteUntil: Date = .distantPast

    /// A decision is in flight; further ⌘V presses pass through rather than
    /// stacking panels on top of each other.
    private var isPresenting = false

    var onDecision: (() -> Void)?
    private(set) var isArmed = false

    // MARK: Lifecycle

    @discardableResult
    func arm() -> Bool {
        guard !isArmed else { return true }
        guard Permissions.allGranted else { return false }

        let mask = CGEventMask(1 << CGEventType.keyDown.rawValue)
        let refcon = Unmanaged.passUnretained(self).toOpaque()

        guard let tap = CGEvent.tapCreate(tap: .cgSessionEventTap,
                                          place: .headInsertEventTap,
                                          options: .defaultTap,
                                          eventsOfInterest: mask,
                                          callback: pasteGuardCallback,
                                          userInfo: refcon) else {
            return false
        }

        let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .commonModes)
        CGEvent.tapEnable(tap: tap, enable: true)

        self.tap = tap
        self.runLoopSource = source
        self.isArmed = true
        return true
    }

    func disarm() {
        if let tap {
            CGEvent.tapEnable(tap: tap, enable: false)
            // Invalidates the underlying mach port. Harmless today since
            // disarm() only runs once at quit and the process exits right
            // after, but arm()/disarm() cycling on a future permission-lost
            // event would otherwise leak a port per cycle.
            CFMachPortInvalidate(tap)
        }
        if let runLoopSource { CFRunLoopRemoveSource(CFRunLoopGetCurrent(), runLoopSource, .commonModes) }
        tap = nil
        runLoopSource = nil
        isArmed = false
    }

    // MARK: Tap callback

    fileprivate func handle(type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        // macOS disables a tap whose callback overruns its deadline. Re-arming
        // here is not optional — without it, protection silently dies the
        // first time the machine is under load.
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
            if let tap { CGEvent.tapEnable(tap: tap, enable: true) }
            return Unmanaged.passUnretained(event)
        }

        guard type == .keyDown else { return Unmanaged.passUnretained(event) }

        // Plain ⌘V only. ⌘⇧V and ⌘⌥⇧V belong to other tools (ClipKeep uses
        // ⌘⇧V for its picker) and claiming them would break them. Established
        // *before* the bypass checks below, so both of them can only ever
        // excuse a ⌘V — never any other keystroke.
        let keyCode = event.getIntegerValueField(.keyboardEventKeycode)
        let flags = event.flags
        guard keyCode == 9,
              flags.contains(.maskCommand),
              !flags.contains(.maskShift),
              !flags.contains(.maskAlternate),
              !flags.contains(.maskControl) else {
            return Unmanaged.passUnretained(event)
        }

        if event.getIntegerValueField(.eventSourceUserData) == Self.bypassMarker {
            return Unmanaged.passUnretained(event)
        }

        // Fallback path only — consumed the instant it's used, so it cannot
        // excuse a *second* ⌘V. If the marker above already matched, this
        // never triggers; it exists only for the rare case the field doesn't
        // survive the event pipeline.
        if Date() < expectingSyntheticPasteUntil {
            expectingSyntheticPasteUntil = .distantPast
            return Unmanaged.passUnretained(event)
        }

        guard !isPresenting else { return Unmanaged.passUnretained(event) }

        guard let destination = AISurfaces.currentDestination() else {
            return Unmanaged.passUnretained(event)
        }

        guard let text = NSPasteboard.general.string(forType: .string), !text.isEmpty else {
            return Unmanaged.passUnretained(event)
        }

        let findings = engine.scan(text)
        guard !findings.isEmpty else { return Unmanaged.passUnretained(event) }

        // Swallow the keystroke, then decide out of band — the callback must
        // return promptly and cannot present UI itself.
        isPresenting = true
        DispatchQueue.main.async { [weak self] in
            self?.present(text: text, findings: findings, destination: destination)
        }
        return nil
    }

    // MARK: Decision

    private func present(text: String, findings: [Finding], destination: Destination) {
        DecisionPanel.present(findings: findings, destination: destination) { [weak self] decision in
            guard let self else { return }
            AuditLog.record(destination: destination,
                            findings: findings,
                            decision: decision.auditName,
                            charactersScanned: text.count)
            self.isPresenting = false
            self.onDecision?()

            switch decision {
            case .redact:
                let cleaned = Redactor.redact(text, findings: findings)
                self.paste(cleaned, into: destination, restoring: text)
            case .allow:
                self.paste(text, into: destination, restoring: nil)
            case .cancel:
                break
            }
        }
    }

    /// Puts `value` on the pasteboard, returns focus to the destination app,
    /// and synthesizes the ⌘V we suppressed.
    private func paste(_ value: String, into destination: Destination, restoring original: String?) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)

        // If the destination has quit — or refuses reactivation — between the
        // decision and now, do not synthesize ⌘V at all. Firing it anyway
        // would type `value` into whatever app happens to be frontmost
        // instead, which could be anything the user switched to while the
        // panel was up. `value` is left on the pasteboard for a manual paste,
        // which is the same place a normal ⌘V would have put it.
        guard destination.app.activate(options: []), !destination.app.isTerminated else { return }

        // Two short hops: one for the destination app to become frontmost
        // again after the panel closes, one for the paste to be consumed
        // before the original clipboard is put back.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
            guard let self else { return }

            // Re-verified right before typing: the 150ms gap is enough time
            // for the user to have switched away on their own.
            guard NSWorkspace.shared.frontmostApplication?.processIdentifier
                    == destination.app.processIdentifier else { return }

            self.expectingSyntheticPasteUntil = Date().addingTimeInterval(0.3)
            self.sendPaste()

            guard let original else { return }
            // The user's clipboard is theirs. Redaction applies to what the AI
            // surface receives, not to what is left sitting on the pasteboard.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) {
                pasteboard.clearContents()
                pasteboard.setString(original, forType: .string)
            }
        }
    }

    private func sendPaste() {
        let source = CGEventSource(stateID: .hidSystemState)
        let vKey: CGKeyCode = 9   // kVK_ANSI_V
        guard let down = CGEvent(keyboardEventSource: source, virtualKey: vKey, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: vKey, keyDown: false) else { return }
        down.flags = .maskCommand
        up.flags = .maskCommand
        down.setIntegerValueField(.eventSourceUserData, value: Self.bypassMarker)
        up.setIntegerValueField(.eventSourceUserData, value: Self.bypassMarker)
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
    }
}

/// Must be a bare C function pointer — a Swift closure that captures context
/// cannot be used as a `CGEventTapCallBack`, hence the refcon round-trip.
private let pasteGuardCallback: CGEventTapCallBack = { _, type, event, refcon in
    guard let refcon else { return Unmanaged.passUnretained(event) }
    let interceptor = Unmanaged<PasteInterceptor>.fromOpaque(refcon).takeUnretainedValue()
    return interceptor.handle(type: type, event: event)
}
