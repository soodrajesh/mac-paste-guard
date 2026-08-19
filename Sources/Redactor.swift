import Foundation

enum Redactor {
    /// Applies findings back-to-front so each replacement cannot shift the
    /// offsets of the ones not yet applied. `NSMutableString` is used rather
    /// than `String` because `NSRange` from `NSRegularExpression` is measured
    /// in UTF-16 units, and an emoji anywhere earlier in the pasted text would
    /// desynchronise `String.Index` arithmetic.
    static func redact(_ text: String, findings: [Finding]) -> String {
        let working = NSMutableString(string: text)
        for finding in findings.sorted(by: { $0.nsRange.location > $1.nsRange.location }) {
            let end = finding.nsRange.location + finding.nsRange.length
            guard finding.nsRange.location >= 0, end <= working.length else { continue }
            working.replaceCharacters(in: finding.nsRange, with: finding.replacement)
        }
        return working as String
    }

    /// "2 critical, 1 high" — the one-line summary shown in the panel header.
    static func summary(of findings: [Finding]) -> String {
        let order: [Severity] = [.critical, .high, .medium]
        let parts = order.compactMap { severity -> String? in
            let count = findings.filter { $0.severity == severity }.count
            return count == 0 ? nil : "\(count) \(severity.label.lowercased())"
        }
        return parts.joined(separator: ", ")
    }

    /// Groups findings for display: "AWS access key ID ×2".
    static func grouped(_ findings: [Finding]) -> [(label: String, severity: Severity, count: Int)] {
        var counts: [String: (Severity, Int)] = [:]
        for finding in findings {
            let existing = counts[finding.label]
            counts[finding.label] = (finding.severity, (existing?.1 ?? 0) + 1)
        }
        return counts
            .map { (label: $0.key, severity: $0.value.0, count: $0.value.1) }
            .sorted { a, b in
                if a.severity != b.severity { return a.severity > b.severity }
                return a.label < b.label
            }
    }
}
