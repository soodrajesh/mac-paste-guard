import Foundation

// Foundation-only on purpose: the detection core is the product, so it has to
// be testable without launching an app or touching AppKit. `Tests/main.swift`
// compiles against exactly this file plus Redactor.swift.

enum Severity: Int, Comparable {
    case medium = 1
    case high = 2
    case critical = 3

    static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }

    var label: String {
        switch self {
        case .critical: return "Critical"
        case .high: return "High"
        case .medium: return "Medium"
        }
    }
}

struct Finding {
    let kind: String        // stable machine key, e.g. "iban" — what the audit log records
    let label: String       // human-facing, e.g. "IBAN"
    let severity: Severity
    let nsRange: NSRange    // UTF-16 offsets, matching NSRegularExpression
    let matched: String
    let replacement: String

    /// Keeps the strongest, longest non-overlapping set. Two detectors firing
    /// on the same span (a card number is also a run of digits a weaker rule
    /// might claim) must not produce two redactions of the same characters —
    /// the second replace would corrupt the offsets of the first.
    static func resolveOverlaps(_ findings: [Finding]) -> [Finding] {
        let ordered = findings.sorted { a, b in
            if a.nsRange.location != b.nsRange.location { return a.nsRange.location < b.nsRange.location }
            if a.nsRange.length != b.nsRange.length { return a.nsRange.length > b.nsRange.length }
            return a.severity > b.severity
        }
        var kept: [Finding] = []
        var consumedUpTo = 0
        for f in ordered where f.nsRange.location >= consumedUpTo {
            kept.append(f)
            consumedUpTo = f.nsRange.location + f.nsRange.length
        }
        return kept
    }
}

struct PatternDetector {
    let kind: String
    let label: String
    let severity: Severity
    let regex: NSRegularExpression
    /// Which capture group is the secret. Contextual rules match
    /// `aws_secret_access_key = <value>` but must only redact `<value>`,
    /// otherwise the redacted text loses the key name and stops making sense.
    let captureGroup: Int
    let validate: (String) -> Bool
    let redact: (String) -> String

    init(kind: String,
         label: String,
         severity: Severity,
         pattern: String,
         options: NSRegularExpression.Options = [],
         captureGroup: Int = 0,
         validate: @escaping (String) -> Bool = { _ in true },
         redact: @escaping (String) -> String) {
        self.kind = kind
        self.label = label
        self.severity = severity
        // Patterns are compile-time constants in this file; a typo is a build
        // -breaking bug, not a runtime condition to recover from.
        self.regex = try! NSRegularExpression(pattern: pattern, options: options)
        self.captureGroup = captureGroup
        self.validate = validate
        self.redact = redact
    }

    func scan(_ text: String) -> [Finding] {
        let full = NSRange(text.startIndex..<text.endIndex, in: text)
        var findings: [Finding] = []
        regex.enumerateMatches(in: text, options: [], range: full) { match, _, _ in
            guard let match, captureGroup < match.numberOfRanges else { return }
            let range = match.range(at: captureGroup)
            guard range.location != NSNotFound,
                  let swiftRange = Range(range, in: text) else { return }
            let value = String(text[swiftRange])
            guard validate(value) else { return }
            findings.append(Finding(kind: kind,
                                    label: label,
                                    severity: severity,
                                    nsRange: range,
                                    matched: value,
                                    replacement: redact(value)))
        }
        return findings
    }
}

// MARK: - Checksums

enum Checksum {
    /// Card numbers. Without Luhn, a 16-digit order reference trips the rule
    /// and the user learns to click through the warning — which is the whole
    /// failure mode that kills tools like this.
    static func luhn(_ digits: String) -> Bool {
        let chars = digits.compactMap { $0.wholeNumberValue }
        guard chars.count >= 13, chars.count <= 19 else { return false }
        var sum = 0
        for (offset, digit) in chars.reversed().enumerated() {
            if offset % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            } else {
                sum += digit
            }
        }
        return sum % 10 == 0
    }

    /// Expected total length per country, so `GB82` + the wrong number of
    /// characters is rejected before the (much weaker) mod-97 check runs.
    /// Only the countries worth caring about here; unknown codes fall through
    /// to mod-97 alone.
    static let ibanLengths: [String: Int] = [
        "IE": 22, "GB": 22, "DE": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18,
        "BE": 16, "PT": 25, "AT": 20, "PL": 28, "SE": 24, "DK": 18, "FI": 18,
        "NO": 15, "CH": 21, "LU": 20, "CZ": 24, "GR": 27, "RO": 24, "HU": 28,
    ]

    static func iban(_ raw: String) -> Bool {
        let compact = raw.replacingOccurrences(of: " ", with: "").uppercased()
        guard compact.count >= 15, compact.count <= 34 else { return false }
        let country = String(compact.prefix(2))
        if let expected = ibanLengths[country], compact.count != expected { return false }

        // mod-97: rotate the first four characters to the end, map letters to
        // two-digit numbers, then take the whole thing mod 97 — which must be
        // 1. Done digit-by-digit because the number overflows every integer
        // type long before the end of a 34-character IBAN.
        let rotated = compact.dropFirst(4) + compact.prefix(4)
        var remainder = 0
        for char in rotated {
            let piece: String
            if let digit = char.wholeNumberValue, char.isNumber {
                piece = String(digit)
            } else if char.isLetter, let ascii = char.asciiValue {
                piece = String(Int(ascii - 65) + 10)
            } else {
                return false
            }
            for digitChar in piece {
                guard let d = digitChar.wholeNumberValue else { return false }
                remainder = (remainder * 10 + d) % 97
            }
        }
        return remainder == 1
    }

    /// Irish PPSN. Seven digits, a check letter, and optionally a second
    /// letter. This is the detector a generic US-built DLP tool does not have,
    /// and it is the single most sensitive identifier in Irish payroll and
    /// health data.
    static func ppsn(_ raw: String) -> Bool {
        let value = raw.uppercased().trimmingCharacters(in: .whitespaces)
        guard value.count == 8 || value.count == 9 else { return false }
        let chars = Array(value)
        let digits = chars.prefix(7)
        guard digits.allSatisfy({ $0.isNumber }) else { return false }

        var sum = 0
        for (index, char) in digits.enumerated() {
            guard let digit = char.wholeNumberValue else { return false }
            sum += digit * (8 - index)
        }

        if chars.count == 9 {
            let second = chars[8]
            guard second.isLetter else { return false }
            // 'W' (and historically a space) carries no weight; A–I count 1–9.
            if second != "W" {
                guard let ascii = second.asciiValue else { return false }
                let position = Int(ascii - 64)
                guard (1...9).contains(position) else { return false }
                sum += position * 9
            }
        }

        let alphabet = Array("WABCDEFGHIJKLMNOPQRSTUV")
        let expected = alphabet[sum % 23]
        return chars[7] == expected
    }

    /// Shannon entropy in bits per character — used to separate a real
    /// 40-character AWS secret from 40 characters of prose or base64 padding.
    static func entropy(_ value: String) -> Double {
        guard !value.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for char in value { counts[char, default: 0] += 1 }
        let length = Double(value.count)
        return counts.values.reduce(0.0) { total, count in
            let p = Double(count) / length
            return total - p * log2(p)
        }
    }
}

// MARK: - Placeholder rejection

enum Placeholder {
    /// Documentation and .env.example files are full of things shaped exactly
    /// like credentials. Flagging them trains the user to dismiss the panel.
    private static let words: Set<String> = [
        "password", "passwd", "changeme", "change_me", "secret", "yoursecret",
        "your_password", "your_api_key", "your-api-key", "apikey", "api_key",
        "todo", "tbd", "none", "null", "example", "test", "dummy", "placeholder",
        "xxxxxxxx", "redacted", "hunter2", "notarealkey", "insert_key_here",
    ]

    static func isPlaceholder(_ value: String) -> Bool {
        let lowered = value.lowercased()
        if words.contains(lowered) { return true }
        if lowered.contains("<") || lowered.contains(">") { return true }
        if lowered.contains("your-") || lowered.contains("your_") { return true }
        if lowered.contains("xxxx") || lowered.contains("****") { return true }
        // A single repeated character is never a real credential.
        if Set(lowered).count <= 2 { return true }
        return false
    }
}

// MARK: - Rules

extension PatternDetector {
    static let all: [PatternDetector] = [
        // ---- Critical: credentials. These are the ones that turn a careless
        // paste into an incident rather than a privacy problem.
        PatternDetector(
            kind: "private_key",
            label: "Private key",
            severity: .critical,
            pattern: "-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\\s\\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
            redact: { _ in "[PRIVATE KEY REDACTED]" }
        ),
        PatternDetector(
            kind: "aws_access_key_id",
            label: "AWS access key ID",
            severity: .critical,
            pattern: "\\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\\b",
            redact: { value in "[AWS KEY \(value.prefix(4))…REDACTED]" }
        ),
        PatternDetector(
            kind: "aws_secret_access_key",
            label: "AWS secret access key",
            severity: .critical,
            // Bare 40-character base64 is far too common to flag on its own,
            // so this rule only fires when the value is introduced by name.
            // `{40,}` not `{40}`: an exact quantifier matches only the first
            // 40 characters of a longer token and leaves the tail sitting in
            // the "redacted" text. A partial redaction is worse than none,
            // because it looks safe.
            pattern: "(?i)(?:aws_secret_access_key|secret_access_key|aws_secret_key)\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40,})",
            captureGroup: 1,
            validate: { Checksum.entropy($0) >= 3.5 && !Placeholder.isPlaceholder($0) },
            redact: { _ in "[AWS SECRET REDACTED]" }
        ),
        PatternDetector(
            kind: "anthropic_key",
            label: "Anthropic API key",
            severity: .critical,
            pattern: "\\bsk-ant-[A-Za-z0-9_-]{20,}",
            redact: { _ in "[ANTHROPIC KEY REDACTED]" }
        ),
        PatternDetector(
            kind: "openai_key",
            label: "OpenAI API key",
            severity: .critical,
            pattern: "\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}",
            validate: { !$0.hasPrefix("sk-ant-") },
            redact: { _ in "[OPENAI KEY REDACTED]" }
        ),
        PatternDetector(
            kind: "github_token",
            label: "GitHub token",
            severity: .critical,
            pattern: "\\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\\b",
            redact: { _ in "[GITHUB TOKEN REDACTED]" }
        ),
        PatternDetector(
            kind: "slack_token",
            label: "Slack token",
            severity: .critical,
            pattern: "\\bxox[baprs]-[A-Za-z0-9-]{10,}",
            redact: { _ in "[SLACK TOKEN REDACTED]" }
        ),
        PatternDetector(
            kind: "google_api_key",
            label: "Google API key",
            severity: .critical,
            pattern: "\\bAIza[0-9A-Za-z_-]{35}\\b",
            redact: { _ in "[GOOGLE KEY REDACTED]" }
        ),
        PatternDetector(
            kind: "jwt",
            label: "JWT",
            severity: .critical,
            pattern: "\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
            redact: { _ in "[JWT REDACTED]" }
        ),
        PatternDetector(
            kind: "assigned_secret",
            label: "Password or API key",
            severity: .critical,
            // Lookbehind rather than \b: the boundary between `_` and
            // `password` in `db_password` is not a word boundary, so \b would
            // miss the single most common way these keys are actually named.
            pattern: "(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\\s*[:=]\\s*[\"']?([^\\s\"',;]{8,})",
            captureGroup: 1,
            validate: { !Placeholder.isPlaceholder($0) },
            redact: { _ in "[SECRET REDACTED]" }
        ),

        // ---- High: money and national identifiers.
        PatternDetector(
            kind: "iban",
            label: "IBAN",
            severity: .high,
            pattern: "\\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\\b",
            validate: { Checksum.iban($0) },
            redact: { _ in "[IBAN REDACTED]" }
        ),
        PatternDetector(
            kind: "card_number",
            label: "Payment card",
            severity: .high,
            pattern: "\\b\\d(?:[ -]?\\d){12,18}\\b",
            validate: { Checksum.luhn($0.filter(\.isNumber)) },
            // Last four survives: it is what a human needs to identify the card
            // in conversation, and is not on its own reusable.
            redact: { value in
                let digits = value.filter(\.isNumber)
                return "**** **** **** \(digits.suffix(4))"
            }
        ),
        PatternDetector(
            kind: "ppsn",
            label: "Irish PPSN",
            severity: .high,
            pattern: "\\b\\d{7}[A-Wa-w][A-Ia-iWw]?\\b",
            validate: { Checksum.ppsn($0) },
            redact: { _ in "[PPSN REDACTED]" }
        ),

        // ---- Medium: personal data. Not an incident, but it is what makes a
        // paste a GDPR question, which is the part an Irish buyer cares about.
        PatternDetector(
            kind: "email",
            label: "Email address",
            severity: .medium,
            pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
            redact: { value in
                guard let at = value.firstIndex(of: "@") else { return "[EMAIL REDACTED]" }
                return "\(value.first.map(String.init) ?? "")***\(value[at...])"
            }
        ),
        PatternDetector(
            kind: "irish_mobile",
            label: "Irish mobile number",
            severity: .medium,
            // Deliberately mobiles only. Irish landline ranges overlap far too
            // much with ordinary numbers to flag without constant false hits.
            pattern: "(?:\\+353[ -]?8|\\b08)[3-9][ -]?\\d{3}[ -]?\\d{4}\\b",
            redact: { _ in "[PHONE REDACTED]" }
        ),
    ]
}

// MARK: - Engine

struct DetectionEngine {
    /// The event tap has a hard deadline — macOS silently disables a tap whose
    /// callback runs long. A pasted log file can be megabytes, so the scan is
    /// capped and the cap is deliberately well inside the budget.
    static let maxScanCharacters = 200_000

    let detectors: [PatternDetector]

    static let standard = DetectionEngine(detectors: PatternDetector.all)

    func scan(_ text: String) -> [Finding] {
        let subject = text.count > Self.maxScanCharacters
            ? String(text.prefix(Self.maxScanCharacters))
            : text
        var findings: [Finding] = []
        for detector in detectors {
            findings.append(contentsOf: detector.scan(subject))
        }
        return Finding.resolveOverlaps(findings)
    }
}
